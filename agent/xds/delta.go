package xds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/mitchellh/copystructure"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/logging"
	"github.com/hashicorp/go-hclog"
)

// ADSDeltaStream is a shorter way of referring to this thing...
type ADSDeltaStream = envoy_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer

// DeltaAggregatedResources implements envoy_discovery_v3.AggregatedDiscoveryServiceServer
func (s *Server) DeltaAggregatedResources(stream ADSDeltaStream) error {
	// a channel for receiving incoming requests
	reqCh := make(chan *envoy_discovery_v3.DeltaDiscoveryRequest)
	reqStop := int32(0)
	go func() {
		for {
			req, err := stream.Recv()
			if atomic.LoadInt32(&reqStop) != 0 {
				return
			}
			if err != nil {
				s.Logger.Error("Error receiving new DeltaDiscoveryRequest; closing request channel", "error", err)
				close(reqCh)
				return
			}
			reqCh <- req
		}
	}()

	err := s.processDelta(stream, reqCh)
	if err != nil {
		s.Logger.Error("Error handling ADS delta stream", "xdsVersion", "v3", "error", err)
	}

	// prevents writing to a closed channel if send failed on blocked recv
	atomic.StoreInt32(&reqStop, 1)

	return err
}

const (
	stateDeltaInit int = iota
	stateDeltaPendingInitialConfig
	stateDeltaRunning
)

func (s *Server) processDelta(stream ADSDeltaStream, reqCh <-chan *envoy_discovery_v3.DeltaDiscoveryRequest) error {
	logger := s.Logger.Named(logging.XDS).With("xDS", "incremental")

	// Loop state
	var (
		cfgSnap       *proxycfg.ConfigSnapshot
		node          *envoy_config_core_v3.Node
		proxyFeatures supportedProxyFeatures
		stateCh       <-chan *proxycfg.ConfigSnapshot
		watchCancel   func()
		proxyID       structs.ServiceID
	)

	streamState := &deltaStreamState{
		DeltaSnap:      newDeltaSnapshot(),
		Types:          make(map[string]*deltaStreamTypeState),
		PendingUpdates: make(map[string]map[string]map[string]string),
	}

	// need to run a small state machine to get through initial authentication.
	var state = stateDeltaInit

	var authTimer <-chan time.Time
	extendAuthTimer := func() {
		authTimer = time.After(s.AuthCheckFrequency)
	}

	checkStreamACLs := func(cfgSnap *proxycfg.ConfigSnapshot) error {
		return s.checkStreamACLs(stream.Context(), cfgSnap)
	}

	unsentConfig := make(chan struct{}, 1)
	notifyUnsent := func() {
		select {
		case unsentConfig <- struct{}{}:
		default:
		}
	}
	drainUnsent := func() {
		select {
		case <-unsentConfig:
		default:
		}
	}
	for {
		logger.Trace("entering event trigger phase")
		select {
		case <-authTimer:
			logger.Trace("event was auth timer elapsed")
			// It's been too long since a Discovery{Request,Response} so recheck ACLs.
			if err := checkStreamACLs(cfgSnap); err != nil {
				return err
			}
			extendAuthTimer()

		case req, ok := <-reqCh:
			var logReq *envoy_discovery_v3.DeltaDiscoveryRequest
			{
				dup, err := copystructure.Copy(req)
				if err == nil {
					logReq = dup.(*envoy_discovery_v3.DeltaDiscoveryRequest)
					logReq.Node = nil
				}
			}

			logger.Trace("event was delta discovery request", "typeUrl", req.TypeUrl, "req", logReq)
			if !ok {
				// reqCh is closed when stream.Recv errors which is how we detect client
				// going away. AFAICT the stream.Context() is only canceled once the
				// RPC method returns which it can't until we return from this one so
				// there's no point in blocking on that.
				return nil
			}

			if req.TypeUrl == "" {
				return status.Errorf(codes.InvalidArgument, "type URL is required for ADS")
			}

			if req.ErrorDetail != nil {
				logger.Error("got error response from envoy proxy", "nonce", req.ResponseNonce,
					"error", status.ErrorProto(req.ErrorDetail))
				streamState.Nack(req.ResponseNonce)

				goto STATE_MACHINE
			}

			if req.ResponseNonce != "" {
				logger.Error("got ok response from envoy proxy", "nonce", req.ResponseNonce)
				streamState.Ack(req.ResponseNonce)

				goto STATE_MACHINE
			}

			if streamState.AddRequestType(req) {
				logger.Trace("subscribing to type", "typeUrl", req.TypeUrl)
			}

			if node == nil && req.Node != nil {
				node = req.Node
				var err error
				proxyFeatures, err = determineSupportedProxyFeatures(req.Node)
				if err != nil {
					return status.Errorf(codes.InvalidArgument, err.Error())
				}
			}

			if len(req.InitialResourceVersions) > 0 {
				logger.Trace("setting initial resource versions for stream", "typeUrl", req.TypeUrl, "resources", req.InitialResourceVersions)
				streamState.SetVersions(req.TypeUrl, req.InitialResourceVersions)
			}

			for _, name := range req.ResourceNamesSubscribe {
				if streamState.Subscribe(req.TypeUrl, name) {
					logger.Trace("subscribing resource for stream", "typeUrl", req.TypeUrl, "resource", name)
				}
			}

			for _, name := range req.ResourceNamesUnsubscribe {
				if streamState.Unsubscribe(req.TypeUrl, name) {
					logger.Trace("unsubscribing resource for stream", "typeUrl", req.TypeUrl, "resource", name)
				}
			}

		case cfgSnap = <-stateCh:
			logger.Trace("event was new config snapshot")

			cInfo := connectionInfo{
				Token:         tokenFromContext(stream.Context()),
				ProxyFeatures: proxyFeatures,
			}
			newRes, err := s.allResourcesFromSnapshot(cInfo, cfgSnap)
			if err != nil {
				return err
			}

			if err := streamState.DeltaSnap.Install(newRes); err != nil {
				return err
			}

			notifyUnsent()
		case <-unsentConfig:
			logger.Trace("event was unsent old config snapshot")
			notifyUnsent()
		}

	STATE_MACHINE:

		logger.Trace("entering state machine phase", "state", state)

		// Trigger state machine
		switch state {
		case stateDeltaInit:
			if node == nil {
				// This can't happen (tm) since stateCh is nil until after the first req
				// is received but lets not panic about it.
				continue
			}
			// Start authentication process, we need the proxyID
			proxyID = structs.NewServiceID(node.Id, parseEnterpriseMeta(node))

			// Start watching config for that proxy
			stateCh, watchCancel = s.CfgMgr.Watch(proxyID)
			// Note that in this case we _intend_ the defer to only be triggered when
			// this whole process method ends (i.e. when streaming RPC aborts) not at
			// the end of the current loop iteration. We have to do it in the loop
			// here since we can't start watching until we get to this state in the
			// state machine.
			defer watchCancel()

			logger.Trace("watching proxy, pending initial proxycfg snapshot for xDS",
				"service_id", proxyID.String())

			// Now wait for the config so we can check ACL
			state = stateDeltaPendingInitialConfig
		case stateDeltaPendingInitialConfig:
			if cfgSnap == nil {
				// Nothing we can do until we get the initial config
				continue
			}

			// Got config, try to authenticate next.
			state = stateDeltaRunning

			logger.Trace("Got initial config snapshot",
				"service_id", cfgSnap.ProxyID.String())

			// Lets actually process the config we just got or we'll mis responding
			fallthrough
		case stateDeltaRunning:
			// Check ACLs on every Discovery{Request,Response}.
			if err := checkStreamACLs(cfgSnap); err != nil {
				return err
			}
			// For the first time through the state machine, this is when the
			// timer is first started.
			extendAuthTimer()

			if !streamState.DeltaSnap.Ready {
				logger.Trace("Skipping delta computation because we haven't gotten a snapshot yet",
					"service_id", cfgSnap.ProxyID.String())
				continue
			}

			drainUnsent()

			if len(streamState.PendingUpdates) > 0 {
				logger.Trace("Skipping delta computation because there are responses in flight",
					"service_id", cfgSnap.ProxyID.String())
				continue
			}

			logger.Trace("Invoking all xDS resource handlers and sending changed data if there are any",
				"service_id", cfgSnap.ProxyID.String())

			sendReply := func(typeUrl string) error {
				resp, updates, err := streamState.createDeltaResponse(logger, typeUrl)
				if err != nil {
					return err
				}
				if resp == nil {
					logger.Trace("no response generated", "typeURL", typeUrl)
					return nil
				}
				logger.Trace("sending response", "typeURL", typeUrl, "nonce", resp.Nonce,
					"response", resp)
				if err := stream.Send(resp); err != nil {
					return err
				}
				streamState.PendingUpdates[resp.Nonce] = map[string]map[string]string{typeUrl: updates}
				logger.Trace("sent response", "typeURL", typeUrl, "nonce", resp.Nonce)
				return nil
			}

			// TODO:
			/*
				Knowing When a Requested Resource Does Not Exist

				When a resource subscribed to by a client does not exist, the
				server will send a Resource whose name field matches the name
				that the client subscribed to and whose resource field is
				unset. This allows the client to quickly determine when a
				resource does not exist without waiting for a timeout, as would
				be done in the SotW protocol variants. However, clients are
				still encouraged to use a timeout to protect against the case
				where the management server fails to send a response in a
				timely manner.
			*/

			/*
				CDS updates (if any) must always be pushed first.

				EDS updates (if any) must arrive after CDS updates for the respective clusters.

				LDS updates must arrive after corresponding CDS/EDS updates.

				RDS updates related to the newly added listeners must arrive after CDS/EDS/LDS updates.

				// TODO: THEN DO CDS DELETES
			*/
			for _, typeUrl := range []string{
				ClusterType,
				EndpointType,
				ListenerType,
				RouteType,
			} {
				if err := sendReply(typeUrl); err != nil {
					return err
				}
			}
		}
	}
}

type deltaStreamState struct {
	// DeltaSnap is the current snapshot from proxycfg converted into xDS
	// structures.
	DeltaSnap *DeltaSnapshot

	// Types is the set of types that envoy has explicitly subscribed to.
	Types map[string]*deltaStreamTypeState

	// nonce => type => name => version (in-flight updates to envoy, pending ACK/NACK)
	PendingUpdates map[string]map[string]map[string]string

	nonce uint64 // xDS requires a unique nonce to correlate response/request pairs
}

func (s *deltaStreamState) Ack(nonce string) {
	if nonce == "" {
		return
	}

	pending, ok := s.PendingUpdates[nonce]
	if !ok {
		return
	}

	for typeUrl, versions := range pending {
		ts, ok := s.Types[typeUrl]
		if !ok {
			continue
		}
		for name, version := range versions {
			ts.ResourceVersions[name] = version
		}
		ts.SentToEnvoyOnce = true
	}
	delete(s.PendingUpdates, nonce)
}

func (s *deltaStreamState) Nack(nonce string) {
	if nonce == "" {
		return
	}

	delete(s.PendingUpdates, nonce)
}

func (s *deltaStreamState) createDeltaResponse(logger hclog.Logger, typeUrl string) (*envoy_discovery_v3.DeltaDiscoveryResponse, map[string]string, error) {
	ts, ok := s.Types[typeUrl]
	if !ok {
		return nil, nil, nil // not registered to type
	}

	// compute difference
	logger.Trace("createDeltaResponse", "typeURL", typeUrl,
		"isWild", ts.Wildcard,
		"envoy", ts.ResourceVersions,
		"consul", s.CurrentVersions(typeUrl))

	updates := make(map[string]string)
	// First find things that need updating or deleting
	for name, envoyVers := range ts.ResourceVersions {
		currVers, ok := s.CurrentVersions(typeUrl)[name]
		if !ok {
			updates[name] = ""
		} else if currVers != envoyVers {
			updates[name] = currVers
		}
	}

	// Now find new things
	if ts.Wildcard {
		for name, currVers := range s.CurrentVersions(typeUrl) {
			if _, ok := ts.ResourceVersions[name]; !ok {
				updates[name] = currVers
			}
		}
	}

	if len(updates) == 0 && ts.SentToEnvoyOnce {
		return nil, nil, nil
	}

	// now turn this into a disco response
	resp := &envoy_discovery_v3.DeltaDiscoveryResponse{
		// SystemVersionInfo    string      `protobuf:"bytes,1,opt,name=system_version_info,json=systemVersionInfo,proto3" json:"system_version_info,omitempty"`
		TypeUrl: typeUrl,
	}
	for name, vers := range updates {
		if vers == "" {
			resp.RemovedResources = append(resp.RemovedResources, name)
		} else {
			res := s.DeltaSnap.GetResource(typeUrl, name)
			if res == nil {
				return nil, nil, fmt.Errorf("unknown type url: %s", typeUrl)
			}
			any, err := ptypes.MarshalAny(res)
			if err != nil {
				return nil, nil, err
			}

			resp.Resources = append(resp.Resources, &envoy_discovery_v3.Resource{
				Name:     name,
				Resource: any,
				Version:  vers,
			})
		}
	}

	s.nonce++
	resp.Nonce = fmt.Sprintf("%08x", s.nonce)

	return resp, updates, nil
}

func (s *deltaStreamState) CurrentVersions(typeUrl string) map[string]string {
	if s.DeltaSnap.CurrentVersions == nil {
		return nil
	}
	return s.DeltaSnap.CurrentVersions[typeUrl]
}

func (s *deltaStreamState) AddRequestType(req *envoy_discovery_v3.DeltaDiscoveryRequest) bool {
	if req.TypeUrl == "" {
		return false
	}

	if _, ok := s.Types[req.TypeUrl]; ok {
		return false
	}
	// We are in the wildcard mode if the first request of a particular type has empty subscription list

	ts := &deltaStreamTypeState{
		Wildcard:         len(req.ResourceNamesSubscribe) == 0,
		ResourceVersions: make(map[string]string),
	}
	s.Types[req.TypeUrl] = ts
	return true
}

func (s *deltaStreamState) SetVersions(typeUrl string, initial map[string]string) {
	if typeUrl == "" {
		return
	}

	ts, ok := s.Types[typeUrl]
	if !ok {
		return
	}

	ts.ResourceVersions = initial
}

func (s *deltaStreamState) Subscribe(typeUrl, name string) bool {
	if typeUrl == "" {
		return false
	}

	ts, ok := s.Types[typeUrl]
	if !ok {
		return false
	}

	if ts.Wildcard {
		return false // not relevant
	}

	if _, ok := ts.ResourceVersions[name]; ok {
		return false
	}

	ts.ResourceVersions[name] = "" // start with no version
	return true
}

func (s *deltaStreamState) Unsubscribe(typeUrl, name string) bool {
	if typeUrl == "" {
		return false
	}

	ts, ok := s.Types[typeUrl]
	if !ok {
		return false
	}

	if ts.Wildcard {
		return false // not relevant
	}

	if _, ok := ts.ResourceVersions[name]; !ok {
		return false
	}

	delete(ts.ResourceVersions, name)
	return true
}

type deltaStreamTypeState struct {
	Wildcard bool

	SentToEnvoyOnce bool

	// name => version (as envoy has CONFIRMED)
	ResourceVersions map[string]string
}

type DeltaSnapshot struct {
	// Ready means this has been populated at least once.
	Ready bool

	// Resources is the SoTW we are incrementally attempting to sync to envoy.
	Resources *ResourceMap // what envoy thinks is true

	// CurrentVersions is the the xDS versioning represented by Resources.
	//
	// type => name => version (as consul knows right now)
	CurrentVersions map[string]map[string]string
}

func newDeltaSnapshot() *DeltaSnapshot {
	return &DeltaSnapshot{
		Resources: newEmptyResourceMap(),
	}
}

func (ds *DeltaSnapshot) GetResource(typeUrl, name string) proto.Message {
	switch typeUrl {
	case ListenerType:
		return ds.Resources.Listeners[name]
	case RouteType:
		return ds.Resources.Routes[name]
	case ClusterType:
		return ds.Resources.Clusters[name]
	case EndpointType:
		return ds.Resources.Endpoints[name]
	default:
		return nil
	}
}

func (ds *DeltaSnapshot) Install(resources map[string][]proto.Message) error {
	newMap, err := newResourceMap(resources)
	if err != nil {
		return err
	}
	versions, err := newMap.HashVersions()
	if err != nil {
		return err
	}

	if true {
		// 1 == copy; 2 == truth
		computeDiff := func(m1, m2 map[string]proto.Message) map[string]proto.Message {
			res := make(map[string]proto.Message) // if value==nil ==> delete

			for k, v1 := range m1 {
				v2, ok := m2[k]
				if !ok {
					res[k] = v1
				} else {
					if !proto.Equal(v1, v2) {
						res[k] = v1
					}
				}
			}

			for k, _ := range m2 {
				if _, ok := m1[k]; !ok {
					res[k] = nil
				}
			}

			return res
		}
		// TODO: delete this is for debugging
		changes := newEmptyResourceMap()
		changes.Listeners = computeDiff(newMap.Listeners, ds.Resources.Listeners)
		changes.Routes = computeDiff(newMap.Routes, ds.Resources.Routes)
		changes.Clusters = computeDiff(newMap.Clusters, ds.Resources.Clusters)
		changes.Endpoints = computeDiff(newMap.Endpoints, ds.Resources.Endpoints)

		if changes.IsEmpty() {
			return nil
		}
		fmt.Fprintf(os.Stdout, "RBOYER CHANGES: %s\n", jd(changes))
	}

	ds.Resources = newMap
	ds.CurrentVersions = versions
	ds.Ready = true

	return nil
}

func (ds *DeltaSnapshot) AsVersions() (map[string]map[string]string, error) {
	m := make(map[string]map[string]string)
	{
		lm, err := hashResourceMap(ds.Resources.Listeners)
		if err != nil {
			return nil, err
		}
		m[ListenerType] = lm
	}
	{
		rm, err := hashResourceMap(ds.Resources.Routes)
		if err != nil {
			return nil, err
		}
		m[RouteType] = rm
	}
	{
		cm, err := hashResourceMap(ds.Resources.Clusters)
		if err != nil {
			return nil, err
		}
		m[ClusterType] = cm
	}
	{
		em, err := hashResourceMap(ds.Resources.Endpoints)
		if err != nil {
			return nil, err
		}
		m[EndpointType] = em
	}

	return m, nil
}

func jd(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type ResourceMap struct {
	Listeners map[string]proto.Message
	Routes    map[string]proto.Message
	Clusters  map[string]proto.Message
	Endpoints map[string]proto.Message
}

func (m *ResourceMap) IsEmpty() bool {
	if m == nil {
		return true
	}
	return len(m.Listeners) == 0 && len(m.Routes) == 0 && len(m.Clusters) == 0 && len(m.Endpoints) == 0
}

func (m *ResourceMap) HashVersions() (map[string]map[string]string, error) {
	out := make(map[string]map[string]string)
	{
		lm, err := hashResourceMap(m.Listeners)
		if err != nil {
			return nil, err
		}
		out[ListenerType] = lm
	}
	{
		rm, err := hashResourceMap(m.Routes)
		if err != nil {
			return nil, err
		}
		out[RouteType] = rm
	}
	{
		cm, err := hashResourceMap(m.Clusters)
		if err != nil {
			return nil, err
		}
		out[ClusterType] = cm
	}
	{
		em, err := hashResourceMap(m.Endpoints)
		if err != nil {
			return nil, err
		}
		out[EndpointType] = em
	}

	return out, nil
}

func newEmptyResourceMap() *ResourceMap {
	return &ResourceMap{
		Listeners: make(map[string]proto.Message),
		Routes:    make(map[string]proto.Message),
		Clusters:  make(map[string]proto.Message),
		Endpoints: make(map[string]proto.Message),
	}
}

func newResourceMap(resources map[string][]proto.Message) (*ResourceMap, error) {
	m := newEmptyResourceMap()

	for typeURL, typeRes := range resources {
		for _, res := range typeRes {
			switch typeURL {
			case ListenerType:
				l, ok := res.(*envoy_listener_v3.Listener)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				m.Listeners[l.Name] = res
			case RouteType:
				route, ok := res.(*envoy_route_v3.RouteConfiguration)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				m.Routes[route.Name] = res
			case ClusterType:
				c, ok := res.(*envoy_cluster_v3.Cluster)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				m.Clusters[c.Name] = res
			case EndpointType:
				e, ok := res.(*envoy_endpoint_v3.ClusterLoadAssignment)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				m.Endpoints[e.ClusterName] = res
			default:
				return nil, fmt.Errorf("unexpected xDS type found in delta snapshot: %s", typeURL)
			}
		}
	}

	return m, nil
}

func (s *Server) allResourcesFromSnapshot(cInfo connectionInfo, cfgSnap *proxycfg.ConfigSnapshot) (map[string][]proto.Message, error) {
	all := make(map[string][]proto.Message)
	for _, typeUrl := range []string{ListenerType, RouteType, ClusterType, EndpointType} {
		res, err := s.resourcesFromSnapshot(typeUrl, cInfo, cfgSnap)
		if err != nil {
			return nil, err
		}
		all[typeUrl] = res
	}
	return all, nil
}

func (s *Server) resourcesFromSnapshot(typeUrl string, cInfo connectionInfo, cfgSnap *proxycfg.ConfigSnapshot) ([]proto.Message, error) {
	switch typeUrl {
	case ListenerType:
		return s.listenersFromSnapshot(cInfo, cfgSnap)
	case RouteType:
		return s.routesFromSnapshot(cInfo, cfgSnap)
	case ClusterType:
		return s.clustersFromSnapshot(cInfo, cfgSnap)
	case EndpointType:
		return s.endpointsFromSnapshot(cInfo, cfgSnap)
	default:
		return nil, fmt.Errorf("unknown typeUrl: %s", typeUrl)
	}
}

func hashResourceMap(resources map[string]proto.Message) (map[string]string, error) {
	m := make(map[string]string)
	for name, res := range resources {
		h, err := hashResource(res)
		if err != nil {
			return nil, err
		}
		m[name] = h
	}
	return m, nil
}

// hashResource will take a resource and create a SHA256 hash sum out of the marshaled bytes
func hashResource(res proto.Message) (string, error) {
	h := sha256.New()
	buffer := proto.NewBuffer(nil)
	buffer.SetDeterministic(true)

	err := buffer.Marshal(res)
	if err != nil {
		return "", err
	}
	h.Write(buffer.Bytes())
	buffer.Reset()

	return hex.EncodeToString(h.Sum(nil)), nil
}

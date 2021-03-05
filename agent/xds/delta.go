package xds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
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
		nonce         uint64 // xDS requires a unique nonce to correlate response/request pairs
		ready         bool   // set to true after the first snapshot arrives
	)

	var (
		// resourceMap is the SoTW we are incrementally attempting to sync to envoy.
		//
		// type => name => proto
		resourceMap = emptyIndexedResources()

		// currentVersions is the the xDS versioning represented by Resources.
		//
		// type => name => version (as consul knows right now)
		currentVersions = make(map[string]map[string]string)

		handlers = make(map[string]*xDSDeltaType)
	)

	// Configure handlers for each type of request we currently care about.
	for _, typeUrl := range []string{
		ListenerType,
		RouteType,
		ClusterType,
		EndpointType,
	} {
		handlers[typeUrl] = &xDSDeltaType{
			typeURL:          typeUrl,
			stream:           stream,
			logger:           logger.With("typeUrl", typeUrl),
			resourceVersions: make(map[string]string),
			pendingUpdates:   make(map[string]map[string]string),
			resourceReader: func(typeUrl, name string) proto.Message {
				resources, ok := resourceMap[typeUrl]
				if !ok {
					return nil
				}
				return resources[name]
			},
		}
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

			logger.Trace("event was delta discovery request", "typeUrl", req.TypeUrl,
				"req", jd(logReq))
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

			handler, ok := handlers[req.TypeUrl]
			if !ok {
				return nil // not a type we care about
			}
			if handler.Recv(req) {
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

			// index and hash the xDS structures
			newResourceMap, err := indexResources(newRes)
			if err != nil {
				return err
			}
			newVersions, err := computeResourceVersions(newResourceMap)
			if err != nil {
				return err
			}

			resourceMap = newResourceMap
			currentVersions = newVersions
			ready = true

			notifyUnsent()
		case <-unsentConfig:
			logger.Trace("event was unsent old config snapshot")
			notifyUnsent()
		}

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

			logger = logger.With("service_id", proxyID.String()) // enhance future logs

			logger.Trace("watching proxy, pending initial proxycfg snapshot for xDS")

			// Now wait for the config so we can check ACL
			state = stateDeltaPendingInitialConfig
		case stateDeltaPendingInitialConfig:
			if cfgSnap == nil {
				// Nothing we can do until we get the initial config
				continue
			}

			// Got config, try to authenticate next.
			state = stateDeltaRunning

			logger.Trace("Got initial config snapshot")

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

			if !ready {
				logger.Trace("Skipping delta computation because we haven't gotten a snapshot yet")
				continue
			}

			drainUnsent()

			var pendingTypes []string
			for name, handler := range handlers {
				if !handler.registered {
					continue
				}
				if len(handler.pendingUpdates) > 0 {
					pendingTypes = append(pendingTypes, name)
				}
			}
			if len(pendingTypes) > 0 {
				sort.Strings(pendingTypes)
				logger.Trace("Skipping delta computation because there are responses in flight",
					"pendingTypeUrls", pendingTypes)
				continue
			}

			logger.Trace("Invoking all xDS resource handlers and sending changed data if there are any")

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
				handler, ok := handlers[typeUrl]
				if !ok || !handler.registered {
					continue
				}

				// Push changes down from config snapshot.
				handler.SetCurrentVersions(currentVersions[typeUrl])

				resp, updates, err := handler.createDeltaResponse()
				if err != nil {
					return err
				}
				if resp == nil {
					handler.logger.Trace("no response generated")
					return nil
				}
				nonce++
				resp.Nonce = fmt.Sprintf("%08x", nonce)

				if err := handler.SendReply(resp); err != nil {
					return err
				}

				handler.MarkPendingUpdates(resp.Nonce, updates)
			}
		}
	}
}

type xDSDeltaType struct {
	typeURL        string
	stream         ADSDeltaStream
	logger         hclog.Logger
	resourceReader func(typeUrl, name string) proto.Message
	registered     bool

	wildcard        bool
	sentToEnvoyOnce bool

	// name => version (as envoy has CONFIRMED)
	resourceVersions map[string]string

	// type => name => version (as consul knows right now)
	currentVersions map[string]string

	// nonce -> name -> version
	// TODO: lazy init and handle nils
	pendingUpdates map[string]map[string]string
}

// Recv handles new discovery requests from envoy.
//
// Returns true the first time a type receives a request.
func (t *xDSDeltaType) Recv(req *envoy_discovery_v3.DeltaDiscoveryRequest) bool {
	if t == nil {
		return false // not something we care about
	}

	registeredThisTime := false
	if !t.registered {
		// We are in the wildcard mode if the first request of a particular
		// type has empty subscription list
		t.wildcard = len(req.ResourceNamesSubscribe) == 0
		t.registered = true
		registeredThisTime = true
	}

	if req.ErrorDetail != nil {
		t.logger.Error("got error response from envoy proxy", "nonce", req.ResponseNonce,
			"error", status.ErrorProto(req.ErrorDetail))
		t.Nack(req.ResponseNonce)

		goto STATE_MACHINE
	}

	if req.ResponseNonce != "" {
		t.logger.Error("got ok response from envoy proxy", "nonce", req.ResponseNonce)
		t.Ack(req.ResponseNonce)

		/*
			TODO: actually skip the goto

			DeltaDiscoveryRequest plays two independent roles. Any
			DeltaDiscoveryRequest can be either or both of: [1] informing
			the server of what resources the client has gained/lost
			interest in (using resource_names_subscribe and
			resource_names_unsubscribe), or [2] (N)ACKing an earlier
			resource update from the server (using response_nonce, with
			presence of error_detail making it a NACK). Additionally, the
			first message (for a given type_url) of a reconnected gRPC
			stream has a third role: informing the server of the resources
			(and their versions) that the client already possesses, using
			the initial_resource_versions field.
		*/

		goto STATE_MACHINE
	}

	if len(req.InitialResourceVersions) > 0 {
		t.logger.Trace("setting initial resource versions for stream",
			"resources", req.InitialResourceVersions)
		t.SetVersions(req.InitialResourceVersions)
	}

	for _, name := range req.ResourceNamesSubscribe {
		if t.Subscribe(name) {
			t.logger.Trace("subscribing resource for stream", "resource", name)
		}
	}

	for _, name := range req.ResourceNamesUnsubscribe {
		if t.Unsubscribe(name) {
			t.logger.Trace("unsubscribing resource for stream", "resource", name)
		}
	}

STATE_MACHINE: // TODO

	return registeredThisTime
}

// TODO: work out function name
func (t *xDSDeltaType) SetVersions(initial map[string]string) {
	t.resourceVersions = initial
}

// TODO: work out function name
func (t *xDSDeltaType) SetCurrentVersions(current map[string]string) {
	t.currentVersions = current
}

func (t *xDSDeltaType) Subscribe(name string) bool {
	if t.wildcard {
		return false // not relevant
	}

	if _, ok := t.resourceVersions[name]; ok {
		return false
	}

	t.resourceVersions[name] = "" // start with no version
	return true
}

func (t *xDSDeltaType) Unsubscribe(name string) bool {
	if t.wildcard {
		return false // not relevant
	}

	if _, ok := t.resourceVersions[name]; !ok {
		return false
	}

	delete(t.resourceVersions, name)
	return true
}

func (t *xDSDeltaType) Ack(nonce string) {
	if nonce == "" {
		return
	}

	pending, ok := t.pendingUpdates[nonce]
	if !ok {
		return
	}

	for name, version := range pending {
		t.resourceVersions[name] = version
	}
	t.sentToEnvoyOnce = true
	delete(t.pendingUpdates, nonce)
}

func (t *xDSDeltaType) Nack(nonce string) {
	if nonce == "" {
		return
	}

	delete(t.pendingUpdates, nonce)
}

func (t *xDSDeltaType) SendReply(resp *envoy_discovery_v3.DeltaDiscoveryResponse) error {
	var logResp *envoy_discovery_v3.DeltaDiscoveryResponse
	{
		dup, err := copystructure.Copy(resp)
		if err == nil {
			logResp = dup.(*envoy_discovery_v3.DeltaDiscoveryResponse)
		}
	}

	t.logger.Trace("sending response", "nonce", resp.Nonce,
		"response", jd(logResp))
	if err := t.stream.Send(resp); err != nil {
		return err
	}
	t.logger.Trace("sent response", "nonce", resp.Nonce)
	return nil
}

func (t *xDSDeltaType) MarkPendingUpdates(nonce string, updates map[string]string) {
	if nonce == "" {
		return
	}
	t.pendingUpdates[nonce] = updates
}

func (t *xDSDeltaType) createDeltaResponse() (*envoy_discovery_v3.DeltaDiscoveryResponse, map[string]string, error) {
	// compute difference
	updates := make(map[string]string)
	// First find things that need updating or deleting
	for name, envoyVers := range t.resourceVersions {
		currVers, ok := t.currentVersions[name]
		if !ok {
			updates[name] = ""
		} else if currVers != envoyVers {
			updates[name] = currVers
		}
	}

	// Now find new things
	if t.wildcard {
		for name, currVers := range t.currentVersions {
			if _, ok := t.resourceVersions[name]; !ok {
				updates[name] = currVers
			}
		}
	}

	if len(updates) == 0 && t.sentToEnvoyOnce {
		return nil, nil, nil
	}

	// now turn this into a disco response
	resp := &envoy_discovery_v3.DeltaDiscoveryResponse{
		// SystemVersionInfo    string      `protobuf:"bytes,1,opt,name=system_version_info,json=systemVersionInfo,proto3" json:"system_version_info,omitempty"`
		TypeUrl: t.typeURL,
	}
	for name, vers := range updates {
		if vers == "" {
			resp.RemovedResources = append(resp.RemovedResources, name)
		} else {
			res := t.resourceReader(t.typeURL, name)
			if res == nil {
				return nil, nil, fmt.Errorf("unknown type url: %s", t.typeURL)
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

	return resp, updates, nil
}

func jd(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type ResourceMap struct {
	Data map[string]map[string]proto.Message
}

func (m *ResourceMap) GetResource(typeUrl, name string) proto.Message {
	resources, ok := m.Data[typeUrl]
	if !ok {
		return nil
	}
	return resources[name]
}

func (m *ResourceMap) IsEmpty() bool {
	if m == nil {
		return true
	}
	return len(m.Data) == 0
}

func computeResourceVersions(resourceMap map[string]map[string]proto.Message) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string)
	for typeUrl, resources := range resourceMap {
		m, err := hashResourceMap(resources)
		if err != nil {
			return nil, err
		}
		out[typeUrl] = m
	}
	return out, nil
}

func newEmptyResourceMap() *ResourceMap {
	return &ResourceMap{
		Data: map[string]map[string]proto.Message{
			ListenerType: make(map[string]proto.Message),
			RouteType:    make(map[string]proto.Message),
			ClusterType:  make(map[string]proto.Message),
			EndpointType: make(map[string]proto.Message),
		},
	}
}

func emptyIndexedResources() map[string]map[string]proto.Message {
	return map[string]map[string]proto.Message{
		ListenerType: make(map[string]proto.Message),
		RouteType:    make(map[string]proto.Message),
		ClusterType:  make(map[string]proto.Message),
		EndpointType: make(map[string]proto.Message),
	}
}

func indexResources(resources map[string][]proto.Message) (map[string]map[string]proto.Message, error) {
	data := emptyIndexedResources()

	for typeURL, typeRes := range resources {
		for _, res := range typeRes {
			var name string
			switch typeURL {
			case ListenerType:
				l, ok := res.(*envoy_listener_v3.Listener)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = l.Name
			case RouteType:
				route, ok := res.(*envoy_route_v3.RouteConfiguration)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = route.Name
			case ClusterType:
				c, ok := res.(*envoy_cluster_v3.Cluster)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = c.Name
			case EndpointType:
				e, ok := res.(*envoy_endpoint_v3.ClusterLoadAssignment)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = e.ClusterName
			default:
				return nil, fmt.Errorf("unexpected xDS type found in delta snapshot: %s", typeURL)
			}
			data[typeURL][name] = res
		}
	}

	return data, nil
}

func newResourceMap(resources map[string][]proto.Message) (*ResourceMap, error) {
	m := newEmptyResourceMap()

	for typeURL, typeRes := range resources {
		for _, res := range typeRes {
			var name string
			switch typeURL {
			case ListenerType:
				l, ok := res.(*envoy_listener_v3.Listener)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = l.Name
			case RouteType:
				route, ok := res.(*envoy_route_v3.RouteConfiguration)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = route.Name
			case ClusterType:
				c, ok := res.(*envoy_cluster_v3.Cluster)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = c.Name
			case EndpointType:
				e, ok := res.(*envoy_endpoint_v3.ClusterLoadAssignment)
				if !ok {
					return nil, fmt.Errorf("unexpected value type for xDS type %s found in delta snapshot: %T", typeURL, res)
				}
				name = e.ClusterName
			default:
				return nil, fmt.Errorf("unexpected xDS type found in delta snapshot: %s", typeURL)
			}
			m.Data[typeURL][name] = res
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

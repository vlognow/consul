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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/logging"
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

	// xDS requires a unique nonce to correlate response/request pairs
	var nonce uint64
	_ = nonce

	// xDS works with versions of configs. Internally we don't have a consistent
	// version. We could hash the config since versions don't have to be
	// ordered as far as I can tell, but it is cheaper to increment a counter
	// every time we observe a new config since the upstream proxycfg package only
	// delivers updates when there are actual changes.
	var configVersion uint64

	// Loop state
	var (
		cfgSnap       *proxycfg.ConfigSnapshot
		delta         *DeltaSnapshot
		node          *envoy_config_core_v3.Node
		proxyFeatures supportedProxyFeatures
		stateCh       <-chan *proxycfg.ConfigSnapshot
		watchCancel   func()
		proxyID       structs.ServiceID

		// type => name => version (as envoy has CONFIRMED)
		resourceVersions map[string]map[string]string
		// nonce => type => name => version (in-flight updates to envoy, pending ACK/NACK)
		pendingUpdates map[string]map[string]map[string]string
		// type => name => version (as consul knows right now)
		currentVersions map[string]map[string]string
	)
	delta = newDeltaSnapshot()
	resourceVersions = map[string]map[string]string{
		ListenerType: make(map[string]string),
		RouteType:    make(map[string]string),
		ClusterType:  make(map[string]string),
		EndpointType: make(map[string]string),
	}
	pendingUpdates = make(map[string]map[string]map[string]string)

	// need to run a small state machine to get through initial authentication.
	var state = stateDeltaInit

	// Configure handlers for each type of request
	handlers := map[string]func(connectionInfo, *proxycfg.ConfigSnapshot) ([]proto.Message, error){
		ListenerType: s.listenersFromSnapshot,
		RouteType:    s.routesFromSnapshot,
		ClusterType:  s.clustersFromSnapshot,
		EndpointType: s.endpointsFromSnapshot,
	}

	var authTimer <-chan time.Time
	extendAuthTimer := func() {
		authTimer = time.After(s.AuthCheckFrequency)
	}

	checkStreamACLs := func(cfgSnap *proxycfg.ConfigSnapshot) error {
		return s.checkStreamACLs(stream.Context(), cfgSnap)
	}

	makeTypedResponse := func(typeUrl string) (*envoy_discovery_v3.DeltaDiscoveryResponse, map[string]string, error) {
		// compute difference

		updates := make(map[string]string)
		// First find things that need updating or deleting
		for name, envoyVers := range resourceVersions[typeUrl] {
			currVers, ok := currentVersions[typeUrl][name]
			if !ok {
				updates[name] = ""
			} else if currVers != envoyVers {
				updates[name] = currVers
			}
		}

		// Now find new things
		for name, currVers := range currentVersions[typeUrl] {
			if _, ok := resourceVersions[typeUrl]; !ok {
				updates[name] = currVers
			}
		}

		if len(updates) == 0 {
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
				res := delta.GetResource(typeUrl, name)
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

		nonce++
		resp.Nonce = fmt.Sprintf("%08x", nonce)

		return resp, updates, nil
	}

	for {
		select {
		case <-authTimer:
			// It's been too long since a Discovery{Request,Response} so recheck ACLs.
			if err := checkStreamACLs(cfgSnap); err != nil {
				return err
			}
			extendAuthTimer()

		case req, ok := <-reqCh:
			if !ok {
				// reqCh is closed when stream.Recv errors which is how we detect client
				// going away. AFAICT the stream.Context() is only canceled once the
				// RPC method returns which it can't until we return from this one so
				// there's no point in blocking on that.
				return nil
			}

			if req.ErrorDetail != nil {
				if req.ErrorDetail.Code == int32(codes.OK) {
					// ACK
					logger.Error("got ok response from envoy proxy", "nonce", req.ResponseNonce)

					if req.ResponseNonce != "" {
						pending, ok := pendingUpdates[req.ResponseNonce]
						if ok {
							for typeUrl, versions := range pending {
								for name, version := range versions {
									resourceVersions[typeUrl][name] = version
								}
							}
							delete(pendingUpdates, req.ResponseNonce)
						}
					}
				} else {
					// NACK
					logger.Error("got error response from envoy proxy", "nonce", req.ResponseNonce,
						"error", status.ErrorProto(req.ErrorDetail))

					if req.ResponseNonce != "" {
						delete(pendingUpdates, req.ResponseNonce)
					}
				}

				goto STATE_MACHINE
			}

			if req.TypeUrl == "" {
				return status.Errorf(codes.InvalidArgument, "type URL is required for ADS")
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
				resourceVersions[req.TypeUrl] = req.InitialResourceVersions
			}

			for _, name := range req.ResourceNamesUnsubscribe {
				if _, ok := resourceVersions[req.TypeUrl][name]; ok {
					logger.Trace("unsubscribing resource for stream", "typeUrl", req.TypeUrl, "resource", name)
					delete(resourceVersions[req.TypeUrl], name)
				}
			}

			for _, name := range req.ResourceNamesSubscribe {
				if _, ok := resourceVersions[req.TypeUrl][name]; !ok {
					logger.Trace("subscribing resource for stream", "typeUrl", req.TypeUrl, "resource", name)
					resourceVersions[req.TypeUrl][name] = "" // envoy has no version yet
				}
			}

		case cfgSnap = <-stateCh:
			// We got a new config, update the version counter
			configVersion++

			cInfo := connectionInfo{
				Token:         tokenFromContext(stream.Context()),
				ProxyFeatures: proxyFeatures,
			}

			// Convert the whole thing to xDS protos.
			newRes := make(map[string][]proto.Message)
			for typeURL, handler := range handlers {
				res, err := handler(cInfo, cfgSnap)
				if err != nil {
					return err
				}
				newRes[typeURL] = res
			}
			delta.Accept(newRes)
			delta.Commit() // TODO:refactor

			v, err := delta.AsVersions()
			if err != nil {
				return err
			}
			currentVersions = v

			// TODO: check delta.Dirty for work to do
			// TODO: trigger delta update?
		}

	STATE_MACHINE:

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

			if len(pendingUpdates) > 0 {
				logger.Trace("Skipping delta computation because there are responses in flight",
					"service_id", cfgSnap.ProxyID.String())
				continue
			}

			logger.Trace("Invoking all xDS resource handlers and sending changed data if there are any",
				"service_id", cfgSnap.ProxyID.String())

			{
				lresp, lupdates, err := makeTypedResponse(ListenerType)
				if err != nil {
					return err
				}
				if lresp != nil {
					if err := stream.Send(lresp); err != nil {
						return err
					}
					pendingUpdates[lresp.Nonce] = map[string]map[string]string{ListenerType: lupdates}
				}
			}

			{
				rresp, rupdates, err := makeTypedResponse(RouteType)
				if err != nil {
					return err
				}
				if rresp != nil {
					if err := stream.Send(rresp); err != nil {
						return err
					}
					pendingUpdates[rresp.Nonce] = map[string]map[string]string{RouteType: rupdates}
				}
			}

			{
				cresp, cupdates, err := makeTypedResponse(ClusterType)
				if err != nil {
					return err
				}
				if cresp != nil {
					if err := stream.Send(cresp); err != nil {
						return err
					}
					pendingUpdates[cresp.Nonce] = map[string]map[string]string{ClusterType: cupdates}
				}
			}

			{
				eresp, eupdates, err := makeTypedResponse(EndpointType)
				if err != nil {
					return err
				}
				if eresp != nil {
					if err := stream.Send(eresp); err != nil {
						return err
					}
					pendingUpdates[eresp.Nonce] = map[string]map[string]string{EndpointType: eupdates}
				}
			}
		}
	}
}

type DeltaSnapshot struct {
	// Ready means this has been populated at least once.
	Ready bool

	// Resources is the SoTW we are incrementally attempting to sync to envoy.
	Resources *ResourceMap // what envoy thinks is true

	// Dirty marks which attributes of Resources haven't been ACKd by envoy
	// yet. A nil payload implies "delete this".
	Dirty *ResourceMap

	// NextResources is the SoTW we will sync next, if we are still syncing
	// Resources and it's not completely ACKd yet.
	NextResources *ResourceMap
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

func (ds *DeltaSnapshot) Accept(resources map[string][]proto.Message) error {
	newMap, err := newResourceMap(resources)
	if err != nil {
		return err
	}

	if ds.Dirty != nil {
		// We are still syncing one snapshot, so just buffer this in the "lobby".
		ds.NextResources = newMap
		return nil
		// TODO: get stuff out of the lobby
	}

	changes := newEmptyResourceMap()
	changes.Listeners = computeDiff(newMap.Listeners, ds.Resources.Listeners)
	changes.Routes = computeDiff(newMap.Routes, ds.Resources.Routes)
	changes.Clusters = computeDiff(newMap.Clusters, ds.Resources.Clusters)
	changes.Endpoints = computeDiff(newMap.Endpoints, ds.Resources.Endpoints)

	if changes.IsEmpty() {
		return nil
	}
	fmt.Fprintf(os.Stdout, "RBOYER CHANGES: %s\n", jd(changes))

	ds.Dirty = changes
	ds.Resources = newMap
	ds.Ready = true

	return nil
}

func (ds *DeltaSnapshot) Commit() {
	ds.Dirty = nil
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

// 1 == copy; 2 == truth
func computeDiff(m1, m2 map[string]proto.Message) map[string]proto.Message {
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

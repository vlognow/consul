package xds

import (
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
	"github.com/hashicorp/consul/acl"
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
		req           *envoy_discovery_v3.DeltaDiscoveryRequest // TODO: subscription logic
		node          *envoy_config_core_v3.Node
		proxyFeatures supportedProxyFeatures
		ok            bool
		stateCh       <-chan *proxycfg.ConfigSnapshot
		watchCancel   func()
		proxyID       structs.ServiceID
	)
	delta = newDeltaSnapshot()

	// need to run a small state machine to get through initial authentication.
	var state = stateDeltaInit

	// Configure handlers for each type of request
	handlers := map[string]func(connectionInfo, *proxycfg.ConfigSnapshot) ([]proto.Message, error){
		EndpointType: s.endpointsFromSnapshot,
		ClusterType:  s.clustersFromSnapshot,
		RouteType:    s.routesFromSnapshot,
		ListenerType: s.listenersFromSnapshot,
	}

	var authTimer <-chan time.Time
	extendAuthTimer := func() {
		authTimer = time.After(s.AuthCheckFrequency)
	}

	checkStreamACLs := func(cfgSnap *proxycfg.ConfigSnapshot) error {
		if cfgSnap == nil {
			return status.Errorf(codes.Unauthenticated, "unauthenticated: no config snapshot")
		}

		rule, err := s.ResolveToken(tokenFromContext(stream.Context()))

		if acl.IsErrNotFound(err) {
			return status.Errorf(codes.Unauthenticated, "unauthenticated: %v", err)
		} else if acl.IsErrPermissionDenied(err) {
			return status.Errorf(codes.PermissionDenied, "permission denied: %v", err)
		} else if err != nil {
			return err
		}

		var authzContext acl.AuthorizerContext
		switch cfgSnap.Kind {
		case structs.ServiceKindConnectProxy:
			cfgSnap.ProxyID.EnterpriseMeta.FillAuthzContext(&authzContext)
			if rule != nil && rule.ServiceWrite(cfgSnap.Proxy.DestinationServiceName, &authzContext) != acl.Allow {
				return status.Errorf(codes.PermissionDenied, "permission denied")
			}
		case structs.ServiceKindMeshGateway, structs.ServiceKindTerminatingGateway, structs.ServiceKindIngressGateway:
			cfgSnap.ProxyID.EnterpriseMeta.FillAuthzContext(&authzContext)
			if rule != nil && rule.ServiceWrite(cfgSnap.Service, &authzContext) != acl.Allow {
				return status.Errorf(codes.PermissionDenied, "permission denied")
			}
		default:
			return status.Errorf(codes.Internal, "Invalid service kind")
		}

		// Authed OK!
		return nil
	}

	for {
		select {
		case <-authTimer:
			// It's been too long since a Discovery{Request,Response} so recheck ACLs.
			if err := checkStreamACLs(cfgSnap); err != nil {
				return err
			}
			extendAuthTimer()

		case req, ok = <-reqCh:
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

			if node == nil && req.Node != nil {
				node = req.Node
				var err error
				proxyFeatures, err = determineSupportedProxyFeatures(req.Node)
				if err != nil {
					return status.Errorf(codes.InvalidArgument, err.Error())
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

			// TODO: check delta.Dirty for work to do
			// TODO: trigger delta update?
		}

		// Trigger state machine
		switch state {
		case stateDeltaInit:
			if req == nil {
				// This can't happen (tm) since stateCh is nil until after the first req
				// is received but lets not panic about it.
				continue
			}
			// Start authentication process, we need the proxyID
			proxyID = structs.NewServiceID(req.Node.Id, parseEnterpriseMeta(req.Node))

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

			logger.Trace("Invoking all xDS resource handlers and sending new data if there is any",
				"service_id", cfgSnap.ProxyID.String())

			// See if any handlers need to have the current (possibly new) config
			// sent. Note the order here is actually significant so we can't just
			// range the map which has no determined order. It's important because:
			//
			//  1. Envoy needs to see a consistent snapshot to avoid potentially
			//     dropping traffic due to inconsistencies. This is the
			//     main win of ADS after all - we get to control this order.
			//  2. Non-determinsic order of complex protobuf responses which are
			//     compared for non-exact JSON equivalence makes the tests uber-messy
			//     to handle
			// for _, typeURL := range []string{ClusterType, EndpointType, RouteType, ListenerType} {
			// 	handler := handlers[typeURL]
			// 	if err := handler.SendIfNew(cfgSnap, configVersion, &nonce); err != nil {
			// 		return err
			// 	}
			// }
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

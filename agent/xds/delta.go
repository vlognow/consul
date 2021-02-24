package xds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/consul/agent/proxycfg"
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

func (s *Server) processDelta(stream ADSDeltaStream, reqCh <-chan *envoy_discovery_v3.DeltaDiscoveryRequest) error {
	logger := s.Logger.Named(logging.XDS).With("xds", "delta")
	_ = logger

	// TODO
	return errors.New("not implemented")
}

type DeltaSnapshot struct {
	Resources *ResourceMap                   // what envoy thinks is true
	Dirty     map[string]map[string]struct{} // type => name => {}
	Ready     bool
}

func newDeltaSnapshot() *DeltaSnapshot {
	return &DeltaSnapshot{
		Resources: newEmptyResourceMap(),
		Dirty:     make(map[string]map[string]struct{}),
	}
}

type ResourceMap struct {
	Listeners map[string]proto.Message
	Routes    map[string]proto.Message
	Clusters  map[string]proto.Message
	Endpoints map[string]proto.Message
}

func newEmptyResourceMap() *ResourceMap {
	return &ResourceMap{
		Listeners: make(map[string]proto.Message),
		Routes:    make(map[string]proto.Message),
		Clusters:  make(map[string]proto.Message),
		Endpoints: make(map[string]proto.Message),
	}
}

// 1 == consul; 2 == envoy
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

func (ds *DeltaSnapshot) Accept(resources map[string][]proto.Message) error {
	newMap, err := newResourceMap(resources)
	if err != nil {
		return err
	}
	_ = newMap

	// TODO: differential comparison
	changes := newEmptyResourceMap()
	changes.Listeners = computeDiff(newMap.Listeners, ds.Resources.Listeners)
	changes.Routes = computeDiff(newMap.Routes, ds.Resources.Routes)
	changes.Clusters = computeDiff(newMap.Clusters, ds.Resources.Clusters)
	changes.Endpoints = computeDiff(newMap.Endpoints, ds.Resources.Endpoints)

	fmt.Fprintf(os.Stdout, "RBOYER CHANGES: %s\n", jd(changes))

	ds.Resources = newMap
	ds.Ready = true
	// TODO: dirty

	return nil
}

func jd(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) snapshotToResources(snap *proxycfg.ConfigSnapshot) (map[string][]proto.Message, error) {
	m := make(map[string][]proto.Message)
	return m, nil
}

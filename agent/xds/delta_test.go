package xds

import (
	"testing"
	"time"

	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_network_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	envoy_tcp_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
)

// NOTE: For these tests, prefer not using xDS protobuf "factory" methods if
// possible to avoid using them to test themselves.
//
// Stick to very straightforward stuff in xds_protocol_helpers_test.go.

func TestServer_DeltaAggregatedResources_v3_BasicProtocol_TCP(t *testing.T) {
	aclResolve := func(id string) (acl.Authorizer, error) {
		// Allow all
		return acl.RootAuthorizer("manage"), nil
	}
	scenario := newTestServerDeltaScenario(t, aclResolve, "web-sidecar-proxy", "", 0)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	sid := structs.NewServiceID("web-sidecar-proxy", nil)

	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover (empty payload)
	// { "typeUrl": "type.googleapis.com/envoy.config.cluster.v3.Cluster" }
	envoy.SendDeltaReq(t, ClusterType, nil)

	// Check no response sent yet
	assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

	// Deliver a new snapshot (tcp with one tcp upstream)
	snap := newTestSnapshot(t, nil, "")
	mgr.DeliverConfig(t, sid, snap)

	assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
		TypeUrl: ClusterType,
		Nonce:   hexString(1),
		Resources: makeTestResources(t,
			makeTestCluster(t, snap, "tcp:local_app"),
			makeTestCluster(t, snap, "tcp:db"),
			makeTestCluster(t, snap, "tcp:geo-cache"),
		),
	})

	// Envoy then tries to discover endpoints for those clusters.
	// {
	//   "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
	//   "resourceNamesSubscribe": [
	//     "api.default.dc1.internal.2902259a-31e7-62e0-fccc-0d482f347e98.consul"
	//   ]
	// }
	envoy.SendDeltaReq(t, EndpointType, &envoy_discovery_v3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{
			"db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			"geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
		},
	})

	// It also (in parallel) issues the cluster ACK
	// { "typeUrl": "type.googleapis.com/envoy.config.cluster.v3.Cluster", "responseNonce": "00000001" }"
	envoy.SendDeltaReqACK(t, ClusterType, 1, true, nil)

	// We should get a response immediately since the config is already present in
	// the server for endpoints. Note that this should not be racy if the server
	// is behaving well since the Cluster send above should be blocked until we
	// deliver a new config version.
	assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
		TypeUrl: EndpointType,
		Nonce:   hexString(2),
		Resources: makeTestResources(t,
			makeTestEndpoints(t, snap, "tcp:db"),
			makeTestEndpoints(t, snap, "tcp:geo-cache"),
		),
	})

	// And no other response yet
	assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

	// Envoy now sends listener request
	// { "typeUrl": "type.googleapis.com/envoy.config.listener.v3.Listener" }
	envoy.SendDeltaReq(t, ListenerType, nil)

	// It also (in parallel) issues the endpoint ACK
	// { "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", "responseNonce": "00000002" }
	envoy.SendDeltaReqACK(t, EndpointType, 2, true, nil)

	// And should get a response immediately.
	assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
		TypeUrl: ListenerType,
		Nonce:   hexString(3),
		Resources: makeTestResources(t,
			makeTestListener(t, snap, "tcp:public_listener"),
			makeTestListener(t, snap, "tcp:db"),
			makeTestListener(t, snap, "tcp:geo-cache"),
		),
	})

	// And no other response yet
	assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

	// ACKs the listener
	// { "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.Listener", "responseNonce": "00000003" }
	envoy.SendDeltaReqACK(t, ListenerType, 3, true, nil)

	// And no other response yet
	assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

	// TODO: test NACK

	envoy.Close()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

func TestServer_DeltaAggregatedResources_v3_BasicProtocol_HTTP2(t *testing.T) {
	aclResolve := func(id string) (acl.Authorizer, error) {
		// Allow all
		return acl.RootAuthorizer("manage"), nil
	}
	scenario := newTestServerDeltaScenario(t, aclResolve, "web-sidecar-proxy", "", 0)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	sid := structs.NewServiceID("web-sidecar-proxy", nil)

	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover (empty payload)
	// { "typeUrl": "type.googleapis.com/envoy.config.cluster.v3.Cluster" }
	envoy.SendDeltaReq(t, ClusterType, nil)

	// Check no response sent yet
	assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

	// Deliver a new snapshot (tcp with one http upstream)
	snap := newTestSnapshot(t, nil, "http2", &structs.ServiceConfigEntry{
		Kind:     structs.ServiceDefaults,
		Name:     "db",
		Protocol: "http2",
	})
	mgr.DeliverConfig(t, sid, snap)

	require.True(t, t.Run("no-rds", func(t *testing.T) {
		assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: ClusterType,
			Nonce:   hexString(1),
			Resources: makeTestResources(t,
				makeTestCluster(t, snap, "tcp:local_app"),
				makeTestCluster(t, snap, "http2:db"),
				makeTestCluster(t, snap, "tcp:geo-cache"),
			),
		})

		// Envoy then tries to discover endpoints for those clusters.
		// {
		//   "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
		//   "resourceNamesSubscribe": [
		//     "api.default.dc1.internal.2902259a-31e7-62e0-fccc-0d482f347e98.consul"
		//   ]
		// }
		envoy.SendDeltaReq(t, EndpointType, &envoy_discovery_v3.DeltaDiscoveryRequest{
			ResourceNamesSubscribe: []string{
				"db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
				"geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
			},
		})

		// It also (in parallel) issues the cluster ACK
		// { "typeUrl": "type.googleapis.com/envoy.config.cluster.v3.Cluster", "responseNonce": "00000001" }"
		envoy.SendDeltaReqACK(t, ClusterType, 1, true, nil)

		// We should get a response immediately since the config is already present in
		// the server for endpoints. Note that this should not be racy if the server
		// is behaving well since the Cluster send above should be blocked until we
		// deliver a new config version.
		assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: EndpointType,
			Nonce:   hexString(2),
			Resources: makeTestResources(t,
				makeTestEndpoints(t, snap, "http2:db"),
				makeTestEndpoints(t, snap, "tcp:geo-cache"),
			),
		})

		// And no other response yet
		assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

		// Envoy now sends listener request
		// { "typeUrl": "type.googleapis.com/envoy.config.listener.v3.Listener" }
		envoy.SendDeltaReq(t, ListenerType, nil)

		// It also (in parallel) issues the endpoint ACK
		// { "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", "responseNonce": "00000002" }
		envoy.SendDeltaReqACK(t, EndpointType, 2, true, nil)

		// And should get a response immediately.
		assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: ListenerType,
			Nonce:   hexString(3),
			Resources: makeTestResources(t,
				makeTestListener(t, snap, "tcp:public_listener"),
				makeTestListener(t, snap, "http2:db"),
				makeTestListener(t, snap, "tcp:geo-cache"),
			),
		})

		// And no other response yet
		assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

		// ACKs the listener
		// { "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.Listener", "responseNonce": "00000003" }
		envoy.SendDeltaReqACK(t, ListenerType, 3, true, nil)

		// And no other response yet
		assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)
	}))

	// -- reconfigure with a no-op discovery chain

	snap = newTestSnapshot(t, snap, "http2", &structs.ServiceConfigEntry{
		Kind:     structs.ServiceDefaults,
		Name:     "db",
		Protocol: "http2",
	}, &structs.ServiceRouterConfigEntry{
		Kind:   structs.ServiceRouter,
		Name:   "db",
		Routes: nil,
	})
	mgr.DeliverConfig(t, sid, snap)

	require.True(t, t.Run("with-rds", func(t *testing.T) {
		// Just the "db" listener sees a change
		assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: ListenerType,
			Nonce:   hexString(4),
			Resources: makeTestResources(t,
				makeTestListener(t, snap, "http2:db:rds"),
			),
		})

		// And no other response yet
		assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)

		// Envoy now sends routes request
		// {
		//   "typeUrl": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
		//   "resourceNamesSubscribe": [
		//     "db"
		//   ]
		// }
		envoy.SendDeltaReq(t, RouteType, &envoy_discovery_v3.DeltaDiscoveryRequest{
			ResourceNamesSubscribe: []string{
				"db",
			},
		})

		// ACKs the listener
		// { "typeUrl": "type.googleapis.com/envoy.config.endpoint.v3.Listener", "responseNonce": "00000003" }
		envoy.SendDeltaReqACK(t, ListenerType, 4, true, nil)

		// And should get a response immediately.
		assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: RouteType,
			Nonce:   hexString(5),
			Resources: makeTestResources(t,
				makeTestRoute(t, "http2:db"),
			),
		})

		envoy.SendDeltaReqACK(t, RouteType, 5, true, nil)

		assertDeltaChanBlocked(t, envoy.deltaStream.sendCh)
	}))

	envoy.Close()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

func TestServer_DeltaAggregatedResources_v3_ACLEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		defaultDeny bool
		acl         string
		token       string
		wantDenied  bool
		cfgSnap     *proxycfg.ConfigSnapshot
	}{
		// Note that although we've stubbed actual ACL checks in the testManager
		// ConnectAuthorize mock, by asserting against specific reason strings here
		// even in the happy case which can't match the default one returned by the
		// mock we are implicitly validating that the implementation used the
		// correct token from the context.
		{
			name:        "no ACLs configured",
			defaultDeny: false,
			wantDenied:  false,
		},
		{
			name:        "default deny, no token",
			defaultDeny: true,
			wantDenied:  true,
		},
		{
			name:        "default deny, write token",
			defaultDeny: true,
			acl:         `service "web" { policy = "write" }`,
			token:       "service-write-on-web",
			wantDenied:  false,
		},
		{
			name:        "default deny, read token",
			defaultDeny: true,
			acl:         `service "web" { policy = "read" }`,
			token:       "service-write-on-web",
			wantDenied:  true,
		},
		{
			name:        "default deny, write token on different service",
			defaultDeny: true,
			acl:         `service "not-web" { policy = "write" }`,
			token:       "service-write-on-not-web",
			wantDenied:  true,
		},
		{
			name:        "ingress default deny, write token on different service",
			defaultDeny: true,
			acl:         `service "not-ingress" { policy = "write" }`,
			token:       "service-write-on-not-ingress",
			wantDenied:  true,
			cfgSnap:     proxycfg.TestConfigSnapshotIngressGateway(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclResolve := func(id string) (acl.Authorizer, error) {
				if !tt.defaultDeny {
					// Allow all
					return acl.RootAuthorizer("allow"), nil
				}
				if tt.acl == "" {
					// No token and defaultDeny is denied
					return acl.RootAuthorizer("deny"), nil
				}
				// Ensure the correct token was passed
				require.Equal(t, tt.token, id)
				// Parse the ACL and enforce it
				policy, err := acl.NewPolicyFromSource("", 0, tt.acl, acl.SyntaxLegacy, nil, nil)
				require.NoError(t, err)
				return acl.NewPolicyAuthorizerWithDefaults(acl.RootAuthorizer("deny"), []*acl.Policy{policy}, nil)
			}

			scenario := newTestServerDeltaScenario(t, aclResolve, "web-sidecar-proxy", tt.token, 0)
			mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

			sid := structs.NewServiceID("web-sidecar-proxy", nil)
			// Register the proxy to create state needed to Watch() on
			mgr.RegisterProxy(t, sid)

			// Deliver a new snapshot
			snap := tt.cfgSnap
			if snap == nil {
				snap = newTestSnapshot(t, nil, "")
			}
			mgr.DeliverConfig(t, sid, snap)

			// Send initial listener discover, in real life Envoy always sends cluster
			// first but it doesn't really matter and listener has a response that
			// includes the token in the ext rbac filter so lets us test more stuff.
			envoy.SendDeltaReq(t, ListenerType, nil)

			if !tt.wantDenied {
				assertDeltaResponseSent(t, envoy.deltaStream.sendCh, &envoy_discovery_v3.DeltaDiscoveryResponse{
					TypeUrl: ListenerType,
					Nonce:   hexString(1),
					Resources: makeTestResources(t,
						makeTestListener(t, snap, "tcp:public_listener"),
						makeTestListener(t, snap, "tcp:db"),
						makeTestListener(t, snap, "tcp:geo-cache"),
					),
				})
				// Close the client stream since all is well. We _don't_ do this in the
				// expected error case because we want to verify the error closes the
				// stream from server side.
				envoy.Close()
			}

			select {
			case err := <-errCh:
				if tt.wantDenied {
					require.Error(t, err)
					require.Contains(t, err.Error(), "permission denied")
					mgr.AssertWatchCancelled(t, sid)
				} else {
					require.NoError(t, err)
				}
			case <-time.After(50 * time.Millisecond):
				t.Fatalf("timed out waiting for handler to finish")
			}
		})
	}
}

// TODO: fork TestServer_StreamAggregatedResources_v2_ACLTokenDeleted_StreamTerminatedDuringDiscoveryRequest
// TODO: fork TestServer_StreamAggregatedResources_v2_ACLTokenDeleted_StreamTerminatedInBackground
// TODO: fork TestServer_StreamAggregatedResources_v2_IngressEmptyResponse

func assertDeltaChanBlocked(t *testing.T, ch chan *envoy_discovery_v3.DeltaDiscoveryResponse) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("chan should block but received: %v", r)
	case <-time.After(10 * time.Millisecond):
		return
	}
}

func assertDeltaResponseSent(t *testing.T, ch chan *envoy_discovery_v3.DeltaDiscoveryResponse, want *envoy_discovery_v3.DeltaDiscoveryResponse) {
	t.Helper()
	select {
	case got := <-ch:
		assertDeltaResponse(t, got, want)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("no response received after 50ms")
	}
}

// assertDeltaResponse is a helper to test a envoy.DeltaDiscoveryResponse matches the
// JSON representation we expect. We use JSON because the responses use protobuf
// Any type which includes binary protobuf encoding and would make creating
// expected structs require the same code that is under test!
func assertDeltaResponse(t *testing.T, got, want *envoy_discovery_v3.DeltaDiscoveryResponse) {
	t.Helper()

	gotJSON := protoToSortedJSON(t, got)
	wantJSON := protoToSortedJSON(t, want)
	require.JSONEqf(t, wantJSON, gotJSON, "got:\n%s", gotJSON)
}

func makeTestCluster(t *testing.T, snap *proxycfg.ConfigSnapshot, fixtureName string) *envoy_cluster_v3.Cluster {
	switch fixtureName {
	case "tcp:local_app":
		return &envoy_cluster_v3.Cluster{
			Name: "local_app",
			ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{
				Type: envoy_cluster_v3.Cluster_STATIC,
			},
			ConnectTimeout: ptypes.DurationProto(5 * time.Second),
			LoadAssignment: &envoy_endpoint_v3.ClusterLoadAssignment{
				ClusterName: "local_app",
				Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpoint("127.0.0.1", 8080),
					},
				}},
			},
		}
	case "tcp:db":
		return &envoy_cluster_v3.Cluster{
			Name: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{
				Type: envoy_cluster_v3.Cluster_EDS,
			},
			EdsClusterConfig: &envoy_cluster_v3.Cluster_EdsClusterConfig{
				EdsConfig: xdsNewADSConfig(),
			},
			CircuitBreakers:  &envoy_cluster_v3.CircuitBreakers{},
			OutlierDetection: &envoy_cluster_v3.OutlierDetection{},
			AltStatName:      "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			CommonLbConfig: &envoy_cluster_v3.Cluster_CommonLbConfig{
				HealthyPanicThreshold: &envoy_type_v3.Percent{Value: 0},
			},
			ConnectTimeout:  ptypes.DurationProto(5 * time.Second),
			TransportSocket: xdsNewUpstreamTransportSocket(t, snap, "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul"),
		}
	case "http2:db":
		return &envoy_cluster_v3.Cluster{
			Name: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{
				Type: envoy_cluster_v3.Cluster_EDS,
			},
			EdsClusterConfig: &envoy_cluster_v3.Cluster_EdsClusterConfig{
				EdsConfig: xdsNewADSConfig(),
			},
			CircuitBreakers:  &envoy_cluster_v3.CircuitBreakers{},
			OutlierDetection: &envoy_cluster_v3.OutlierDetection{},
			AltStatName:      "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			CommonLbConfig: &envoy_cluster_v3.Cluster_CommonLbConfig{
				HealthyPanicThreshold: &envoy_type_v3.Percent{Value: 0},
			},
			ConnectTimeout:       ptypes.DurationProto(5 * time.Second),
			TransportSocket:      xdsNewUpstreamTransportSocket(t, snap, "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul"),
			Http2ProtocolOptions: &envoy_core_v3.Http2ProtocolOptions{},
		}
	case "tcp:geo-cache":
		return &envoy_cluster_v3.Cluster{
			Name: "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
			ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{
				Type: envoy_cluster_v3.Cluster_EDS,
			},
			EdsClusterConfig: &envoy_cluster_v3.Cluster_EdsClusterConfig{
				EdsConfig: xdsNewADSConfig(),
			},
			CircuitBreakers:  &envoy_cluster_v3.CircuitBreakers{},
			OutlierDetection: &envoy_cluster_v3.OutlierDetection{},
			ConnectTimeout:   ptypes.DurationProto(5 * time.Second),
			TransportSocket:  xdsNewUpstreamTransportSocket(t, snap, "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul"),
		}
	default:
		t.Fatalf("unexpected fixture name: %s", fixtureName)
		return nil
	}
}

func makeTestEndpoints(t *testing.T, snap *proxycfg.ConfigSnapshot, fixtureName string) *envoy_endpoint_v3.ClusterLoadAssignment {
	switch fixtureName {
	case "tcp:db":
		return &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpointWithHealth("10.10.1.1", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
						xdsNewEndpointWithHealth("10.10.1.2", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
					},
				},
			},
		}
	case "http2:db":
		return &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpointWithHealth("10.10.1.1", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
						xdsNewEndpointWithHealth("10.10.1.2", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
					},
				},
			},
		}
	case "tcp:geo-cache":
		return &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpointWithHealth("10.10.1.1", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
						xdsNewEndpointWithHealth("10.10.1.2", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
					},
				},
			},
		}
	default:
		t.Fatalf("unexpected fixture name: %s", fixtureName)
		return nil
	}
}

func makeTestListener(t *testing.T, snap *proxycfg.ConfigSnapshot, fixtureName string) *envoy_listener_v3.Listener {
	switch fixtureName {
	case "tcp:public_listener":
		return &envoy_listener_v3.Listener{
			Name:             "public_listener:0.0.0.0:9999",
			Address:          makeAddress("0.0.0.0", 9999),
			TrafficDirection: envoy_core_v3.TrafficDirection_INBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					TransportSocket: xdsNewPublicTransportSocket(t, snap),
					Filters: []*envoy_listener_v3.Filter{
						xdsNewFilter(t, "envoy.filters.network.rbac", &envoy_network_rbac_v3.RBAC{
							Rules:      &envoy_rbac_v3.RBAC{},
							StatPrefix: "connect_authz",
						}),
						xdsNewFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "local_app",
							},
							StatPrefix: "public_listener",
						}),
					},
				},
			},
		}
	case "tcp:db":
		return &envoy_listener_v3.Listener{
			Name:             "db:127.0.0.1:9191",
			Address:          makeAddress("127.0.0.1", 9191),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						xdsNewFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
							},
							StatPrefix: "upstream.db.default.dc1",
						}),
					},
				},
			},
		}
	case "http2:db":
		return &envoy_listener_v3.Listener{
			Name:             "db:127.0.0.1:9191",
			Address:          makeAddress("127.0.0.1", 9191),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						xdsNewFilter(t, "envoy.filters.network.http_connection_manager", &envoy_http_v3.HttpConnectionManager{
							HttpFilters: []*envoy_http_v3.HttpFilter{
								{Name: "envoy.filters.http.router"},
							},
							RouteSpecifier: &envoy_http_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: makeTestRoute(t, "http2:db:inline"),
							},
							StatPrefix: "upstream.db.default.dc1",
							Tracing: &envoy_http_v3.HttpConnectionManager_Tracing{
								RandomSampling: &envoy_type_v3.Percent{Value: 0},
							},
							Http2ProtocolOptions: &envoy_core_v3.Http2ProtocolOptions{},
						}),
					},
				},
			},
		}
	case "http2:db:rds":
		return &envoy_listener_v3.Listener{
			Name:             "db:127.0.0.1:9191",
			Address:          makeAddress("127.0.0.1", 9191),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						xdsNewFilter(t, "envoy.filters.network.http_connection_manager", &envoy_http_v3.HttpConnectionManager{
							HttpFilters: []*envoy_http_v3.HttpFilter{
								{Name: "envoy.filters.http.router"},
							},
							RouteSpecifier: &envoy_http_v3.HttpConnectionManager_Rds{
								Rds: &envoy_http_v3.Rds{
									RouteConfigName: "db",
									ConfigSource:    xdsNewADSConfig(),
								},
							},
							StatPrefix: "upstream.db.default.dc1",
							Tracing: &envoy_http_v3.HttpConnectionManager_Tracing{
								RandomSampling: &envoy_type_v3.Percent{Value: 0},
							},
							Http2ProtocolOptions: &envoy_core_v3.Http2ProtocolOptions{},
						}),
					},
				},
			},
		}
	case "tcp:geo-cache":
		return &envoy_listener_v3.Listener{
			Name:             "prepared_query:geo-cache:127.10.10.10:8181",
			Address:          makeAddress("127.10.10.10", 8181),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						xdsNewFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
							},
							StatPrefix: "upstream.prepared_query_geo-cache",
						}),
					},
				},
			},
		}
	default:
		t.Fatalf("unexpected fixture name: %s", fixtureName)
		return nil
	}
}

func makeTestRoute(t *testing.T, fixtureName string) *envoy_route_v3.RouteConfiguration {
	switch fixtureName {
	case "http2:db":
		return &envoy_route_v3.RouteConfiguration{
			Name:             "db",
			ValidateClusters: makeBoolValue(true),
			VirtualHosts: []*envoy_route_v3.VirtualHost{
				{
					Name:    "db",
					Domains: []string{"*"},
					Routes: []*envoy_route_v3.Route{
						{
							Match: &envoy_route_v3.RouteMatch{
								PathSpecifier: &envoy_route_v3.RouteMatch_Prefix{
									Prefix: "/",
								},
							},
							Action: &envoy_route_v3.Route_Route{
								Route: &envoy_route_v3.RouteAction{
									ClusterSpecifier: &envoy_route_v3.RouteAction_Cluster{
										Cluster: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
									},
								},
							},
						},
					},
				},
			},
		}
	case "http2:db:inline":
		return &envoy_route_v3.RouteConfiguration{
			Name: "db",
			VirtualHosts: []*envoy_route_v3.VirtualHost{
				{
					Name:    "db.default.dc1",
					Domains: []string{"*"},
					Routes: []*envoy_route_v3.Route{
						{
							Match: &envoy_route_v3.RouteMatch{
								PathSpecifier: &envoy_route_v3.RouteMatch_Prefix{
									Prefix: "/",
								},
							},
							Action: &envoy_route_v3.Route_Route{
								Route: &envoy_route_v3.RouteAction{
									ClusterSpecifier: &envoy_route_v3.RouteAction_Cluster{
										Cluster: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
									},
								},
							},
						},
					},
				},
			},
		}
	default:
		t.Fatalf("unexpected fixture name: %s", fixtureName)
		return nil
	}
}

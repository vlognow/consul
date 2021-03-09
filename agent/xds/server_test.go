package xds

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	envoy_api_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_network_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	envoy_tcp_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/sdk/testutil"
)

// NOTE: For these tests, prefer not using xDS protobuf "factory" methods if
// possible to avoid using them to test themselves.

// testManager is a mock of proxycfg.Manager that's simpler to control for
// testing. It also implements ConnectAuthz to allow control over authorization.
type testManager struct {
	sync.Mutex
	chans   map[structs.ServiceID]chan *proxycfg.ConfigSnapshot
	cancels chan structs.ServiceID
}

func newTestManager(t *testing.T) *testManager {
	return &testManager{
		chans:   map[structs.ServiceID]chan *proxycfg.ConfigSnapshot{},
		cancels: make(chan structs.ServiceID, 10),
	}
}

// RegisterProxy simulates a proxy registration
func (m *testManager) RegisterProxy(t *testing.T, proxyID structs.ServiceID) {
	m.Lock()
	defer m.Unlock()
	m.chans[proxyID] = make(chan *proxycfg.ConfigSnapshot, 1)
}

// Deliver simulates a proxy registration
func (m *testManager) DeliverConfig(t *testing.T, proxyID structs.ServiceID, cfg *proxycfg.ConfigSnapshot) {
	t.Helper()
	m.Lock()
	defer m.Unlock()
	select {
	case m.chans[proxyID] <- cfg:
	case <-time.After(10 * time.Millisecond):
		t.Fatalf("took too long to deliver config")
	}
}

// Watch implements ConfigManager
func (m *testManager) Watch(proxyID structs.ServiceID) (<-chan *proxycfg.ConfigSnapshot, proxycfg.CancelFunc) {
	m.Lock()
	defer m.Unlock()
	// ch might be nil but then it will just block forever
	return m.chans[proxyID], func() {
		m.cancels <- proxyID
	}
}

// AssertWatchCancelled checks that the most recent call to a Watch cancel func
// was from the specified proxyID and that one is made in a short time. This
// probably won't work if you are running multiple Watches in parallel on
// multiple proxyIDS due to timing/ordering issues but I don't think we need to
// do that.
func (m *testManager) AssertWatchCancelled(t *testing.T, proxyID structs.ServiceID) {
	t.Helper()
	select {
	case got := <-m.cancels:
		require.Equal(t, proxyID, got)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for Watch cancel for %s", proxyID)
	}
}

type testServerScenario struct {
	server *Server
	mgr    *testManager
	envoy  *TestEnvoy
	errCh  <-chan error
}

func newTestServerScenario(
	t *testing.T,
	resolveToken ACLResolverFunc,
	proxyID string,
	token string,
	authCheckFrequency time.Duration,
) *testServerScenario {
	return newTestServerScenarioInner(t, resolveToken, proxyID, token, authCheckFrequency, false)
}

func newTestServerDeltaScenario(
	t *testing.T,
	resolveToken ACLResolverFunc,
	proxyID string,
	token string,
	authCheckFrequency time.Duration,
) *testServerScenario {
	return newTestServerScenarioInner(t, resolveToken, proxyID, token, authCheckFrequency, true)
}

func newTestServerScenarioInner(
	t *testing.T,
	resolveToken ACLResolverFunc,
	proxyID string,
	token string,
	authCheckFrequency time.Duration,
	incremental bool,
) *testServerScenario {
	mgr := newTestManager(t)
	envoy := NewTestEnvoy(t, proxyID, token)
	t.Cleanup(func() {
		envoy.Close()
	})

	s := &Server{
		Logger:             testutil.Logger(t),
		CfgMgr:             mgr,
		ResolveToken:       resolveToken,
		AuthCheckFrequency: authCheckFrequency,
	}

	errCh := make(chan error, 1)
	go func() {
		if incremental {
			errCh <- s.DeltaAggregatedResources(envoy.deltaStream)
		} else {
			shim := &adsServerV2Shim{srv: s}
			errCh <- shim.StreamAggregatedResources(envoy.stream)
		}
	}()

	return &testServerScenario{
		server: s,
		mgr:    mgr,
		envoy:  envoy,
		errCh:  errCh,
	}
}

func TestServer_StreamAggregatedResources_v2_BasicProtocol(t *testing.T) {
	aclResolve := func(id string) (acl.Authorizer, error) {
		// Allow all
		return acl.RootAuthorizer("manage"), nil
	}
	scenario := newTestServerScenario(t, aclResolve, "web-sidecar-proxy", "", 0)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	sid := structs.NewServiceID("web-sidecar-proxy", nil)

	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover (empty payload)
	envoy.SendReq(t, ClusterType, 0, 0)

	// Check no response sent yet
	assertChanBlocked(t, envoy.stream.sendCh)

	// Deliver a new snapshot
	snap := proxycfg.TestConfigSnapshot(t)
	mgr.DeliverConfig(t, sid, snap)

	assertResponseSent(t, envoy.stream.sendCh, expectClustersJSON_v2(t, snap, 1, 1))

	// Envoy then tries to discover endpoints for those clusters. Technically it
	// includes the cluster names in the ResourceNames field but we ignore that
	// completely for now so not bothering to simulate that.
	envoy.SendReq(t, EndpointType, 0, 0)

	// It also (in parallel) issues the next cluster request (which acts as an ACK
	// of the version we sent)
	envoy.SendReq(t, ClusterType, 1, 1)

	// We should get a response immediately since the config is already present in
	// the server for endpoints. Note that this should not be racy if the server
	// is behaving well since the Cluster send above should be blocked until we
	// deliver a new config version.
	assertResponseSent(t, envoy.stream.sendCh, expectEndpointsJSON_v2(t, 1, 2))

	// And no other response yet
	assertChanBlocked(t, envoy.stream.sendCh)

	// Envoy now sends listener request along with next endpoint one
	envoy.SendReq(t, ListenerType, 0, 0)
	envoy.SendReq(t, EndpointType, 1, 2)

	// And should get a response immediately.
	assertResponseSent(t, envoy.stream.sendCh, expectListenerJSON_v2(t, snap, 1, 3))

	// Now send Route request along with next listener one
	envoy.SendReq(t, RouteType, 0, 0)
	envoy.SendReq(t, ListenerType, 1, 3)

	// We don't serve routes yet so this should block with no response
	assertChanBlocked(t, envoy.stream.sendCh)

	// WOOP! Envoy now has full connect config. Lets verify that if we update it,
	// all the responses get resent with the new version. We don't actually want
	// to change everything because that's tedious - our implementation will
	// actually resend all blocked types on the new "version" anyway since it
	// doesn't know _what_ changed. We could do something trivial but let's
	// simulate a leaf cert expiring and being rotated.
	snap.ConnectProxy.Leaf = proxycfg.TestLeafForCA(t, snap.Roots.Roots[0])
	mgr.DeliverConfig(t, sid, snap)

	// All 3 response that have something to return should return with new version
	// note that the ordering is not deterministic in general. Trying to make this
	// test order-agnostic though is a massive pain since we are comparing
	// non-identical JSON strings (so can simply sort by anything) and because we
	// don't know the order the nonces will be assigned. For now we rely and
	// require our implementation to always deliver updates in a specific order
	// which is reasonable anyway to ensure consistency of the config Envoy sees.
	assertResponseSent(t, envoy.stream.sendCh, expectClustersJSON_v2(t, snap, 2, 4))
	assertResponseSent(t, envoy.stream.sendCh, expectEndpointsJSON_v2(t, 2, 5))
	assertResponseSent(t, envoy.stream.sendCh, expectListenerJSON_v2(t, snap, 2, 6))

	// Let's pretend that Envoy doesn't like that new listener config. It will ACK
	// all the others (same version) but NACK the listener. This is the most
	// subtle part of xDS and the server implementation so I'll elaborate. A full
	// description of the protocol can be found at
	// https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol
	// Envoy delays making a followup request for a type until after it has
	// processed and applied the last response. The next request then will include
	// the nonce in the last response which acknowledges _receiving_ and handling
	// that response. It also includes the currently applied version. If all is
	// good and it successfully applies the config, then the version in the next
	// response will be the same version just sent. This is considered to be an
	// ACK of that version for that type. If envoy fails to apply the config for
	// some reason, it will still acknowledge that it received it (still return
	// the responses nonce), but will show the previous version it's still using.
	// This is considered a NACK. It's important that the server pay attention to
	// the _nonce_ and not the version when deciding what to send otherwise a bad
	// version that can't be applied in Envoy will cause a busy loop.
	//
	// In this case we are simulating that Envoy failed to apply the Listener
	// response but did apply the other types so all get the new nonces, but
	// listener stays on v1.
	envoy.SendReq(t, ClusterType, 2, 4)
	envoy.SendReq(t, EndpointType, 2, 5)
	envoy.SendReq(t, ListenerType, 1, 6) // v1 is a NACK (TODO(rb): this should have error detail info)

	// Even though we nacked, we should still NOT get then v2 listeners
	// redelivered since nothing has changed.
	assertChanBlocked(t, envoy.stream.sendCh)

	// Change config again and make sure it's delivered to everyone!
	snap.ConnectProxy.Leaf = proxycfg.TestLeafForCA(t, snap.Roots.Roots[0])
	mgr.DeliverConfig(t, sid, snap)

	assertResponseSent(t, envoy.stream.sendCh, expectClustersJSON_v2(t, snap, 3, 7))
	assertResponseSent(t, envoy.stream.sendCh, expectEndpointsJSON_v2(t, 3, 8))
	assertResponseSent(t, envoy.stream.sendCh, expectListenerJSON_v2(t, snap, 3, 9))

	envoy.Close()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

func assertChanBlocked(t *testing.T, ch chan *envoy_api_v2.DiscoveryResponse) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("chan should block but received: %v", r)
	case <-time.After(10 * time.Millisecond):
		return
	}
}

func assertResponseSent(t *testing.T, ch chan *envoy_api_v2.DiscoveryResponse, want *envoy_api_v2.DiscoveryResponse) {
	t.Helper()
	select {
	case got := <-ch:
		assertResponse(t, got, want)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("no response received after 50ms")
	}
}

// assertResponse is a helper to test a envoy.DiscoveryResponse matches the
// JSON representation we expect. We use JSON because the responses use protobuf
// Any type which includes binary protobuf encoding and would make creating
// expected structs require the same code that is under test!
func assertResponse(t *testing.T, got, want *envoy_api_v2.DiscoveryResponse) {
	t.Helper()

	gotJSON := protoToJSON(t, got)
	wantJSON := protoToJSON(t, want)
	require.JSONEqf(t, wantJSON, gotJSON, "got:\n%s", gotJSON)
}

func TestServer_StreamAggregatedResources_v2_ACLEnforcement(t *testing.T) {
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

			scenario := newTestServerScenario(t, aclResolve, "web-sidecar-proxy", tt.token, 0)
			mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

			sid := structs.NewServiceID("web-sidecar-proxy", nil)
			// Register the proxy to create state needed to Watch() on
			mgr.RegisterProxy(t, sid)

			// Deliver a new snapshot
			snap := tt.cfgSnap
			if snap == nil {
				snap = proxycfg.TestConfigSnapshot(t)
			}
			mgr.DeliverConfig(t, sid, snap)

			// Send initial listener discover, in real life Envoy always sends cluster
			// first but it doesn't really matter and listener has a response that
			// includes the token in the ext rbac filter so lets us test more stuff.
			envoy.SendReq(t, ListenerType, 0, 0)

			if !tt.wantDenied {
				assertResponseSent(t, envoy.stream.sendCh, expectListenerJSON_v2(t, snap, 1, 1))
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

func TestServer_StreamAggregatedResources_v2_ACLTokenDeleted_StreamTerminatedDuringDiscoveryRequest(t *testing.T) {
	aclRules := `service "web" { policy = "write" }`
	token := "service-write-on-web"

	policy, err := acl.NewPolicyFromSource("", 0, aclRules, acl.SyntaxLegacy, nil, nil)
	require.NoError(t, err)

	var validToken atomic.Value
	validToken.Store(token)

	aclResolve := func(id string) (acl.Authorizer, error) {
		if token := validToken.Load(); token == nil || id != token.(string) {
			return nil, acl.ErrNotFound
		}

		return acl.NewPolicyAuthorizerWithDefaults(acl.RootAuthorizer("deny"), []*acl.Policy{policy}, nil)
	}
	scenario := newTestServerScenario(t, aclResolve, "web-sidecar-proxy", token,
		1*time.Hour, // make sure this doesn't kick in
	)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	getError := func() (gotErr error, ok bool) {
		select {
		case err := <-errCh:
			return err, true
		default:
			return nil, false
		}
	}

	sid := structs.NewServiceID("web-sidecar-proxy", nil)
	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover (OK)
	envoy.SendReq(t, ClusterType, 0, 0)
	{
		err, ok := getError()
		require.NoError(t, err)
		require.False(t, ok)
	}

	// Check no response sent yet
	assertChanBlocked(t, envoy.stream.sendCh)
	{
		err, ok := getError()
		require.NoError(t, err)
		require.False(t, ok)
	}

	// Deliver a new snapshot
	snap := proxycfg.TestConfigSnapshot(t)
	mgr.DeliverConfig(t, sid, snap)

	assertResponseSent(t, envoy.stream.sendCh, expectClustersJSON_v2(t, snap, 1, 1))

	// Now nuke the ACL token.
	validToken.Store("")

	// It also (in parallel) issues the next cluster request (which acts as an ACK
	// of the version we sent)
	envoy.SendReq(t, ClusterType, 1, 1)

	select {
	case err := <-errCh:
		require.Error(t, err)
		gerr, ok := status.FromError(err)
		require.Truef(t, ok, "not a grpc status error: type='%T' value=%v", err, err)
		require.Equal(t, codes.Unauthenticated, gerr.Code())
		require.Equal(t, "unauthenticated: ACL not found", gerr.Message())

		mgr.AssertWatchCancelled(t, sid)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

func TestServer_StreamAggregatedResources_v2_ACLTokenDeleted_StreamTerminatedInBackground(t *testing.T) {
	if testing.Short() {
		t.Skip("too slow for testing.Short")
	}

	aclRules := `service "web" { policy = "write" }`
	token := "service-write-on-web"

	policy, err := acl.NewPolicyFromSource("", 0, aclRules, acl.SyntaxLegacy, nil, nil)
	require.NoError(t, err)

	var validToken atomic.Value
	validToken.Store(token)

	aclResolve := func(id string) (acl.Authorizer, error) {
		if token := validToken.Load(); token == nil || id != token.(string) {
			return nil, acl.ErrNotFound
		}

		return acl.NewPolicyAuthorizerWithDefaults(acl.RootAuthorizer("deny"), []*acl.Policy{policy}, nil)
	}
	scenario := newTestServerScenario(t, aclResolve, "web-sidecar-proxy", token,
		100*time.Millisecond, // Make this short.
	)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	getError := func() (gotErr error, ok bool) {
		select {
		case err := <-errCh:
			return err, true
		default:
			return nil, false
		}
	}

	sid := structs.NewServiceID("web-sidecar-proxy", nil)
	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover (OK)
	envoy.SendReq(t, ClusterType, 0, 0)
	{
		err, ok := getError()
		require.NoError(t, err)
		require.False(t, ok)
	}

	// Check no response sent yet
	assertChanBlocked(t, envoy.stream.sendCh)
	{
		err, ok := getError()
		require.NoError(t, err)
		require.False(t, ok)
	}

	// Deliver a new snapshot
	snap := proxycfg.TestConfigSnapshot(t)
	mgr.DeliverConfig(t, sid, snap)

	assertResponseSent(t, envoy.stream.sendCh, expectClustersJSON_v2(t, snap, 1, 1))

	// It also (in parallel) issues the next cluster request (which acts as an ACK
	// of the version we sent)
	envoy.SendReq(t, ClusterType, 1, 1)

	// Check no response sent yet
	assertChanBlocked(t, envoy.stream.sendCh)
	{
		err, ok := getError()
		require.NoError(t, err)
		require.False(t, ok)
	}

	// Now nuke the ACL token while there's no activity.
	validToken.Store("")

	select {
	case err := <-errCh:
		require.Error(t, err)
		gerr, ok := status.FromError(err)
		require.Truef(t, ok, "not a grpc status error: type='%T' value=%v", err, err)
		require.Equal(t, codes.Unauthenticated, gerr.Code())
		require.Equal(t, "unauthenticated: ACL not found", gerr.Message())

		mgr.AssertWatchCancelled(t, sid)
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

// NOTE: this test sidesteps the v3-only-does-incremental so it can test
// v2-state-of-the-world-xDS indirectly via the v3 version
func TestServer_StreamAggregatedResources_v2_IngressEmptyResponse(t *testing.T) {
	aclResolve := func(id string) (acl.Authorizer, error) {
		// Allow all
		return acl.RootAuthorizer("manage"), nil
	}
	scenario := newTestServerScenario(t, aclResolve, "ingress-gateway", "", 0)
	mgr, errCh, envoy := scenario.mgr, scenario.errCh, scenario.envoy

	sid := structs.NewServiceID("ingress-gateway", nil)

	// Register the proxy to create state needed to Watch() on
	mgr.RegisterProxy(t, sid)

	// Send initial cluster discover
	envoy.SendReq(t, ClusterType, 0, 0)

	// Check no response sent yet
	assertChanBlocked(t, envoy.stream.sendCh)

	// Deliver a new snapshot with no services
	snap := proxycfg.TestConfigSnapshotIngressGatewayNoServices(t)
	mgr.DeliverConfig(t, sid, snap)

	emptyClusterResp, err := convertDiscoveryResponseToV2(&envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(1),
		TypeUrl:     ClusterType,
		Nonce:       hexString(1),
	})
	require.NoError(t, err)
	emptyListenerResp, err := convertDiscoveryResponseToV2(&envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(1),
		TypeUrl:     ListenerType,
		Nonce:       hexString(2),
	})
	require.NoError(t, err)
	emptyRouteResp, err := convertDiscoveryResponseToV2(&envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(1),
		TypeUrl:     RouteType,
		Nonce:       hexString(3),
	})
	require.NoError(t, err)

	assertResponseSent(t, envoy.stream.sendCh, emptyClusterResp)

	// Send initial listener discover
	envoy.SendReq(t, ListenerType, 0, 0)
	assertResponseSent(t, envoy.stream.sendCh, emptyListenerResp)

	envoy.SendReq(t, RouteType, 0, 0)
	assertResponseSent(t, envoy.stream.sendCh, emptyRouteResp)

	envoy.Close()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timed out waiting for handler to finish")
	}
}

func expectListenerJSON_v2(t *testing.T, snap *proxycfg.ConfigSnapshot, v, n uint64) *envoy_api_v2.DiscoveryResponse {
	v3 := expectListenerJSON_v3(t, snap, v, n)

	v2, err := convertDiscoveryResponseToV2(v3)
	require.NoError(t, err)

	return v2
}

func expectListenerJSON_v3(t *testing.T, snap *proxycfg.ConfigSnapshot, v, n uint64) *envoy_discovery_v3.DiscoveryResponse {
	resourceMap := map[string]proto.Message{
		"public_listener": &envoy_listener_v3.Listener{
			Name:             "public_listener:0.0.0.0:9999",
			Address:          makeAddress("0.0.0.0", 9999),
			TrafficDirection: envoy_core_v3.TrafficDirection_INBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					TransportSocket: xdsNewPublicTransportSocket(t, snap),
					Filters: []*envoy_listener_v3.Filter{
						mustMakeFilter(t, "envoy.filters.network.rbac", &envoy_network_rbac_v3.RBAC{
							Rules:      &envoy_rbac_v3.RBAC{},
							StatPrefix: "connect_authz",
						}),
						mustMakeFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "local_app",
							},
							StatPrefix: "public_listener",
						}),
					},
				},
			},
		},
		"db": &envoy_listener_v3.Listener{
			Name:             "db:127.0.0.1:9191",
			Address:          makeAddress("127.0.0.1", 9191),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						mustMakeFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
							},
							StatPrefix: "upstream.db.default.dc1",
						}),
					},
				},
			},
		},
		"prepared_query:geo-cache": &envoy_listener_v3.Listener{
			Name:             "prepared_query:geo-cache:127.10.10.10:8181",
			Address:          makeAddress("127.10.10.10", 8181),
			TrafficDirection: envoy_core_v3.TrafficDirection_OUTBOUND,
			FilterChains: []*envoy_listener_v3.FilterChain{
				{
					Filters: []*envoy_listener_v3.Filter{
						mustMakeFilter(t, "envoy.filters.network.tcp_proxy", &envoy_tcp_proxy_v3.TcpProxy{
							ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
								Cluster: "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
							},
							StatPrefix: "upstream.prepared_query_geo-cache",
						}),
					},
				},
			},
		},
	}

	resp := &envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(v),
		TypeUrl:     ListenerType,
		Nonce:       hexString(n),
	}

	// Sort resources into specific order because that matters in JSONEq
	// comparison later.
	keyOrder := []string{"public_listener"}
	for _, u := range snap.Proxy.Upstreams {
		keyOrder = append(keyOrder, u.Identifier())
	}
	for _, k := range keyOrder {
		res, ok := resourceMap[k]
		if !ok {
			continue
		}

		any, err := ptypes.MarshalAny(res)
		require.NoError(t, err)
		resp.Resources = append(resp.Resources, any)
	}

	return resp
}

func mustMakeFilter(t *testing.T, name string, cfg proto.Message) *envoy_listener_v3.Filter {
	f, err := makeFilter(name, cfg)
	require.NoError(t, err)
	return f
}

func expectClustersJSON_v2(t *testing.T, snap *proxycfg.ConfigSnapshot, v, n uint64) *envoy_api_v2.DiscoveryResponse {
	v3 := expectClustersJSON_v3(t, snap, v, n)

	v2, err := convertDiscoveryResponseToV2(v3)
	require.NoError(t, err)

	return v2
}

func expectClustersJSON_v3(t *testing.T, snap *proxycfg.ConfigSnapshot, v, n uint64) *envoy_discovery_v3.DiscoveryResponse {
	resourceMap := map[string]proto.Message{
		"local_app": &envoy_cluster_v3.Cluster{
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
		},
		"db": &envoy_cluster_v3.Cluster{
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
		},
		"prepared_query:geo-cache": &envoy_cluster_v3.Cluster{
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
		},
	}

	resp := &envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(v),
		TypeUrl:     ClusterType,
		Nonce:       hexString(n),
	}

	// Sort resources into specific order because that matters in JSONEq
	// comparison later.
	keyOrder := []string{"local_app"}
	for _, u := range snap.Proxy.Upstreams {
		keyOrder = append(keyOrder, u.Identifier())
	}
	for _, k := range keyOrder {
		res, ok := resourceMap[k]
		if !ok {
			continue
		}

		any, err := ptypes.MarshalAny(res)
		require.NoError(t, err)
		resp.Resources = append(resp.Resources, any)
	}

	return resp
}

func xdsNewPublicTransportSocket(
	t *testing.T,
	snap *proxycfg.ConfigSnapshot,
) *envoy_core_v3.TransportSocket {
	return xdsNewTransportSocket(t, snap, true, true, "")
}

func xdsNewUpstreamTransportSocket(
	t *testing.T,
	snap *proxycfg.ConfigSnapshot,
	sni string,
) *envoy_core_v3.TransportSocket {
	return xdsNewTransportSocket(t, snap, false, false, sni)
}

func xdsNewTransportSocket(
	t *testing.T,
	snap *proxycfg.ConfigSnapshot,
	downstream bool,
	requireClientCert bool,
	sni string,
) *envoy_core_v3.TransportSocket {
	// Assume just one root for now, can get fancier later if needed.
	caPEM := snap.Roots.Roots[0].RootCert

	commonTlsContext := &envoy_tls_v3.CommonTlsContext{
		TlsParams: &envoy_tls_v3.TlsParameters{},
		TlsCertificates: []*envoy_tls_v3.TlsCertificate{{
			CertificateChain: xdsNewInlineString(snap.Leaf().CertPEM),
			PrivateKey:       xdsNewInlineString(snap.Leaf().PrivateKeyPEM),
		}},
		ValidationContextType: &envoy_tls_v3.CommonTlsContext_ValidationContext{
			ValidationContext: &envoy_tls_v3.CertificateValidationContext{
				TrustedCa: xdsNewInlineString(caPEM),
			},
		},
	}

	var tlsContext proto.Message
	if downstream {
		var requireClientCertPB *wrappers.BoolValue
		if requireClientCert {
			requireClientCertPB = makeBoolValue(true)
		}

		tlsContext = &envoy_tls_v3.DownstreamTlsContext{
			CommonTlsContext:         commonTlsContext,
			RequireClientCertificate: requireClientCertPB,
		}
	} else {
		tlsContext = &envoy_tls_v3.UpstreamTlsContext{
			CommonTlsContext: commonTlsContext,
			Sni:              sni,
		}
	}

	any, err := ptypes.MarshalAny(tlsContext)
	require.NoError(t, err)

	return &envoy_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_core_v3.TransportSocket_TypedConfig{
			TypedConfig: any,
		},
	}
}

func xdsNewInlineString(s string) *envoy_core_v3.DataSource {
	return &envoy_core_v3.DataSource{
		Specifier: &envoy_core_v3.DataSource_InlineString{
			InlineString: s,
		},
	}
}

func xdsNewEndpoint(ip string, port int) *envoy_endpoint_v3.LbEndpoint {
	return &envoy_endpoint_v3.LbEndpoint{
		HostIdentifier: &envoy_endpoint_v3.LbEndpoint_Endpoint{
			Endpoint: &envoy_endpoint_v3.Endpoint{
				Address: makeAddress(ip, port),
			},
		},
	}
}

func xdsNewEndpointWithHealth(ip string, port int, health envoy_core_v3.HealthStatus, weight int) *envoy_endpoint_v3.LbEndpoint {
	ep := xdsNewEndpoint(ip, port)
	ep.HealthStatus = health
	ep.LoadBalancingWeight = makeUint32Value(weight)
	return ep
}

func xdsNewADSConfig() *envoy_core_v3.ConfigSource {
	return &envoy_core_v3.ConfigSource{
		ResourceApiVersion: envoy_core_v3.ApiVersion_V3,
		ConfigSourceSpecifier: &envoy_core_v3.ConfigSource_Ads{
			Ads: &envoy_core_v3.AggregatedConfigSource{},
		},
	}
}

func expectEndpointsJSON_v2(t *testing.T, v, n uint64) *envoy_api_v2.DiscoveryResponse {
	v3 := expectEndpointsJSON_v3(t, v, n)

	v2, err := convertDiscoveryResponseToV2(v3)
	require.NoError(t, err)

	return v2
}

func expectEndpointsJSON_v3(t *testing.T, v, n uint64) *envoy_discovery_v3.DiscoveryResponse {
	resources := []*envoy_endpoint_v3.ClusterLoadAssignment{
		{
			ClusterName: "db.default.dc1.internal.11111111-2222-3333-4444-555555555555.consul",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpointWithHealth("10.10.1.1", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
						xdsNewEndpointWithHealth("10.10.1.2", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
					},
				},
			},
		},

		{
			ClusterName: "geo-cache.default.dc1.query.11111111-2222-3333-4444-555555555555.consul",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						xdsNewEndpointWithHealth("10.10.1.1", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
						xdsNewEndpointWithHealth("10.10.1.2", 8080, envoy_core_v3.HealthStatus_HEALTHY, 1),
					},
				},
			},
		},
	}

	resp := &envoy_discovery_v3.DiscoveryResponse{
		VersionInfo: hexString(v),
		TypeUrl:     EndpointType,
		Nonce:       hexString(n),
	}
	for _, res := range resources {
		any, err := ptypes.MarshalAny(res)
		require.NoError(t, err)
		resp.Resources = append(resp.Resources, any)
	}

	return resp
}

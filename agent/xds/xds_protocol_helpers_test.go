package xds

import (
	"sort"
	"sync"
	"testing"
	"time"

	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/sdk/testutil"
)

// NOTE: this file is a collection of test helper functions for testing xDS
// protocols.

func newTestSnapshot(
	t *testing.T,
	prevSnap *proxycfg.ConfigSnapshot,
	dbServiceProtocol string,
	additionalEntries ...structs.ConfigEntry,
) *proxycfg.ConfigSnapshot {
	snap := proxycfg.TestConfigSnapshotDiscoveryChainDefaultWithEntries(t, additionalEntries...)
	snap.ConnectProxy.PreparedQueryEndpoints = map[string]structs.CheckServiceNodes{
		"prepared_query:geo-cache": proxycfg.TestUpstreamNodes(t),
	}
	if prevSnap != nil {
		snap.Roots = prevSnap.Roots
		snap.ConnectProxy.Leaf = prevSnap.ConnectProxy.Leaf
	}
	if dbServiceProtocol != "" {
		// Simulate ServiceManager injection of protocol
		snap.Proxy.Upstreams[0].Config["protocol"] = dbServiceProtocol
	}
	return snap
}

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

func makeTestResources_v2(t *testing.T, resources ...proto.Message) []*any.Any {
	var ret []*any.Any
	for _, res := range resources {
		any, err := ptypes.MarshalAny(res)
		require.NoError(t, err)
		ret = append(ret, any)
	}
	return ret
}

func makeTestResources(t *testing.T, resources ...proto.Message) []*envoy_discovery_v3.Resource {
	var ret []*envoy_discovery_v3.Resource
	for _, res := range resources {
		ret = append(ret, makeTestResource(t, res))
	}
	return ret
}

func makeTestResource(t *testing.T, res proto.Message) *envoy_discovery_v3.Resource {
	v, err := hashResource(res)
	require.NoError(t, err)

	any, err := ptypes.MarshalAny(res)
	require.NoError(t, err)

	return &envoy_discovery_v3.Resource{
		Name:     getResourceName(res),
		Version:  v,
		Resource: any,
	}
}

func protoToSortedJSON(t *testing.T, pb proto.Message) string {
	dup, err := copystructure.Copy(pb)
	require.NoError(t, err)
	pb = dup.(proto.Message)

	switch x := pb.(type) {
	case *envoy_discovery_v3.DeltaDiscoveryResponse:
		sort.Slice(x.Resources, func(i, j int) bool {
			return x.Resources[i].Name < x.Resources[j].Name
		})
		sort.Strings(x.RemovedResources)
	}

	return protoToJSON(t, pb)
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

func xdsNewFilter(t *testing.T, name string, cfg proto.Message) *envoy_listener_v3.Filter {
	f, err := makeFilter(name, cfg)
	require.NoError(t, err)
	return f
}

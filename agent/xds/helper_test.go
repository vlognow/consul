package xds

import (
	"sort"
	"testing"

	envoy_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/require"
)

// A collection of test helper functions.

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

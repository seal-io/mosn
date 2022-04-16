package sbomgen

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"mosn.io/api"
	v2 "mosn.io/mosn/pkg/config/v2"
)

func ConvertAnyToFilterRouteConfig(in *anypb.Any) (*FilterRouteConfig, error) {
	if in == nil {
		return nil, nil
	}
	var cs structpb.Struct
	err := anypb.UnmarshalTo(in, &cs, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	b, err := cs.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var c FilterRouteConfig
	if err = json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

type FilterRouteConfig struct {
	Headers map[string]string `json:"headers"`
}

func GetFilterRouteConfig(route api.Route) *FilterRouteConfig {
	if route == nil {
		return nil
	}
	var m = route.RouteRule().PerFilterConfig()
	if m == nil {
		return nil
	}
	var v, ok = m[v2.SBOMGenerator]
	if !ok {
		return nil
	}
	return v.(*FilterRouteConfig)
}

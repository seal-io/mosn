package sca

import (
	"context"

	jsoniter "github.com/json-iterator/go"
	"mosn.io/api"

	v2 "mosn.io/mosn/pkg/config/v2"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func init() {
	api.RegisterStream(v2.HTTP_SCA, CreateFilterChainFactory)
}

func CreateFilterChainFactory(config map[string]interface{}) (api.StreamFilterChainFactory, error) {
	var cfg, err = ConvertMapToGlobalConfig(config)
	if err != nil {
		return nil, err
	}

	return factory{
		config: cfg,
	}, nil
}

type factory struct {
	config *ResourceGlobalConfig
}

func (x factory) CreateFilterChain(ctx context.Context, callbacks api.StreamFilterChainFactoryCallbacks) {
	// pulling
	var ingressFilter = NewIngressBridge(ctx, x.config)
	callbacks.AddStreamReceiverFilter(ingressFilter, api.AfterChooseHost)
	callbacks.AddStreamSenderFilter(ingressFilter, api.BeforeSend)

	if !x.config.GetPushEnabled() {
		return
	}
	// pushing
	var egressFilter = NewEgressBridge(ctx, x.config)
	callbacks.AddStreamReceiverFilter(egressFilter, api.AfterChooseHost)
	callbacks.AddStreamSenderFilter(egressFilter, api.BeforeSend)
}

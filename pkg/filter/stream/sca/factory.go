package sca

import (
	"context"

	"github.com/eko/gocache/v2/cache"
	"github.com/eko/gocache/v2/store"
	jsoniter "github.com/json-iterator/go"
	gocache "github.com/patrickmn/go-cache"
	"mosn.io/api"
	v2 "mosn.io/mosn/pkg/config/v2"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func init() {
	api.RegisterStream(v2.SCA, CreateFilterChainFactory)
}

func CreateFilterChainFactory(config map[string]interface{}) (api.StreamFilterChainFactory, error) {
	var cfg, err = ConvertMapToGlobalConfig(config)
	if err != nil {
		return nil, err
	}
	var cacher = cache.New(store.NewGoCache(gocache.New(gocache.NoExpiration, 0), nil))
	return factory{
		config: cfg,
		cacher: cacher,
	}, nil
}

type factory struct {
	config *ResourceGlobalConfig
	cacher cache.CacheInterface
}

func (x factory) CreateFilterChain(ctx context.Context, callbacks api.StreamFilterChainFactoryCallbacks) {
	// pulling
	var ingressFilter = NewIngressBridge(x.config, x.cacher)
	callbacks.AddStreamReceiverFilter(ingressFilter, api.AfterChooseHost)
	callbacks.AddStreamSenderFilter(ingressFilter, api.BeforeSend)

	if !x.config.GetPushEnabled() {
		return
	}
	// pushing
	var egressFilter = NewEgressBridge(x.config, x.cacher)
	callbacks.AddStreamReceiverFilter(egressFilter, api.AfterChooseHost)
	callbacks.AddStreamSenderFilter(egressFilter, api.BeforeSend)
}

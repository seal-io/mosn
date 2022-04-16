package sbomgen

import (
	"context"

	"mosn.io/api"
	v2 "mosn.io/mosn/pkg/config/v2"
)

func init() {
	api.RegisterStream(v2.SBOMGenerator, CreateFilterChainFactory)
}

func CreateFilterChainFactory(config map[string]interface{}) (api.StreamFilterChainFactory, error) {
	return &factory{
		config: ConfigFromMap(config),
	}, nil
}

type factory struct {
	config FilterConfig
}

type StreamDualFilter interface {
	api.StreamSenderFilter
	api.StreamReceiverFilter
}

func (f *factory) CreateFilterChain(ctx context.Context, callbacks api.StreamFilterChainFactoryCallbacks) {
	if f == nil {
		return
	}

	var filter StreamDualFilter
	switch f.config.Kind {
	default:
		return
	case "package":
		filter = NewPackageGenerator(&f.config)
	case "image":
		filter = NewImageGenerator(&f.config)
	}
	callbacks.AddStreamReceiverFilter(filter, api.AfterChooseHost)
	callbacks.AddStreamSenderFilter(filter, api.BeforeSend)
}

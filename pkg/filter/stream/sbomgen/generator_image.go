package sbomgen

import (
	"context"

	"mosn.io/api"
	"mosn.io/mosn/pkg/variable"
)

func NewImageGenerator(cfg *FilterConfig) StreamDualFilter {
	return &imageGenerator{
		name:              cfg.Name,
		validator:         cfg.Validator,
		receiverSelectors: cfg.ReceiverSelectors,
		senderSelectors:   cfg.SenderSelectors,
	}
}

type imageGenerator struct {
	// initialize settings
	name              string
	validator         FilterConfigValidator
	receiverSelectors FilterConfigSelectors
	senderSelectors   FilterConfigSelectors

	// callback settings
	receiverHandler api.StreamReceiverFilterHandler
	senderHandler   api.StreamSenderFilterHandler
}

// tryLock locks only one direction.
func (g *imageGenerator) tryLock(ctx context.Context) bool {
	var key = "x-mosn-filter-image-sbomgen-" + g.name
	var _, err = variable.GetString(ctx, key)
	if err != nil {
		_ = variable.SetString(ctx, key, "processed")
		return true
	}
	return false
}

func (g *imageGenerator) process(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) ([]byte, error) {
	return nil, nil
}

func (g *imageGenerator) OnDestroy() {}

// Append processes pulling images.
func (g *imageGenerator) Append(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	var cfg = GetFilterRouteConfig(g.senderHandler.Route())
	if cfg != nil {
		for k, v := range cfg.Headers {
			headers.Set(k, v)
		}
	}
	if !g.senderSelectors.MatchAll(ctx, headers) {
		return api.StreamFilterContinue
	}

	if !g.tryLock(ctx) {
		return api.StreamFilterContinue
	}

	return api.StreamFilterContinue
}

func (g *imageGenerator) SetSenderFilterHandler(handler api.StreamSenderFilterHandler) {
	g.senderHandler = handler
}

// OnReceive processes pushing images.
func (g *imageGenerator) OnReceive(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	var cfg = GetFilterRouteConfig(g.receiverHandler.Route())
	if cfg != nil {
		for k, v := range cfg.Headers {
			headers.Set(k, v)
		}
	}
	if !g.receiverSelectors.MatchAll(ctx, headers) {
		return api.StreamFilterContinue
	}

	if !g.tryLock(ctx) {
		return api.StreamFilterContinue
	}

	return api.StreamFilterContinue
}

func (g *imageGenerator) SetReceiveFilterHandler(handler api.StreamReceiverFilterHandler) {
	g.receiverHandler = handler
}

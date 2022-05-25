package sca

import (
	"context"

	"mosn.io/api"

	"mosn.io/mosn/pkg/log"
)

func NewEgressBridge(globalCtx context.Context, globalConfig *GlobalConfig) StreamDualFilter {
	return &egressBridge{
		globalCtx:    globalCtx,
		globalConfig: globalConfig,
	}
}

type egressBridge struct {
	bridge

	globalCtx    context.Context
	globalConfig *GlobalConfig
}

func (x *egressBridge) OnReceive(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	var cfg = ExtractConfigFromRouteConfig(x.receiveHandler.Route())
	if cfg == nil {
		log.Proxy.Debugf(ctx, "ignore as config not found")
		return api.StreamFilterContinue
	}

	var egress EgressPort
	switch cfg.GetType() {
	default:
		return api.StreamFilterContinue
	case EgressTypeMaven:
		egress = NewMavenEgress(x.globalConfig.GetEvaluator(), cfg.GetEvaluatorExtraArgs(), x.receiveHandler.Route())
	}

	// try to get sample to confirm next step.
	var found, err = egress.GetDescriptor(ctx, headers, buf, trailers)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting descriptor: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}
	if !found {
		// short-circuit if sample not found.
		return api.StreamFilterContinue
	}

	// dig out with the sbom, which can take from cache or directly generate by buffering bytes.
	err = egress.GetBillOfMaterials(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	// ask evaluator via the above found sbom.
	err = egress.ValidateBillOfMaterials(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error validating sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	log.Proxy.Infof(ctx, "validated sbom")
	return api.StreamFilterContinue
}

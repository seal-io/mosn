package sca

import (
	"context"
	"errors"

	"mosn.io/api"

	"mosn.io/mosn/pkg/log"
)

func NewIngressBridge(globalCtx context.Context, globalConfig *ResourceGlobalConfig) StreamDualFilter {
	return &ingressBridge{
		globalCtx:    globalCtx,
		globalConfig: globalConfig,
	}
}

type ingressBridge struct {
	bridge

	globalCtx    context.Context
	globalConfig *ResourceGlobalConfig
}

func (x *ingressBridge) Append(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	var cfg = ExtractConfigFromRouteConfig(x.receiveHandler.Route())
	if cfg == nil {
		log.Proxy.Debugf(ctx, "ignore as config not found")
		return api.StreamFilterContinue
	}

	var ingress IngressPort
	switch cfg.GetType() {
	default:
		return api.StreamFilterContinue
	case IngressTypeMaven:
		ingress = NewMavenIngress(x.globalConfig.GetEvaluator(), cfg.GetEvaluatorExtraArgs(), x.receiveHandler.Route())
	case IngressTypeDocker:
		ingress = NewDockerIngress(x.globalConfig.GetEvaluator(), cfg.GetEvaluatorExtraArgs(), x.receiveHandler.Route())
	}

	// try to get sample to confirm next step.
	var found, err = ingress.GetDescriptor(ctx, headers, buf, trailers)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sample: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}
	if !found {
		// short-circuit if sample not found.
		return api.StreamFilterContinue
	}

	// use the found sample to validate some explicit threats.
	err = ingress.ValidateBillOfMaterials(ctx)
	if err != nil {
		if !errors.Is(err, evaluateIncompleteError) {
			log.Proxy.Errorf(ctx, "error validating metadata: %v", err)
			x.SendHijackReplyError(err)
			return api.StreamFilterStop
		}
		// there is not cache for this checksum,
		// so it needs sbom to validate again.
	} else {
		log.Proxy.Infof(ctx, "validated")
		return api.StreamFilterContinue
	}

	// if there are no explicit threats, then dig out with the sbom,
	// which can take from cache or directly ask from upstream.
	err = ingress.GetBillOfMaterials(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	// ask evaluator via the above found sbom.
	err = ingress.ValidateBillOfMaterials(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error validating sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	log.Proxy.Infof(ctx, "validated sbom")
	return api.StreamFilterContinue
}

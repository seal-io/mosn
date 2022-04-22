package sca

import (
	"context"

	"github.com/eko/gocache/v2/cache"
	"mosn.io/api"
	"mosn.io/mosn/pkg/log"
)

func NewIngressBridge(globalConfig *ResourceGlobalConfig, globalCacher cache.CacheInterface) StreamDualFilter {
	return &ingressBridge{
		globalConfig: globalConfig,
		globalCacher: globalCacher,
	}
}

type ingressBridge struct {
	bridge

	globalConfig *ResourceGlobalConfig
	globalCacher cache.CacheInterface
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
	var found, err = ingress.GetSample(ctx, headers, buf, trailers, x.globalCacher)
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
	err = ingress.ValidateSample(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error validating metadata: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	// if there are no explicit threats, then dig out with the sbom,
	// which can take from cache or directly ask from upstream.
	var cacher cache.CacheInterface
	if policy := cfg.GetSbomGeneratePolicy(); policy == SBOMGeneratePolicyGenIfNotFound {
		cacher = x.globalCacher
	} else if policy == "" {
		if globalPolicy := x.globalConfig.GetSbomGeneratePolicy(); globalPolicy == SBOMGeneratePolicyGenIfNotFound {
			cacher = x.globalCacher
		}
	}
	err = ingress.GetBillOfMaterials(ctx, cacher)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	// ask evaluator via the above found sbom.
	err = ingress.Validate(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error validating sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	return api.StreamFilterContinue
}

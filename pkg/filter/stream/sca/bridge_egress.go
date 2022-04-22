package sca

import (
	"context"

	"github.com/eko/gocache/v2/cache"
	"mosn.io/api"
	"mosn.io/mosn/pkg/log"
)

func NewEgressBridge(globalConfig *ResourceGlobalConfig, globalCacher cache.CacheInterface) StreamDualFilter {
	return &egressBridge{
		globalConfig: globalConfig,
		globalCacher: globalCacher,
	}
}

type egressBridge struct {
	bridge

	globalConfig *ResourceGlobalConfig
	globalCacher cache.CacheInterface
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
	var found, err = egress.GetSample(ctx, headers, buf, trailers, x.globalCacher)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sample: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}
	if !found {
		// short-circuit if sample not found.
		return api.StreamFilterContinue
	}

	// dig out with the sbom, which can take from cache or directly generate by buffering bytes.
	var cacher cache.CacheInterface
	if cfg.GetSbomGeneratePolicy() == "" {
		if x.globalConfig.GetSbomGeneratePolicy() == SBOMGeneratePolicyGenIfNotFound {
			cacher = x.globalCacher
		}
	} else if cfg.GetSbomGeneratePolicy() == SBOMGeneratePolicyGenIfNotFound {
		cacher = x.globalCacher
	}
	err = egress.GetBillOfMaterials(ctx, cacher)
	if err != nil {
		log.Proxy.Errorf(ctx, "error getting sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	// ask evaluator via the above found sbom.
	err = egress.Validate(ctx)
	if err != nil {
		log.Proxy.Errorf(ctx, "error validating sbom: %v", err)
		x.SendHijackReplyError(err)
		return api.StreamFilterStop
	}

	return api.StreamFilterContinue
}

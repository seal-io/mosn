package sbomgen

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"mosn.io/api"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
)

func NewPackageGenerator(cfg *FilterConfig) StreamDualFilter {
	return &packageGenerator{
		name:              cfg.Name,
		validator:         cfg.Validator,
		receiverSelectors: cfg.ReceiverSelectors,
		senderSelectors:   cfg.SenderSelectors,
	}
}

type packageGenerator struct {
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
func (g *packageGenerator) tryLock(ctx context.Context) bool {
	var key = "x-mosn-filter-package-sbomgen-" + g.name
	var _, err = variable.GetString(ctx, key)
	if err != nil {
		_ = variable.SetString(ctx, key, "processed")
		return true
	}
	return false
}

func (g *packageGenerator) genSBOM(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) ([]byte, error) {
	path, err := variable.GetString(ctx, types.VarPath)
	if err != nil {
		log.Proxy.Warnf(ctx, "error getting request path: %v", err)
		return nil, nil
	}
	src, err := source.NewFromFileBuffer(path, bytes.NewBuffer(buf.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("error creating source: %w", err)
	}
	packageCatalog, relationships, theDistro, err := syft.CatalogPackages(&src, cataloger.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("error scaning source: %w", err)
	}

	var bom = sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:    "mosn",
			Vendor:  "sealio",
			Version: "v1.0.0",
		},
	}
	bom.Relationships = relationships
	bom.Artifacts.PackageCatalog = packageCatalog
	bom.Artifacts.LinuxDistribution = theDistro
	bomEncoded, err := syft.Encode(bom, syft.FormatByName("cyclonedxjson"))
	if err != nil {
		return nil, fmt.Errorf("error converting scanned result in cyclonedx json: %w", err)
	}
	return bomEncoded, nil
}

func (g *packageGenerator) OnDestroy() {}

// Append processes pulling packages.
func (g *packageGenerator) Append(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
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

	var sbomBytes, err = g.genSBOM(ctx, headers, buf, trailers)
	if err != nil {
		log.Proxy.Errorf(ctx, "error processing on pulling package: %v", err)
		return api.StreamFilterStop
	}
	if len(sbomBytes) == 0 {
		log.Proxy.Infof(ctx, "ignored sbom validation on pulling package")
		return api.StreamFilterContinue
	}
	log.Proxy.Infof(ctx, "generated sbom on pulling package: %s", string(sbomBytes))

	err = g.validator.Validate(ctx, headers, "package_pull", sbomBytes)
	if err != nil {
		if errors.Is(err, errValidationEmptyEndpoint) {
			log.Proxy.Warnf(ctx, "skipped validating sbom on pulling package: %v", err)
			return api.StreamFilterContinue
		}
		var vbe *validationBlockError
		if !errors.As(err, &vbe) {
			log.Proxy.Warnf(ctx, "failed validating sbom on pulling package: %v", err)
			return api.StreamFilterContinue
		}
		g.receiverHandler.SendHijackReplyWithBody(403, headers, vbe.requestURL)
		log.Proxy.Errorf(ctx, "blocked pulling package after validated: %v", vbe.message)
		return api.StreamFilterStop
	}

	log.Proxy.Infof(ctx, "allowed pulling package after validated")
	return api.StreamFilterContinue
}

func (g *packageGenerator) SetSenderFilterHandler(handler api.StreamSenderFilterHandler) {
	g.senderHandler = handler
}

// OnReceive processes pushing packages.
func (g *packageGenerator) OnReceive(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
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

	var bs, err = g.genSBOM(ctx, headers, buf, trailers)
	if err != nil {
		log.Proxy.Errorf(ctx, "error processing on pushing package: %v", err)
		return api.StreamFilterStop
	}
	if len(bs) == 0 {
		log.Proxy.Infof(ctx, "ignored sbom validation on pushing package")
		return api.StreamFilterContinue
	}

	log.Proxy.Infof(ctx, "generated sbom on pushing package: %s", string(bs))
	err = g.validator.Validate(ctx, headers, "package_push", bs)
	if err != nil {
		if errors.Is(err, errValidationEmptyEndpoint) {
			log.Proxy.Warnf(ctx, "skipped validating sbom on pushing package: %v", err)
			return api.StreamFilterContinue
		}
		var vbe *validationBlockError
		if !errors.As(err, &vbe) {
			log.Proxy.Warnf(ctx, "failed validating sbom on pushing package: %v", err)
			return api.StreamFilterContinue
		}
		g.receiverHandler.SendHijackReplyWithBody(403, headers, vbe.requestURL)
		log.Proxy.Errorf(ctx, "blocked pushing package after validated: %v", vbe.message)
		return api.StreamFilterStop
	}

	log.Proxy.Infof(ctx, "allowed pushing package after validated")
	return api.StreamFilterContinue
}

func (g *packageGenerator) SetReceiveFilterHandler(handler api.StreamReceiverFilterHandler) {
	g.receiverHandler = handler
}

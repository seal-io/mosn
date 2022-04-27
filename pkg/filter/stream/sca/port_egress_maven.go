package sca

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/anchore/syft/syft/source"
	"github.com/eko/gocache/v2/cache"
	"mosn.io/api"
	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
)

const EgressTypeMaven = "maven"

func NewMavenEgress(evaluator *ResourceEvaluator, evaluatorExtraArgs map[string]string, route api.Route) EgressPort {
	return &mavenEgress{
		evaluator:          evaluator,
		evaluatorExtraArgs: evaluatorExtraArgs,
		route:              route,
	}
}

type mavenEgress struct {
	port

	// initialized
	evaluator          *ResourceEvaluator
	evaluatorExtraArgs map[string]string
	route              api.Route

	// fetched
	packageSample MavenEgressPackageSample
	packageSBOM   stdjson.RawMessage
}

type MavenEgressPackageSample struct {
	Path    string             `json:"path"`
	Content stdjson.RawMessage `json:"content"`
}

func (m *mavenEgress) GetSample(ctx context.Context, reqHeaders api.HeaderMap, reqBuf api.IoBuffer, _ api.HeaderMap, _ cache.CacheInterface) (bool, error) {
	// intercept method
	reqMethod, err := variable.GetString(ctx, types.VarMethod)
	if err != nil {
		return false, fmt.Errorf("error getting %s variable: %w", types.VarMethod, err)
	}
	switch reqMethod {
	default:
		return false, nil
	case http.MethodPut, http.MethodPost:
	}
	// intercept path
	reqPath, err := variable.GetString(ctx, types.VarPath)
	if err != nil {
		return false, fmt.Errorf("error getting %s variable: %w", types.VarPath, err)
	}
	switch filepath.Ext(reqPath) {
	default:
		return false, nil
	case ".jar", ".war", ".ear", ".par", ".sar", ".jpi", ".hpi", ".lpkg":
	}

	m.packageSample = MavenEgressPackageSample{
		Path:    reqPath,
		Content: reqBuf.Bytes(),
	}
	return true, nil
}

func (m *mavenEgress) GetBillOfMaterials(ctx context.Context, _ cache.CacheInterface) error {
	var src, err = source.NewFromFileBuffer(m.packageSample.Path, bytes.NewBuffer(m.packageSample.Content))
	if err != nil {
		return fmt.Errorf("error creating sbom scanning source: %w", err)
	}
	sbomBytes, err := m.GenerateSBOM(ctx, src)
	if err != nil {
		return fmt.Errorf("error generating sbom: %w", err)
	}
	if len(sbomBytes) == 0 {
		return errors.New("invalid sbom of pushing maven archive")
	}

	m.packageSBOM = sbomBytes
	log.Proxy.Infof(ctx, "[maven/package_push] sbom generated: \n%s", string(sbomBytes))
	return nil
}

func (m *mavenEgress) Validate(ctx context.Context) error {
	var headers, ok = mosnctx.Get(ctx, types.ContextKeyDownStreamHeaders).(api.HeaderMap)
	if !ok {
		return errors.New("cannot find downstream headers")
	}

	var input = map[string]interface{}{
		"eventType": "package_push",
		"sbom":      m.packageSBOM,
	}
	for k, v := range m.evaluatorExtraArgs {
		if _, exist := input[k]; !exist {
			input[k] = v
		}
	}
	return m.evaluator.Evaluate(ctx, headers, input)
}

func (m mavenEgress) EgressPort() {}

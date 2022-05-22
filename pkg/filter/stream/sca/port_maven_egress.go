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
	packageDescriptor mavenPackageDescriptor
	packageSBOM       stdjson.RawMessage
}

func (m *mavenEgress) GetDescriptor(ctx context.Context, reqHeaders api.HeaderMap, reqBuf api.IoBuffer, reqTrailers api.HeaderMap) (bool, error) {
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

	m.packageDescriptor = mavenPackageDescriptor{
		Path:    reqPath,
		RawData: reqBuf.Bytes(),
	}
	return true, nil
}

func (m *mavenEgress) GetBillOfMaterials(ctx context.Context) error {
	var sbomBytes []byte

	// otherwise, generate from the downloaded blobs.
	src, err := source.NewFromFileBuffer(m.packageDescriptor.Path, bytes.NewBuffer(m.packageDescriptor.RawData))
	if err != nil {
		return fmt.Errorf("error creating sbom scanning source: %w", err)
	}
	sbomBytes, err = m.GenerateSBOM(ctx, src)
	if err != nil {
		return fmt.Errorf("error generating sbom: %w", err)
	}
	if len(sbomBytes) == 0 {
		return errors.New("invalid sbom of pushing maven archive")
	}
	m.packageSBOM = sbomBytes
	if log.Proxy.GetLogLevel() >= log.DEBUG {
		log.Proxy.Debugf(ctx, "maven egress sbom generated: %s", string(sbomBytes))
	}
	return nil
}

func (m *mavenEgress) ValidateBillOfMaterials(ctx context.Context) error {
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

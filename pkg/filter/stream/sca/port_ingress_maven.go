package sca

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	stdhttp "net/http"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/source"
	"github.com/eko/gocache/v2/cache"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
	"mosn.io/api"
	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
	"mosn.io/pkg/buffer"
)

const IngressTypeMaven = "maven"

func NewMavenIngress(evaluator *ResourceEvaluator, evaluatorExtraArgs map[string]string, route api.Route) IngressPort {
	return &mavenIngress{
		evaluator:          evaluator,
		evaluatorExtraArgs: evaluatorExtraArgs,
		route:              route,
		checksumAlgorithm:  "sha1",
	}
}

type mavenIngress struct {
	port

	// initialized
	evaluator          *ResourceEvaluator
	evaluatorExtraArgs map[string]string
	route              api.Route
	checksumAlgorithm  string

	// fetched
	packageSample MavenIngressPackageSample
	packageSBOM   stdjson.RawMessage
}

type MavenIngressPackageSample struct {
	Checksum    string `json:"checksum"`
	Packaging   string `json:"packaging"`
	Path        string `json:"path"`
	GroupID     string `json:"groupId"`
	ArtifactID  string `json:"artifactId"`
	Version     string `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

func (m *mavenIngress) GetSample(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, _ api.HeaderMap, _ cache.CacheInterface) (bool, error) {
	// intercept content-type
	var respContentType, _ = respHeaders.Get("Content-Type")
	switch respContentType {
	default:
		return false, nil
	case "text/xml", "application/xml":
	}
	// intercept method
	reqMethod, err := variable.GetString(ctx, types.VarMethod)
	if err != nil {
		return false, fmt.Errorf("error getting %s variable: %w", types.VarMethod, err)
	}
	if reqMethod != stdhttp.MethodGet {
		return false, nil
	}
	// intercept path
	reqPath, err := variable.GetString(ctx, types.VarPath)
	if err != nil {
		return false, fmt.Errorf("error getting %s variable: %w", types.VarPath, err)
	}
	if filepath.Ext(reqPath) != ".pom" {
		return false, nil
	}

	// parse response
	var proj gopom.Project
	var dec = xml.NewDecoder(bytes.NewBuffer(respBuf.Bytes()))
	dec.CharsetReader = charset.NewReaderLabel
	if err = dec.Decode(&proj); err != nil {
		return false, fmt.Errorf("error decoding proj pom: %w", err)
	}
	var packaging = func() string {
		if proj.Packaging == "" {
			return "jar"
		}
		return proj.Packaging
	}()
	if packaging == "pom" { // nothing to do if vendor parent project
		return false, nil
	}
	var path = strings.TrimSuffix(reqPath, ".pom") + "." + packaging

	// get sha1 checksum
	var checksum []byte
	var checksumCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
	err = variable.SetString(checksumCtx, types.VarPath, path+"."+m.checksumAlgorithm)
	if err != nil {
		return false, fmt.Errorf("error setting checksum forward path: %w", err)
	}
	var checksumReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
		var contentType, _ = respHeaders.Get("Content-Type")
		if contentType != "text/plain" {
			return nil
		}
		checksum = respData.Bytes()
		return nil
	}
	var checksumForwardErr = m.Forward(checksumCtx, m.route.RouteRule().ClusterName(ctx), checksumReceiver)
	if checksumForwardErr != nil {
		return false, checksumForwardErr
	}
	if len(checksum) == 0 {
		return false, errors.New("cannot get checksum")
	}

	m.packageSample = MavenIngressPackageSample{
		Checksum:    string(checksum),
		Packaging:   packaging,
		Path:        path,
		GroupID:     proj.GroupID,
		ArtifactID:  proj.ArtifactID,
		Version:     proj.Version,
		Name:        proj.Name,
		Description: proj.Description,
		URL:         proj.URL,
	}
	return true, nil
}

func (m *mavenIngress) ValidateSample(ctx context.Context) error {
	return nil
}

func (m *mavenIngress) GetBillOfMaterials(ctx context.Context, _ cache.CacheInterface) error {
	// get blobs
	var sbomBytes []byte
	var blobCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
	var err = variable.SetString(blobCtx, types.VarPath, m.packageSample.Path)
	if err != nil {
		return fmt.Errorf("error setting blob forward path: %w", err)
	}
	var blobReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
		if respCode != stdhttp.StatusOK {
			return nil
		}
		var contentType, _ = respHeaders.Get("Content-Type")
		switch contentType {
		default:
			return fmt.Errorf("invalid blob content type %s", contentType)
		case "application/java-archive", "application/jar":
		}
		if respData == nil {
			return nil
		}

		src, err := source.NewFromFileBuffer(m.packageSample.Path, bytes.NewBuffer(respData.Bytes()))
		if err != nil {
			return fmt.Errorf("error creating sbom scanning source: %w", err)
		}
		sbomBytes, err = m.GenerateSBOM(ctx, src)
		if err != nil {
			return fmt.Errorf("error generating sbom: %w", err)
		}
		return nil
	}
	var blobForwardErr = m.Forward(blobCtx, m.route.RouteRule().ClusterName(ctx), blobReceiver)
	if blobForwardErr != nil {
		return blobForwardErr
	}
	if len(sbomBytes) == 0 {
		return errors.New("cannot get sbom from archive")
	}

	m.packageSBOM = sbomBytes
	log.Proxy.Infof(ctx, "[maven/package_pull] sbom generated: \n%s", string(sbomBytes))
	return nil
}

func (m *mavenIngress) Validate(ctx context.Context) error {
	var headers, ok = mosnctx.Get(ctx, types.ContextKeyDownStreamHeaders).(api.HeaderMap)
	if !ok {
		return errors.New("cannot find downstream headers")
	}

	var input = map[string]interface{}{
		"eventType": "package_pull",
		"sbom":      m.packageSBOM,
	}
	for k, v := range m.evaluatorExtraArgs {
		if _, exist := input[k]; !exist {
			input[k] = v
		}
	}
	return m.evaluator.Evaluate(ctx, headers, input)
}

func (m mavenIngress) IngressPort() {}

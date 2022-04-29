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
	packageDescriptor MavenIngressPackageDescriptor
	packageSBOM       stdjson.RawMessage
}

type MavenIngressPackageDescriptor struct {
	Path              string `json:"path"`
	ChecksumAlgorithm string `json:"checksumAlgorithm"`
	Checksum          string `json:"checksum"`
	GroupID           string `json:"groupId"`
	ArtifactID        string `json:"artifactId"`
	Version           string `json:"version"`
	Packaging         string `json:"packaging"`
}

func (s MavenIngressPackageDescriptor) GetName() string {
	return s.GroupID + "/" + s.ArtifactID + "/" + s.Version
}

func (s MavenIngressPackageDescriptor) GetID() string {
	if len(s.Checksum) < 3 {
		return ""
	}
	return "/maven/" + s.ChecksumAlgorithm + "/" + s.Checksum[:2] + "/" + s.Checksum
}

func (m *mavenIngress) GetDescriptor(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap) (bool, error) {
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

	// get metadata
	var proj gopom.Project
	var dec = xml.NewDecoder(bytes.NewBuffer(respBuf.Bytes()))
	dec.CharsetReader = charset.NewReaderLabel
	if err = dec.Decode(&proj); err != nil {
		return false, fmt.Errorf("error decoding project pom: %w", err)
	}
	var packaging = func() string {
		if proj.Packaging == "" {
			return "jar"
		}
		return strings.ToLower(proj.Packaging)
	}()
	if packaging == "pom" { // nothing to do if vendor parent project
		return false, nil
	}
	var path = strings.TrimSuffix(reqPath, ".pom") + "." + packaging
	var groupID, artifactID, version = proj.GroupID, proj.ArtifactID, proj.Version

	// get checksum
	var checksum []byte
	var checksumCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
	err = variable.SetString(checksumCtx, types.VarPath, path+"."+m.checksumAlgorithm)
	if err != nil {
		return false, fmt.Errorf("error setting checksum forward path: %w", err)
	}
	var checksumReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
		if respCode != stdhttp.StatusOK {
			return nil
		}
		if respHeaders == nil {
			return nil
		}
		var contentType, _ = respHeaders.Get("Content-Type")
		if contentType != "text/plain" {
			return nil
		}
		if respData == nil {
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

	m.packageDescriptor = MavenIngressPackageDescriptor{
		Path:              path,
		ChecksumAlgorithm: m.checksumAlgorithm,
		Checksum:          string(checksum),
		GroupID:           groupID,
		ArtifactID:        artifactID,
		Version:           version,
		Packaging:         packaging,
	}
	return true, nil
}

func (m *mavenIngress) ValidateDescriptor(ctx context.Context) error {
	return nil
}

func (m *mavenIngress) GetBillOfMaterials(ctx context.Context) error {
	var sbomBytes []byte

	// generate from the downloaded blobs.
	type blobFetchedResponse struct {
		content []byte
	}
	var blobFetchedResult blobFetchedResponse
	var blobCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
	var err = variable.SetString(blobCtx, types.VarPath, m.packageDescriptor.Path)
	if err != nil {
		return fmt.Errorf("error setting blob forward path: %w", err)
	}
	var blobFetchingReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
		if respCode != stdhttp.StatusOK {
			return fmt.Errorf("unexpected response status: %d", respCode)
		}
		var contentType, _ = respHeaders.Get("Content-Type")
		switch contentType {
		default:
			return fmt.Errorf("invalid blob content type %s", contentType)
		case "application/java-archive", "application/jar":
		}
		if respData == nil || respData.Len() == 0 {
			return errors.New("empty response body")
		}
		blobFetchedResult.content = respData.Bytes()
		return nil
	}
	var blobFetchingErr = m.Forward(blobCtx, m.route.RouteRule().ClusterName(ctx), blobFetchingReceiver)
	if blobFetchingErr != nil {
		return blobFetchingErr
	}

	src, err := source.NewFromFileBuffer(m.packageDescriptor.Path, bytes.NewBuffer(blobFetchedResult.content))
	if err != nil {
		return fmt.Errorf("error creating sbom scanning source: %w", err)
	}
	sbomBytes, err = m.GenerateSBOM(ctx, src)
	if err != nil {
		return fmt.Errorf("error generating sbom: %w", err)
	}
	if len(sbomBytes) == 0 {
		return errors.New("invalid sbom of pulling maven archive")
	}
	m.packageSBOM = sbomBytes
	if log.Proxy.GetLogLevel() >= log.DEBUG {
		log.Proxy.Debugf(ctx, "maven ingress sbom generated: %s", string(sbomBytes))
	}

	return nil
}

func (m *mavenIngress) ValidateBillOfMaterials(ctx context.Context) error {
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

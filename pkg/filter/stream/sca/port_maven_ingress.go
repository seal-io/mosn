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
	"github.com/valyala/fasthttp"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
	"mosn.io/api"
	"mosn.io/pkg/buffer"

	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
)

const IngressTypeMaven = "maven"

func NewMavenIngress(evaluator *Evaluator, evaluatorExtraArgs map[string]string, route api.Route) IngressPort {
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
	evaluator          *Evaluator
	evaluatorExtraArgs map[string]string
	route              api.Route
	checksumAlgorithm  string

	// fetched
	packageDescriptor mavenPackageDescriptor
	packageSBOM       stdjson.RawMessage
}

func (m *mavenIngress) GetDescriptor(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap) (bool, error) {
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
	switch filepath.Ext(reqPath) {
	default:
	case ".jar":
		// protect from disabled re-resolve case as much as possible.
		reqPath = strings.TrimSuffix(reqPath, ".jar") + ".pom"
		err = cacher.GetObject(reqPath, &m.packageDescriptor)
		if err != nil {
			log.Proxy.Warnf(ctx, "error getting package descriptor from cache: %v", err)
			return false, nil
		}
		return true, nil
	case ".pom":
		err = cacher.GetObject(reqPath, &m.packageDescriptor)
		if err == nil {
			// reduce checksum gain request.
			return true, nil
		}
	}
	// intercept content-type
	var respContentType, _ = respHeaders.Get("Content-Type")
	switch respContentType {
	default:
		var respLocation, _ = respHeaders.Get("Location")
		if respLocation == "" {
			return false, nil
		}
		// upstream redirects the response to another place.
		err = redirect(ctx, respLocation, func(respRedirect *fasthttp.Response) error {
			respBuf = buffer.NewIoBufferBytes(respRedirect.Body())
			return nil
		})
		if err != nil {
			return false, fmt.Errorf("error redirecting %s: %w", respLocation, err)
		}
	case "text/xml", "application/xml":
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
	var checksum = make([]byte, 0)
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
		switch contentType {
		default:
			log.Proxy.Warnf(ctx, "get invalid checksum content-type %s", contentType)
		case "application/octet-stream", "text/plain":
		}
		if respData == nil {
			return nil
		}
		checksum = respData.Bytes()
		return nil
	}
	var checksumForwardErr = m.Forward(checksumCtx, m.route.RouteRule().ClusterName(ctx), checksumReceiver)
	if checksumForwardErr != nil {
		log.Proxy.Warnf(ctx, "error forwarding to get checksum: %v", checksumForwardErr)
	} else if len(checksum) == 0 {
		log.Proxy.Warnf(ctx, "empty checksum")
	}

	m.packageDescriptor = mavenPackageDescriptor{
		ChecksumAlgorithm: m.checksumAlgorithm,
		Checksum:          string(checksum),
		Path:              path,
		GroupID:           groupID,
		ArtifactID:        artifactID,
		Version:           version,
		Packaging:         packaging,
	}
	err = cacher.SetObject(reqPath, m.packageDescriptor)
	if err != nil {
		log.Proxy.Warnf(ctx, "error setting package descriptor into cache: %v", err)
	}
	return true, nil
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
			log.Proxy.Warnf(ctx, "get invalid blob content-type %s", contentType)
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
		"checksum":  m.packageDescriptor.GetChecksum(),
	}
	if len(m.packageSBOM) != 0 {
		input["sbom"] = m.packageSBOM
	}
	for k, v := range m.evaluatorExtraArgs {
		if _, exist := input[k]; !exist {
			input[k] = v
		}
	}
	return m.evaluator.Evaluate(ctx, headers, input)
}

func (m mavenIngress) IngressPort() {}

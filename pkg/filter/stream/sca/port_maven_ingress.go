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
	var reqPackageExtension = filepath.Ext(reqPath)
	if !mavenExtensionProcessedSet.Has(reqPackageExtension) {
		switch reqPackageExtension {
		default:
			return false, nil
		case ".pom":
			// NB(thxCode): optimization, reduce checksum gain request
			var cerr = cacher.GetObject(reqPath, &m.packageDescriptor)
			if cerr == nil {
				return true, nil
			}
		}
	} else {
		// protect from disabled re-resolve case as much as possible.
		var re HijackReplyError
		var pomReqPath = strings.TrimSuffix(reqPath, reqPackageExtension) + ".pom"
		var cerr = cacher.GetObject("validates:"+pomReqPath, &re)
		if cerr == nil {
			// NB(thxCode): return the previous pom validating result.
			return false, re
		}
		return false, nil
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
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	if err = dec.Decode(&proj); err != nil {
		log.Proxy.Warnf(ctx, "error decoding project pom: %v", err)
		// NB(thxCode): ignore error if failed decoding.
		return false, nil
	}
	if proj.GroupID == "" {
		proj.GroupID = proj.Parent.GroupID
	}
	if proj.Version == "" {
		proj.Version = proj.Parent.Version
	}
	var packaging = strings.ToLower(proj.Packaging)
	var extension = mavenPackagingExtensionMap[packaging]
	if extension == "" {
		// not found extension
		log.Proxy.Warnf(ctx, "ignored unrecorded extension for package %s/%s:%s(%q)",
			proj.GroupID, proj.ArtifactID, proj.Version, packaging)
		return false, nil
	}
	var path = strings.TrimSuffix(reqPath, ".pom") + extension
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
		log.Proxy.Warnf(ctx, "error caching package descriptor: %v", err)
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

	var input = &EvaluateInput{
		EventType: "package_pull",
		Checksum:  m.packageDescriptor.getChecksum(),
		ExtraArgs: m.evaluatorExtraArgs,
	}
	if len(m.packageSBOM) != 0 {
		input.SBOM = m.packageSBOM
	}
	var err = m.evaluator.Evaluate(ctx, headers, input)
	if err != nil {
		var re HijackReplyError
		if errors.As(err, &re) {
			var pomReqPath = m.packageDescriptor.Path
			var cerr = cacher.SetObject("validates:"+pomReqPath, re)
			if cerr != nil {
				log.Proxy.Warnf(ctx, "error caching package validation: %v", err)
			}
		}
	}
	return err
}

func (m mavenIngress) IngressPort() {}

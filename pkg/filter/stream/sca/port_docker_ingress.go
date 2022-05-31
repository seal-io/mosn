package sca

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"os"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	conreg "github.com/google/go-containerregistry/pkg/v1"
	conregempty "github.com/google/go-containerregistry/pkg/v1/empty"
	conregmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	conregstatic "github.com/google/go-containerregistry/pkg/v1/static"
	conregtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"mosn.io/api"
	"mosn.io/pkg/buffer"

	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
)

const IngressTypeDocker = "docker"

func NewDockerIngress(evaluator *Evaluator, evaluatorExtraArgs map[string]string, route api.Route) IngressPort {
	return &dockerIngress{
		evaluator:          evaluator,
		evaluatorExtraArgs: evaluatorExtraArgs,
		route:              route,
		checksumAlgorithm:  "sha256",
	}
}

type dockerIngress struct {
	port

	// initialized
	evaluator          *Evaluator
	evaluatorExtraArgs map[string]string
	route              api.Route
	checksumAlgorithm  string

	// fetched
	packageDescriptor dockerPackageDescriptor
	packageSBOM       stdjson.RawMessage
}

func (m *dockerIngress) GetDescriptor(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap) (bool, error) {
	var found, err = m.doGetDescriptor(ctx, respHeaders, respBuf, respTrailers)
	return found, dockerResponseErrorWrap(err)
}

func (m *dockerIngress) doGetDescriptor(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap) (bool, error) {
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
	var reqPaths = strings.Split(reqPath, "/")
	for i := 0; i < len(reqPaths); i++ {
		// we only support v2 apiversion currently.
		if reqPaths[i] == "v2" {
			reqPaths = reqPaths[i:]
			break
		}
	}
	if len(reqPaths) != 5 ||
		reqPaths[0] != "v2" ||
		reqPaths[3] != "manifests" ||
		!strings.HasPrefix(reqPaths[len(reqPaths)-1], m.checksumAlgorithm+":") {
		return false, nil
	}
	// intercept content-type
	var respContentType, _ = respHeaders.Get("Content-Type")
	switch respContentType {
	default:
		return false, nil
	case string(conregtypes.DockerManifestSchema2), string(conregtypes.OCIManifestSchema1):
	}

	// get metadata
	repository, err := variable.GetString(ctx, types.VarIstioHeaderHost)
	if err != nil {
		return false, fmt.Errorf("error getting repository: %w", err)
	}
	var namespace, name, tag = reqPaths[1], reqPaths[2], reqPaths[4]

	// get checksum
	var checksum = strings.TrimPrefix(reqPaths[4], m.checksumAlgorithm+":")

	m.packageDescriptor = dockerPackageDescriptor{
		ChecksumAlgorithm: m.checksumAlgorithm,
		Checksum:          checksum,
		Path:              reqPath,
		Repository:        repository,
		Namespace:         namespace,
		Name:              name,
		Tag:               tag,
		RawManifest:       respBuf.Bytes(),
	}
	return true, nil
}

func (m *dockerIngress) GetBillOfMaterials(ctx context.Context) error {
	return dockerResponseErrorWrap(m.doGetBillOfMaterials(ctx))
}

func (m *dockerIngress) doGetBillOfMaterials(ctx context.Context) error {
	var sbomBytes []byte

	// generate from the downloaded blobs.
	type blobFetchedResponse struct {
		order     int
		content   []byte
		mediaType conregtypes.MediaType
	}
	manifest, err := conreg.ParseManifest(bytes.NewBuffer(m.packageDescriptor.RawManifest))
	if err != nil {
		return fmt.Errorf("error parsing manifest format: %w", err)
	}
	var blobFetchedResults = make([]blobFetchedResponse, 0, len(manifest.Layers)+1)
	var descriptors = append(append(make([]conreg.Descriptor, 0, cap(blobFetchedResults)), manifest.Layers...), manifest.Config)
	for i := range descriptors {
		var blobOrder = i
		var blobURL = strings.Join([]string{"/v2", m.packageDescriptor.Namespace, m.packageDescriptor.Name, "blobs", descriptors[blobOrder].Digest.String()}, "/")
		log.Proxy.Debugf(ctx, "fetching blob from %s", blobURL)
		var blobCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
		var err = variable.SetString(blobCtx, types.VarPath, blobURL)
		if err != nil {
			return fmt.Errorf("error setting blob forward path: %w", err)
		}
		var blobContent bytes.Buffer
		var blobFetchingReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
			if respCode != stdhttp.StatusOK {
				return fmt.Errorf("unexpected response status: %d", respCode)
			}
			var contentType, _ = respHeaders.Get("Content-Type")
			switch contentType {
			default:
				log.Proxy.Warnf(ctx, "get invalid blob content type %s", contentType)
			case "application/octet-stream":
			}
			if respData == nil || respData.Len() == 0 {
				return errors.New("empty response body")
			}
			var _, err = io.Copy(&blobContent, respData)
			return err
		}
		var blobFetchingErr = m.Forward(blobCtx, m.route.RouteRule().ClusterName(ctx), blobFetchingReceiver)
		if blobFetchingErr != nil {
			return blobFetchingErr
		}
		log.Proxy.Infof(ctx, "fetched %d blob from %s", blobContent.Len(), blobURL)
		blobFetchedResults = append(blobFetchedResults, blobFetchedResponse{
			order:     blobOrder,
			content:   blobContent.Bytes(),
			mediaType: descriptors[blobOrder].MediaType,
		})
	}

	rawImage, err := conregmutate.AppendLayers(conregempty.Image)
	if err != nil {
		return fmt.Errorf("error appending image layer 0: %w", err)
	}
	for i := range blobFetchedResults {
		if i == len(blobFetchedResults)-1 {
			break
		}
		var result = blobFetchedResults[i]
		var layer, err = partial.CompressedToLayer(conregstatic.NewLayer(result.content, result.mediaType))
		if err != nil {
			return fmt.Errorf("error perparing compressed image layer %d: %w", i+1, err)
		}
		rawImage, err = conregmutate.AppendLayers(rawImage, layer)
		if err != nil {
			return fmt.Errorf("error appending image layer %d: %w", i+1, err)
		}
	}
	var img = image.NewImage(rawImage, os.TempDir(),
		image.WithConfig(blobFetchedResults[len(blobFetchedResults)-1].content),
		image.WithManifest(m.packageDescriptor.RawManifest))
	if err = img.Read(); err != nil {
		return fmt.Errorf("error reading image: %w", err)
	}
	src, err := source.NewFromImage(img, m.packageDescriptor.getName())
	if err != nil {
		return fmt.Errorf("error creating sbom scanning source: %w", err)
	}
	sbomBytes, err = m.GenerateSBOM(ctx, src)
	if err != nil {
		return fmt.Errorf("error generating sbom: %w", err)
	}
	if len(sbomBytes) == 0 {
		return errors.New("invalid sbom of pulling docker image")
	}
	m.packageSBOM = sbomBytes
	if log.Proxy.GetLogLevel() >= log.DEBUG {
		log.Proxy.Debugf(ctx, "docker ingress sbom generated: %s", string(sbomBytes))
	}

	return nil
}

func (m *dockerIngress) ValidateBillOfMaterials(ctx context.Context) error {
	var err = m.doValidateBillOfMaterials(ctx)
	if err != nil {
		if IsEvaluateIncompleteError(err) {
			return err
		}
	}
	return dockerResponseErrorWrap(err)
}

func (m *dockerIngress) doValidateBillOfMaterials(ctx context.Context) error {
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

	return m.evaluator.Evaluate(ctx, headers, input)
}

func (m dockerIngress) IngressPort() {}

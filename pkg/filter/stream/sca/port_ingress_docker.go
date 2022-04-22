package sca

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"os"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/eko/gocache/v2/cache"
	conreg "github.com/google/go-containerregistry/pkg/v1"
	conregempty "github.com/google/go-containerregistry/pkg/v1/empty"
	conregmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	conregstatic "github.com/google/go-containerregistry/pkg/v1/static"
	conregtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"mosn.io/api"
	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/variable"
	"mosn.io/pkg/buffer"
)

const IngressTypeDocker = "docker"

func NewDockerIngress(evaluator *ResourceEvaluator, evaluatorExtraArgs map[string]string, route api.Route) IngressPort {
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
	evaluator          *ResourceEvaluator
	evaluatorExtraArgs map[string]string
	route              api.Route
	checksumAlgorithm  string

	// fetched
	packageSample DockerIngressPackageSample
	packageSBOM   stdjson.RawMessage
}

type DockerIngressPackageSample struct {
	Path              string             `json:"path"`
	Repository        string             `json:"repository"`
	Namespace         string             `json:"namespace"`
	Name              string             `json:"name"`
	Tag               string             `json:"tag"`
	ManifestMediaType string             `json:"manifestMediaType"`
	Manifest          stdjson.RawMessage `json:"manifest"`
}

func (s DockerIngressPackageSample) ImageName() string {
	var sb strings.Builder
	if s.Repository != "registry-1.docker.io" && s.Repository != "docker.io" {
		sb.WriteString(s.Repository)
		sb.WriteString("/")
	}
	if s.Namespace == "library" && sb.Len() != 0 ||
		s.Namespace != "library" {
		sb.WriteString(s.Namespace)
		sb.WriteString("/")
	}
	sb.WriteString(s.Name)
	sb.WriteString("@")
	sb.WriteString(s.Tag)
	return sb.String()
}

func (m *dockerIngress) GetSample(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap, cacher cache.CacheInterface) (bool, error) {
	// intercept content-type
	var respContentType, _ = respHeaders.Get("Content-Type")
	switch respContentType {
	default:
		return false, nil
	case string(conregtypes.DockerManifestSchema2), string(conregtypes.OCIManifestSchema1):
	}
	// intercept method
	reqMethod, err := variable.GetString(ctx, types.VarMethod)
	if err != nil {
		return false, EncodeDockerReplyError(fmt.Errorf("error getting %s variable: %w", types.VarMethod, err))
	}
	if reqMethod != stdhttp.MethodGet {
		return false, nil
	}
	// intercept path
	reqPath, err := variable.GetString(ctx, types.VarPath)
	if err != nil {
		return false, EncodeDockerReplyError(fmt.Errorf("error getting %s variable: %w", types.VarPath, err))
	}
	var reqPaths = strings.Split(reqPath, "/")
	for i := 0; i < len(reqPaths); i++ {
		// ensure oci api
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

	repository, err := variable.GetString(ctx, types.VarIstioHeaderHost)
	if err != nil {
		return false, EncodeDockerReplyError(fmt.Errorf("error getting %s variable: %w", types.VarIstioHeaderHost, err))
	}

	m.packageSample = DockerIngressPackageSample{
		Path:              reqPath,
		Repository:        repository,
		Namespace:         reqPaths[1],
		Name:              reqPaths[2],
		Tag:               reqPaths[4],
		ManifestMediaType: respContentType,
		Manifest:          respBuf.Bytes(),
	}
	return true, nil
}

func (m *dockerIngress) ValidateSample(ctx context.Context) error {
	return nil
}

func (m *dockerIngress) GetBillOfMaterials(ctx context.Context, cacher cache.CacheInterface) error {
	// get blobs
	var manifest, err = conreg.ParseManifest(bytes.NewBuffer(m.packageSample.Manifest))
	if err != nil {
		return EncodeDockerReplyError(fmt.Errorf("error parsing manifest in %s format: %w", m.packageSample.ManifestMediaType, err))
	}

	type layerFetchedResult struct {
		order     int
		content   []byte
		mediaType conregtypes.MediaType
	}
	var layerFetchedResults = make([]layerFetchedResult, 0, len(manifest.Layers)+1)
	var layersWantToFetch = append(append(make([]conreg.Descriptor, 0, cap(layerFetchedResults)), manifest.Layers...), manifest.Config)
	for i := range layersWantToFetch {
		var blobOrder = i
		var blobURL = strings.Join([]string{"", "v2", m.packageSample.Namespace, m.packageSample.Name, "blobs", layersWantToFetch[blobOrder].Digest.String()}, "/")
		var blobCtx = mosnctx.WithValue(mosnctx.Clone(ctx), types.ContextKeyBufferPoolCtx, nil)
		var err = variable.SetString(blobCtx, types.VarPath, blobURL)
		if err != nil {
			return EncodeDockerReplyError(fmt.Errorf("error setting blob forward path: %w", err))
		}
		var blobBytes []byte
		var blobReceiver = func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error {
			if respCode != stdhttp.StatusOK {
				return nil
			}
			var contentType, _ = respHeaders.Get("Content-Type")
			if contentType != "application/octet-stream" {
				return EncodeDockerReplyError(fmt.Errorf("invalid blob content type %s", contentType))
			}
			if respData == nil {
				return nil
			}
			blobBytes = respData.Bytes()
			return nil
		}
		var blobForwardErr = m.Forward(blobCtx, m.route.RouteRule().ClusterName(ctx), blobReceiver)
		if blobForwardErr != nil {
			return blobForwardErr
		}
		if len(blobBytes) == 0 {
			return EncodeDockerReplyError(fmt.Errorf("empty blob in %d", blobOrder))
		}
		layerFetchedResults = append(layerFetchedResults, layerFetchedResult{
			order:     blobOrder,
			content:   blobBytes,
			mediaType: layersWantToFetch[blobOrder].MediaType,
		})
	}

	rawImage, err := conregmutate.AppendLayers(conregempty.Image)
	if err != nil {
		return fmt.Errorf("error appending image layer 0: %w", err)
	}
	for i := range layerFetchedResults {
		if i == len(layerFetchedResults)-1 {
			break
		}
		var result = layerFetchedResults[i]
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
		image.WithConfig(layerFetchedResults[len(layerFetchedResults)-1].content),
		image.WithManifest(m.packageSample.Manifest))
	if err = img.Read(); err != nil {
		return fmt.Errorf("error reading image: %w", err)
	}

	src, err := source.NewFromImage(img, m.packageSample.ImageName())
	if err != nil {
		return fmt.Errorf("error creating sbom scanning source: %w", err)
	}
	sbomBytes, err := m.GenerateSBOM(ctx, src)
	if err != nil {
		return fmt.Errorf("error generating sbom: %w", err)
	}

	m.packageSBOM = sbomBytes
	log.Proxy.Infof(ctx, "[docker/package_pull] sbom generated: \n%s", string(sbomBytes))
	return nil
}

func (m *dockerIngress) Validate(ctx context.Context) error {
	var headers, ok = mosnctx.Get(ctx, types.ContextKeyDownStreamHeaders).(api.HeaderMap)
	if !ok {
		return EncodeDockerReplyError(errors.New("cannot find downstream headers"))
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
	return EncodeDockerReplyError(m.evaluator.Evaluate(ctx, headers, input))
}

func (m dockerIngress) IngressPort() {}

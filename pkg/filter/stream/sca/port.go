package sca

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net"
	stdhttp "net/http"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/valyala/fasthttp"
	"mosn.io/api"
	mosnctx "mosn.io/mosn/pkg/context"
	"mosn.io/mosn/pkg/protocol"
	"mosn.io/mosn/pkg/protocol/http"
	"mosn.io/mosn/pkg/types"
	"mosn.io/mosn/pkg/upstream/cluster"
	"mosn.io/pkg/buffer"
)

type PortForwardReceiver func(ctx context.Context, respCode int, respHeaders api.HeaderMap, respData buffer.IoBuffer, respTrailers api.HeaderMap) error

type port struct{}

// GetProtocols returns the protocols of downstream and upstream.
func (port) GetProtocols(ctx context.Context) (downstreamProtocol types.ProtocolName, upstreamProtocol types.ProtocolName, err error) {
	downstreamProtocol, _ = mosnctx.Get(ctx, types.ContextKeyDownStreamProtocol).(types.ProtocolName)
	if downstreamProtocol == "" {
		err = errors.New("cannot find downstream protocol")
		return
	}
	upstreamProtocol, _ = mosnctx.Get(ctx, types.ContextKeyUpStreamProtocol).(types.ProtocolName)
	if upstreamProtocol == "" || upstreamProtocol == protocol.Auto {
		upstreamProtocol = downstreamProtocol
	}
	return
}

// Forward forwards the get request to the given target cluster.
func (p port) Forward(ctx context.Context, targetCluster string, receive PortForwardReceiver) error {
	var clsMgrAdapter = cluster.GetClusterMngAdapterInstance()
	var cls = clsMgrAdapter.GetClusterSnapshot(targetCluster)
	if cls == nil {
		return errors.New("cannot find target cluster")
	}

	var reqHeaders, ok = mosnctx.Get(ctx, types.ContextKeyDownStreamHeaders).(api.HeaderMap)
	if !ok {
		return errors.New("cannot find downstream headers")
	}
	var _, reqProtocol, err = p.GetProtocols(ctx)
	if err != nil {
		return err
	}

	var proc = &portForwarder{
		ctx:            ctx,
		cluster:        cls,
		headers:        reqHeaders.Clone(),
		data:           nil,
		trailers:       nil,
		forwardReceive: receive,
		errCh:          make(chan error),
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				proc.Stop(fmt.Errorf("panic: %v", r))
			}
		}()
		var cp, _ = clsMgrAdapter.ConnPoolForCluster(proc, cls, reqProtocol)
		var _, s, fr = cp.NewStream(ctx, proc)
		if fr != "" {
			proc.Stop(fmt.Errorf("failed to create stream with target cluster: %v", fr))
			return
		}
		proc.Start(s)
	}()
	return proc.Wait()
}

// GenerateSBOM generates the archive sbom with the given source.
func (port) GenerateSBOM(ctx context.Context, src source.Source) (stdjson.RawMessage, error) {
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

type portForwarder struct {
	ctx            context.Context
	cluster        types.ClusterSnapshot
	headers        api.HeaderMap
	data           buffer.IoBuffer
	trailers       api.HeaderMap
	forwardReceive PortForwardReceiver

	errCh chan error
}

func (p *portForwarder) MetadataMatchCriteria() api.MetadataMatchCriteria {
	return nil
}

func (p *portForwarder) DownstreamConnection() net.Conn {
	// NB(thxCode): panic here to let us know when and where use it.
	panic("not supported")
}

func (p *portForwarder) DownstreamHeaders() api.HeaderMap {
	return p.headers
}

func (p *portForwarder) DownstreamContext() context.Context {
	return p.ctx
}

func (p *portForwarder) DownstreamCluster() types.ClusterInfo {
	return p.cluster.ClusterInfo()
}

func (p *portForwarder) DownstreamRoute() api.Route {
	// NB(thxCode): panic here to let us know when and where use it.
	panic("not supported maglev load balancer")
}

func (p *portForwarder) Wait() error {
	return <-p.errCh
}

func (p *portForwarder) Stop(err error) {
	p.errCh <- err
}

func (p *portForwarder) OnReceive(ctx context.Context, rawRespHeaders api.HeaderMap, rawRespData buffer.IoBuffer, rawRespTrailers api.HeaderMap) {
	var headers, ok = rawRespHeaders.(http.ResponseHeader)
	if !ok {
		p.Stop(errors.New("unknown response header"))
		return
	}
	var data = rawRespData
	var trailers = rawRespTrailers

	switch headers.StatusCode() {
	case stdhttp.StatusTemporaryRedirect, stdhttp.StatusPermanentRedirect, stdhttp.StatusMovedPermanently:
		var location, _ = headers.Get("Location")
		if location == "" {
			p.Stop(errors.New("invalid redirect response"))
			return
		}
		var req fasthttp.Request
		p.headers.Range(func(key, value string) bool {
			switch key {
			case "Authorization", "User-Agent":
				req.Header.Add(key, value)
			}
			return true
		})
		req.SetRequestURI(location)
		var resp fasthttp.Response
		var err = fasthttp.Do(&req, &resp)
		if err != nil {
			p.Stop(fmt.Errorf("empty blob in %s", location))
			return
		}
		headers = http.ResponseHeader{ResponseHeader: &resp.Header}
		data = buffer.NewIoBufferBytes(resp.Body())
		trailers = nil
	default:
	}
	if p.forwardReceive != nil {
		p.Stop(p.forwardReceive(ctx, headers.StatusCode(), headers, data, trailers))
		return
	}
	p.Stop(nil) // close
}

func (p *portForwarder) OnDecodeError(ctx context.Context, err error, headers api.HeaderMap) {
	p.errCh <- err
}

func (p *portForwarder) Start(sender types.StreamSender) {
	var endStream = p.data == nil && p.trailers == nil
	var err = sender.AppendHeaders(p.ctx, p.headers, endStream)
	if err != nil {
		p.errCh <- fmt.Errorf("error appending headers for target cluster stream: %w", err)
		return
	}
	if endStream {
		return
	}

	endStream = p.trailers == nil
	err = sender.AppendData(p.ctx, p.data, endStream)
	if err != nil {
		p.errCh <- fmt.Errorf("error appending data for target cluster stream: %w", err)
		return
	}
	if endStream {
		return
	}

	err = sender.AppendTrailers(p.ctx, p.trailers)
	if err != nil {
		p.errCh <- fmt.Errorf("error appending trailers for target cluster stream: %w", err)
	}
}

type IngressPort interface {
	// GetDescriptor gets the resource descriptor from the given parameters.
	GetDescriptor(ctx context.Context, respHeaders api.HeaderMap, respBuf api.IoBuffer, respTrailers api.HeaderMap) (bool, error)

	// ValidateDescriptor validates the ingress resource with its sample, i.e. type, name, version, checksum,
	// which is faster but less accurate, and return nil if not block explicitly.
	ValidateDescriptor(ctx context.Context) error

	// GetBillOfMaterials generates from the ingress resource blobs.
	GetBillOfMaterials(ctx context.Context) error

	// ValidateBillOfMaterials validates the ingress resource with its sbom,
	// which is slower but more accurate, and return nil if not block.
	ValidateBillOfMaterials(ctx context.Context) error

	// IngressPort identifies from EgressPort.
	IngressPort()
}

type EgressPort interface {
	// GetDescriptor gets the resource descriptor from the given parameters.
	GetDescriptor(ctx context.Context, reqHeaders api.HeaderMap, reqBuf api.IoBuffer, reqTrailers api.HeaderMap) (bool, error)

	// GetBillOfMaterials generates from the egress resource blobs.
	GetBillOfMaterials(ctx context.Context) error

	// ValidateBillOfMaterials validates the egress resource with its sbom,
	// which is slower but more accurate, and return nil if not block.
	ValidateBillOfMaterials(ctx context.Context) error

	// EgressPort identifies from IngressPort.
	EgressPort()
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package xds

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"time"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpconnectionmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/credentials"

	"mosn.io/mosn/istio/istio1106/xds/conv"
	"mosn.io/mosn/pkg/istio"
	"mosn.io/mosn/pkg/log"
)

type AdsConfig struct {
	APIType      envoy_config_core_v3.ApiConfigSource_ApiType
	Services     []*ServiceConfig
	Clusters     map[string]*ClusterConfig
	xdsInfo      istio.XdsInfo
	converter    conv.Converter
	previousInfo *apiState
}

var _ istio.XdsStreamConfig = (*AdsConfig)(nil)

func (ads *AdsConfig) CreateXdsStreamClient() (istio.XdsStreamClient, error) {
	return NewAdsStreamClient(ads)
}

// InitAdsRequest creates a cds request
func (ads *AdsConfig) InitAdsRequest() interface{} {
	return CreateCdsRequest(ads)
}

func (ads *AdsConfig) Node() *envoy_config_core_v3.Node {
	return &envoy_config_core_v3.Node{
		Id:       ads.xdsInfo.ServiceNode,
		Cluster:  ads.xdsInfo.ServiceCluster,
		Metadata: ads.xdsInfo.Metadata,
	}
}

func (ads *AdsConfig) loadADSConfig(dynamicResources *envoy_config_bootstrap_v3.Bootstrap_DynamicResources) error {
	if dynamicResources == nil || dynamicResources.AdsConfig == nil {
		log.DefaultLogger.Errorf("DynamicResources is null")
		return errors.New("null point exception")
	}
	if err := dynamicResources.AdsConfig.Validate(); err != nil {
		log.DefaultLogger.Errorf("Invalid DynamicResources")
		return err
	}
	return ads.getAPISourceEndpoint(dynamicResources.AdsConfig)
}

func (ads *AdsConfig) getAPISourceEndpoint(source *envoy_config_core_v3.ApiConfigSource) error {
	if source.ApiType != envoy_config_core_v3.ApiConfigSource_GRPC {
		log.DefaultLogger.Errorf("unsupported api type: %v", source.ApiType)
		return errors.New("only support GRPC api type yet")
	}
	ads.APIType = source.ApiType
	ads.Services = make([]*ServiceConfig, 0, len(source.GrpcServices))
	for _, service := range source.GrpcServices {
		t := service.TargetSpecifier
		target, ok := t.(*envoy_config_core_v3.GrpcService_EnvoyGrpc_)
		if !ok {
			continue
		}
		serviceConfig := ServiceConfig{}
		if service.Timeout == nil || (service.Timeout.GetSeconds() <= 0 && service.Timeout.GetNanos() <= 0) {
			duration := time.Duration(time.Second) // default connection timeout
			serviceConfig.Timeout = &duration
		} else {
			nanos := service.Timeout.Seconds*int64(time.Second) + int64(service.Timeout.Nanos)
			duration := time.Duration(nanos)
			serviceConfig.Timeout = &duration
		}
		clusterName := target.EnvoyGrpc.ClusterName
		serviceConfig.ClusterConfig = ads.Clusters[clusterName]
		if serviceConfig.ClusterConfig == nil {
			log.DefaultLogger.Errorf("cluster not found: %s", clusterName)
			return fmt.Errorf("cluster not found: %s", clusterName)
		}
		ads.Services = append(ads.Services, &serviceConfig)
	}
	return nil
}

func (ads *AdsConfig) loadClusters(staticResources *envoy_config_bootstrap_v3.Bootstrap_StaticResources) error {
	if staticResources == nil {
		log.DefaultLogger.Errorf("StaticResources is null")
		err := errors.New("null point exception")
		return err
	}
	if err := staticResources.Validate(); err != nil {
		log.DefaultLogger.Errorf("Invalid StaticResources")
		return err
	}
	ads.Clusters = make(map[string]*ClusterConfig)
	for _, cluster := range staticResources.Clusters {
		name := cluster.Name
		config := ClusterConfig{}
		if cluster.TransportSocket != nil && cluster.TransportSocket.Name == wellknown.TransportSocketTls {
			config.TlsContext = cluster.TransportSocket
		}
		if cluster.LbPolicy != envoy_config_cluster_v3.Cluster_RANDOM {
			log.DefaultLogger.Warnf("only random lbPoliy supported, convert to random")
		}
		config.LbPolicy = envoy_config_cluster_v3.Cluster_RANDOM
		if cluster.ConnectTimeout.GetSeconds() <= 0 {
			duration := time.Second * 10
			config.ConnectTimeout = &duration // default connect timeout
		} else {
			duration := conv.ConvertDuration(cluster.ConnectTimeout)
			config.ConnectTimeout = &duration
		}

		// TODO: can we ignore it?
		if len(cluster.LoadAssignment.Endpoints) == 0 {
			log.DefaultLogger.Fatalf("xds v3 cluster.loadassignment is empty")
		}

		config.Address = make([]string, 0, len(cluster.LoadAssignment.GetEndpoints()[0].LbEndpoints))
		for _, host := range cluster.LoadAssignment.GetEndpoints()[0].LbEndpoints {
			endpoint := host.GetEndpoint()

			// Istio 1.8+ use istio-agent proxy request Istiod
			if pipe := endpoint.Address.GetPipe(); pipe != nil {
				newAddress := fmt.Sprintf("unix://%s", pipe.Path)
				config.Address = append(config.Address, newAddress)
				break
			}

			if endpoint.Address.GetSocketAddress() == nil {
				log.DefaultLogger.Fatalf("xds v3 cluster.loadassignment pipe and socket both empty")
			}
			if port, ok := endpoint.Address.GetSocketAddress().PortSpecifier.(*envoy_config_core_v3.SocketAddress_PortValue); ok {
				newAddress := fmt.Sprintf("%s:%d", endpoint.Address.GetSocketAddress().Address, port.PortValue)
				config.Address = append(config.Address, newAddress)
			} else {
				log.DefaultLogger.Warnf("only PortValue supported")
				continue
			}
		}
		ads.Clusters[name] = &config
	}
	return nil
}

func getBytesFromDataSource(source *envoy_config_core_v3.DataSource) (bs []byte, err error) {
	switch t := source.GetSpecifier().(type) {
	default:
		err = errors.New("unknown data source type")
		return
	case *envoy_config_core_v3.DataSource_Filename:
		bs, err = ioutil.ReadFile(t.Filename)
		if err != nil {
			return
		}
	case *envoy_config_core_v3.DataSource_InlineBytes:
		bs = t.InlineBytes
	case *envoy_config_core_v3.DataSource_InlineString:
		var v = t.InlineString
		if v != "" {
			bs = []byte(v)
		}
	case *envoy_config_core_v3.DataSource_EnvironmentVariable:
		var v = os.Getenv(t.EnvironmentVariable)
		if v != "" {
			bs = []byte(v)
		}
	}
	if len(bs) == 0 {
		err = errors.New("empty bytes")
		return
	}
	return
}

func (ads *AdsConfig) getTLSCreds(tlsContextConfig *envoy_config_core_v3.TransportSocket) (credentials.TransportCredentials, error) {
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{}
	if err := ptypes.UnmarshalAny(tlsContextConfig.GetTypedConfig(), tlsContext); err != nil {
		return nil, err
	}
	var tlsConfig = tls.Config{
		InsecureSkipVerify: true,
	}

	if trustedCA := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa(); trustedCA != nil {
		var certPool = x509.NewCertPool()
		var trustedCABytes, err = getBytesFromDataSource(trustedCA)
		if err != nil {
			return nil, err
		}
		if !certPool.AppendCertsFromPEM(trustedCABytes) {
			return nil, errors.New("failed to append trusted CA")
		}
		tlsConfig.RootCAs = certPool
	}

	if tlsCerts := tlsContext.GetCommonTlsContext().GetTlsCertificates(); len(tlsCerts) != 0 {
		var tlsCert = tlsCerts[0]
		var tlsCertCrtBytes, tlsCertKeyBytes []byte
		var err error
		if tlsCertCrt := tlsCert.GetCertificateChain(); tlsCertCrt != nil {
			tlsCertCrtBytes, err = getBytesFromDataSource(tlsCertCrt)
			if err != nil {
				return nil, err
			}
		}
		if tlsCertKey := tlsCert.GetPrivateKey(); tlsCertKey != nil {
			tlsCertKeyBytes, err = getBytesFromDataSource(tlsCertKey)
			if err != nil {
				return nil, err
			}
		}
		if len(tlsCertCrtBytes) == 0 || len(tlsCertKeyBytes) == 0 {
			return nil, errors.New("blank client cert or key")
		}
		tlsCertX509, err := tls.X509KeyPair(tlsCertCrtBytes, tlsCertKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("error construct x509 key pair with given client cert and key: %w", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCertX509)
	}

	return credentials.NewTLS(&tlsConfig), nil
}

const connectionManager = "envoy.filters.network.http_connection_manager"

var (
	typeFactoryMapping = map[string]func() proto.Message{
		connectionManager: func() proto.Message { return new(httpconnectionmanagerv3.HttpConnectionManager) },
	}
)

// FIXME: does this datas will be overwrite the xds info?
func (ads *AdsConfig) loadStaticResources(staticResources *envoy_config_bootstrap_v3.Bootstrap_StaticResources) error {
	var clusters []*envoy_config_cluster_v3.Cluster
	if cs := staticResources.Clusters; cs != nil && len(cs) > 0 {
		clusters = make([]*envoy_config_cluster_v3.Cluster, 0, len(cs))
		for _, c := range cs {
			if name := c.Name; name == "zipkin" { // why ignore zipkin ?
				continue
			}
			clusters = append(clusters, c)
		}
	}
	if len(clusters) > 0 {
		ads.converter.ConvertUpdateClusters(clusters)
	}
	listeners, routes, err := adaptStaticListenersToDynamic(staticResources.Listeners)
	if err != nil {
		return err
	}
	ads.converter.ConvertUpdateListeners(listeners)
	ads.converter.ConvertUpdateRouters(routes)
	return nil

}

func adaptStaticListenersToDynamic(listeners []*listenerv3.Listener) ([]*listenerv3.Listener, []*routev3.RouteConfiguration, error) {
	if len(listeners) <= 0 {
		return nil, nil, nil
	}
	collector := &routerCollector{routes: make([]*routev3.RouteConfiguration, 0, len(listeners))}
	for _, listener := range listeners {
		port := adaptListenerName(listener)
		if err := collector.collectRoute(listener, port); err != nil {
			return nil, nil, err
		}
	}
	return listeners, collector.routes, nil
}

func adaptListenerName(listener *listenerv3.Listener) (port uint32) {
	// name exists
	if len(listener.Name) > 0 {
		return
	}
	address := listener.Address.GetSocketAddress()
	if address == nil {
		return
	}
	port = address.GetPortValue()
	if port == 0 {
		return
	}
	listener.Name = "127.0.0.1_" + strconv.Itoa(int(port))
	return port
}

type routerCollector struct {
	routes []*routev3.RouteConfiguration
}

func (rc *routerCollector) collectRoute(listener *listenerv3.Listener, port uint32) (err error) {

	filterChains := listener.FilterChains
	if len(filterChains) <= 0 {
		return nil
	}
	for _, filterChain := range filterChains {
		filters := filterChain.Filters
		if len(filters) <= 0 {
			continue
		}
		for _, filter := range filters {
			factory, exist := typeFactoryMapping[filter.Name]
			if !exist {
				log.DefaultLogger.Warnf("cannot handle route type, listener: %s, filter: %s", listener.Name, filter.Name)
				continue
			}

			typedConfig := factory()
			if err = ptypes.UnmarshalAny(filter.GetTypedConfig(), typedConfig); err != nil {
				return
			}
			switch typedConfig.(type) {
			case *httpconnectionmanagerv3.HttpConnectionManager:
				manager := typedConfig.(*httpconnectionmanagerv3.HttpConnectionManager)

				if routerConfig := manager.GetRouteConfig(); routerConfig != nil {
					if name := routerConfig.Name; len(name) <= 0 && port > 0 {
						routerConfig.Name = fmt.Sprintf("inbound|%d||", port)
						if a, e := ptypes.MarshalAny(manager); e != nil {
							log.DefaultLogger.Errorf("marshal connection manager back to any failed, %s", e)
						} else {
							filter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: a}
						}
					}
					rc.routes = append(rc.routes, routerConfig)
				}
			default:
				log.DefaultLogger.Warnf("cannot handle route config type, listener: %s, name: %s",
					listener.Name, filter.Name)

			}
		}
	}
	return nil
}

// ServiceConfig for grpc service
type ServiceConfig struct {
	Timeout       *time.Duration
	ClusterConfig *ClusterConfig
}

// ClusterConfig contains an cluster info from static resources
type ClusterConfig struct {
	LbPolicy       envoy_config_cluster_v3.Cluster_LbPolicy
	Address        []string
	ConnectTimeout *time.Duration
	TlsContext     *envoy_config_core_v3.TransportSocket
}

// GetEndpoint return an endpoint address by random
func (c *ClusterConfig) GetEndpoint() (string, *time.Duration) {
	if c.LbPolicy != envoy_config_cluster_v3.Cluster_RANDOM || len(c.Address) < 1 {
		// never happen
		return "", nil
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	idx := r.Intn(len(c.Address))

	return c.Address[idx], c.ConnectTimeout
}

package config

import (
	"errors"

	pb "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"gitlab.alipay-inc.com/afe/mosn/pkg/log"
	"gitlab.alipay-inc.com/afe/mosn/pkg/server"
	"gitlab.alipay-inc.com/afe/mosn/pkg/server/config/proxy"
	"gitlab.alipay-inc.com/afe/mosn/pkg/types"
	clusterAdapter "gitlab.alipay-inc.com/afe/mosn/pkg/upstream/cluster"
	"gitlab.alipay-inc.com/afe/mosn/pkg/api/v2"
)

func SetGlobalStreamFilter(globalStreamFilters []types.StreamFilterChainFactory) {
	if streamFilter == nil {
		streamFilter = globalStreamFilters
	}
}

// todo , no hack
var streamFilter []types.StreamFilterChainFactory

func (config *MOSNConfig) OnUpdateListeners(listeners []*pb.Listener) error {
	for _, listener := range listeners {
		mosnListener := convertListenerConfig(listener)
		if mosnListener == nil {
			continue
		}

		var networkFilter *proxy.GenericProxyFilterConfigFactory

		for _, filterChain := range mosnListener.FilterChains {
			for _, filter := range filterChain.Filters {
				if filter.Name == v2.DEFAULT_NETWORK_FILTER {
					networkFilter = &proxy.GenericProxyFilterConfigFactory{
						Proxy: ParseProxyFilterJson(&filter),
					}
				}
			}
		}

		if networkFilter == nil {
			errMsg := "proxy needed in network filters"
			log.DefaultLogger.Errorf(errMsg)
			return errors.New(errMsg)
		}

		if streamFilter != nil {
			errMsg := "stream filter needed in network filters"
			log.DefaultLogger.Errorf(errMsg)
			return errors.New(errMsg)
		}

		if err := server.GetServer().AddListenerAndStart(mosnListener, networkFilter, streamFilter); err == nil {
			log.StartLogger.Infof("Add listener success listener = %+v\n", mosnListener)
		} else {
			log.StartLogger.Infof("Add listener error, listener = %+v\n", mosnListener)
			return err
		}
	}

	return nil
}

/*
func (config *MOSNConfig) OnUpdateRoutes(route *pb.RouteConfiguration) error {
	log.DefaultLogger.Infof("route: %+v\n", route)
	return nil
}
*/

func (config *MOSNConfig) OnUpdateClusters(clusters []*pb.Cluster) error {
	mosnClusters := convertClustersConfig(clusters)

	for _, cluster := range mosnClusters {
		log.DefaultLogger.Infof("cluster: %+v\n", cluster)
		if err := clusterAdapter.ClusterAdap.TriggerClusterUpdate(cluster.Name, cluster.Hosts); err != nil {
			log.DefaultLogger.Errorf("Istio Update Clusters Error = %s", err.Error())
		}

	}

	return nil
}

func (config *MOSNConfig) OnUpdateEndpoints(loadAssignments []*pb.ClusterLoadAssignment) error {

	for _, loadAssignment := range loadAssignments {
		clusterName := loadAssignment.ClusterName

		for _, endpoints := range loadAssignment.Endpoints {
			hosts := convertEndpointsConfig(&endpoints)

			for _, host := range hosts {
				log.DefaultLogger.Infof("endpoint: cluster: %s, priority: %d, %+v\n", loadAssignment.ClusterName, endpoints.Priority, host)
			}

			if err := clusterAdapter.ClusterAdap.TriggerClusterUpdate(clusterName, hosts); err != nil {
				log.DefaultLogger.Errorf("Istio Update Clusters Error = %s", err.Error())
			}
		}
	}

	return nil
}

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

package conv

import (
	"errors"
	"fmt"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jsoniter "github.com/json-iterator/go"
	"k8s.io/apimachinery/pkg/util/sets"

	"mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/router"
	"mosn.io/mosn/pkg/server"
	clusterAdapter "mosn.io/mosn/pkg/upstream/cluster"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func (cvt *xdsConverter) ConvertUpdateClusters(clusters []*envoy_config_cluster_v3.Cluster) error {
	configLock.Lock()
	var ins = sets.NewString()
	var adds = make([]*envoy_config_cluster_v3.Cluster, 0, len(clusters))
	for i := range clusters {
		ins.Insert(clusters[i].GetName())
		adds = append(adds, clusters[i])
	}
	var dels = make([]*envoy_config_cluster_v3.Cluster, 0)
	for i := range envoyClusters {
		if !ins.Has(envoyClusters[i].GetName()) {
			dels = append(dels, envoyClusters[i])
		}
	}
	configLock.Unlock()

	mosnAddClusters := ConvertClustersConfig(adds)
	for _, cls := range mosnAddClusters {
		var err error
		if cls.ClusterType == v2.EDS_CLUSTER {
			err = clusterAdapter.GetClusterMngAdapterInstance().TriggerClusterAddOrUpdate(*cls)
		} else {
			err = clusterAdapter.GetClusterMngAdapterInstance().TriggerClusterAndHostsAddOrUpdate(*cls, cls.Hosts)
		}
		if err != nil {
			log.DefaultLogger.Errorf("[convertxds] update cluster failed, name: '%s', error: %v", cls.Name, err)
			cvt.stats.CdsUpdateReject.Inc(1)
			return err
		}
		log.DefaultLogger.Debugf("[convertxds] update cluster succeed, name: '%s'", cls.Name)
		cvt.stats.CdsUpdateSuccess.Inc(1)
	}
	mosnDelClusters := ConvertClustersConfig(dels)
	for _, cls := range mosnDelClusters {
		log.DefaultLogger.Debugf("delete cluster: %+v\n", cls)
		var err error
		if cls.ClusterType == v2.EDS_CLUSTER {
			err = clusterAdapter.GetClusterMngAdapterInstance().TriggerClusterDel(cls.Name)
		}
		if err != nil {
			log.DefaultLogger.Errorf("[convertxds] delete cluster failed, name: '%s', error: %v", cls.Name, err)
			cvt.stats.CdsUpdateReject.Inc(1)
			continue
		}
		log.DefaultLogger.Debugf("[convertxds] delete cluster succeed, name: '%s'", cls.Name)
		cvt.stats.CdsUpdateSuccess.Inc(1)
	}

	EnvoyConfigUpdateClusters(adds, dels)
	return nil
}

func (cvt *xdsConverter) ConvertUpdateRouters(routers []*envoy_config_route_v3.RouteConfiguration) error {
	routersMngIns := router.GetRoutersMangerInstance()
	if routersMngIns == nil {
		return errors.New("[convertxds] ConvertUpdateRouters router error: router manager in nil")
	}

	configLock.Lock()
	var ins = sets.NewString()
	var adds = make([]*envoy_config_route_v3.RouteConfiguration, 0, len(routers))
	for i := range routers {
		ins.Insert(routers[i].GetName())
		adds = append(adds, routers[i])
	}
	var dels = make([]*envoy_config_route_v3.RouteConfiguration, 0)
	for i := range envoyRoutes {
		if !ins.Has(envoyRoutes[i].GetName()) {
			dels = append(dels, envoyRoutes[i])
		}
	}
	configLock.Unlock()

	for _, rt := range adds {
		mosnAddRouter, _ := ConvertRouterConf("", rt)
		err := routersMngIns.AddOrUpdateRouters(mosnAddRouter)
		if err != nil {
			log.DefaultLogger.Errorf("[convertxds] update route failed, name: '%s', error: %v", rt.Name, err)
			return err
		}
		log.DefaultLogger.Debugf("[convertxds] update route succeed, name: '%s'", rt.Name)
	}
	for _, rt := range dels {
		mosnAddRouter, _ := ConvertRouterConf("", rt)
		err := routersMngIns.DeleteRouters(mosnAddRouter)
		if err != nil {
			log.DefaultLogger.Errorf("[convertxds] delete route failed, name: '%s', error: %v", rt.Name, err)
			continue
		}
		log.DefaultLogger.Debugf("[convertxds] delete route succeed, name: '%s'", rt.Name)
	}

	EnvoyConfigUpdateRoutes(adds, dels)
	return nil
}

func (cvt *xdsConverter) ConvertUpdateListeners(listeners []*envoy_config_listener_v3.Listener) error {
	listenerAdapter := server.GetListenerAdapterInstance()
	if listenerAdapter == nil {
		cvt.stats.LdsUpdateReject.Inc(1)
		return errors.New("[convertxds] ConvertUpdateListeners error: listener adapter in nil")
	}

	configLock.Lock()
	var ins = sets.NewString()
	var adds = make([]*envoy_config_listener_v3.Listener, 0, len(listeners))
	for i := range listeners {
		ins.Insert(listeners[i].GetName())
		adds = append(adds, listeners[i])
	}
	var dels = make([]*envoy_config_listener_v3.Listener, 0)
	for i := range envoyListeners {
		if !ins.Has(envoyListeners[i].GetName()) {
			dels = append(dels, envoyListeners[i])
		}
	}
	configLock.Unlock()

	for _, lis := range adds {
		mosnListeners := ConvertListenerConfig(lis, cvt.listenerRouterHandler)
		if len(mosnListeners) == 0 {
			log.DefaultLogger.Errorf("[convertxds] ConvertUpdateListeners error: empty listeners")
			cvt.stats.LdsUpdateReject.Inc(1)
			continue // Maybe next listener is ok
		}
		for _, mosnListener := range mosnListeners {
			err := listenerAdapter.AddOrUpdateListener("", mosnListener)
			if err != nil {
				log.DefaultLogger.Errorf("[convertxds] update listener failed, name: '%s', error: %v", mosnListener.Name, err)
				cvt.stats.LdsUpdateReject.Inc(1)
				return err
			}
			log.DefaultLogger.Debugf("[convertxds] update listener succeed, name: '%s'", mosnListener.Name)
			cvt.stats.LdsUpdateSuccess.Inc(1)
		}
	}
	for _, lis := range dels {
		err := listenerAdapter.DeleteListener("", lis.GetName())
		if err != nil {
			log.DefaultLogger.Errorf("[convertxds] delete listener failed, name: '%s', error: %v", lis.GetName(), err)
			cvt.stats.LdsUpdateReject.Inc(1)
			continue
		}
		log.DefaultLogger.Debugf("[convertxds] delete listener succeed, name: '%s'", lis.GetName())
		cvt.stats.LdsUpdateSuccess.Inc(1)
	}

	EnvoyConfigUpdateListeners(adds, dels)
	return nil
}

type routeHandler func(isRds bool, routerConfig *v2.RouterConfiguration)

// listenerRouterHandler handles router config in listener
func (cvt *xdsConverter) listenerRouterHandler(isRds bool, routerConfig *v2.RouterConfiguration) {
	if routerConfig == nil {
		return
	}
	// save rds records, get router config from rds request
	if isRds {
		cvt.AppendRouterName(routerConfig.RouterConfigName)
		return
	}
	routersMngIns := router.GetRoutersMangerInstance()
	if routersMngIns == nil {
		log.DefaultLogger.Errorf("[xds] [router handler] AddOrUpdateRouters error: router manager in nil")
		return
	}
	if err := routersMngIns.AddOrUpdateRouters(routerConfig); err != nil {
		log.DefaultLogger.Errorf("[xds] [router handler]  AddOrUpdateRouters error: %v", err)
	}

}

// ConvertUpdateEndpoints converts cluster configuration, used to udpate hosts
func (cvt *xdsConverter) ConvertUpdateEndpoints(loadAssignments []*envoy_config_endpoint_v3.ClusterLoadAssignment) error {
	var errGlobal error
	clusterMngAdapter := clusterAdapter.GetClusterMngAdapterInstance()
	if clusterMngAdapter == nil {
		return errors.New("xds ConvertUpdateEndpoints error: cluster mng adapter in nil")
	}

	for _, loadAssignment := range loadAssignments {
		clusterName := loadAssignment.ClusterName

		if len(loadAssignment.Endpoints) == 0 {
			if err := clusterAdapter.GetClusterMngAdapterInstance().TriggerClusterHostUpdate(clusterName, nil); err != nil {
				log.DefaultLogger.Errorf("xds client update Error = %s, hosts are is empty", err.Error())
				errGlobal = fmt.Errorf("xds client update Error = %s, hosts are is empty", err.Error())
			} else {
				log.DefaultLogger.Debugf("xds client update host success,hosts is empty")
			}
			continue
		}

		for _, endpoints := range loadAssignment.Endpoints {
			hosts := ConvertEndpointsConfig(endpoints)
			log.DefaultLogger.Debugf("xds client update endpoints: cluster: %s, priority: %d", loadAssignment.ClusterName, endpoints.Priority)
			for index, host := range hosts {
				log.DefaultLogger.Debugf("host[%d] is : %+v", index, host)
			}

			if err := clusterAdapter.GetClusterMngAdapterInstance().TriggerClusterHostUpdate(clusterName, hosts); err != nil {
				log.DefaultLogger.Errorf("xds client update Error = %s, hosts are %+v", err.Error(), hosts)
				errGlobal = fmt.Errorf("xds client update Error = %s, hosts are %+v", err.Error(), hosts)

			} else {
				log.DefaultLogger.Debugf("xds client update host success,hosts are %+v", hosts)
			}
		}
	}

	return errGlobal

}

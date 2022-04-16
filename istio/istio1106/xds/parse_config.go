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
	"encoding/json"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"mosn.io/mosn/istio/istio1106/xds/conv"
	"mosn.io/mosn/pkg/admin/server"
	"mosn.io/mosn/pkg/istio"
	"mosn.io/mosn/pkg/log"
)

func init() {
	istio.RegisterParseAdsConfig(UnmarshalResources)
}

// UnmarshalResources register  istio.ParseAdsConfig
func UnmarshalResources(dynamic, static json.RawMessage) (istio.XdsStreamConfig, error) {
	ads, err := unmarshalResources(dynamic, static)
	if err != nil {
		return nil, err
	}
	// register admin api
	server.RegisterAdminHandleFunc("/stats", ads.statsForIstio)

	return ads, nil
}

// unmarshalResources used in order to convert bootstrap_v2 json to pb struct (go-control-plane), some fields must be exchanged format
func unmarshalResources(dynamic, static json.RawMessage) (*AdsConfig, error) {
	dynamicResources, err := unmarshalDynamic(dynamic)
	if err != nil {
		return nil, err
	}
	staticResources, err := unmarshalStatic(static)
	if err != nil {
		return nil, err
	}
	cfg := &AdsConfig{
		xdsInfo:      istio.GetGlobalXdsInfo(),
		converter:    conv.NewConverter(),
		previousInfo: newApiState(),
	}
	// update static config to mosn config
	if err := cfg.loadClusters(staticResources); err != nil {
		return nil, err
	}
	if err := cfg.loadStaticResources(staticResources); err != nil {
		return nil, err
	}
	if err := cfg.loadADSConfig(dynamicResources); err != nil {
		return nil, err
	}
	return cfg, nil
}

func unmarshalDynamic(dynamic json.RawMessage) (*envoy_config_bootstrap_v3.Bootstrap_DynamicResources, error) {
	if len(dynamic) <= 0 {
		return nil, nil
	}
	dynamicResources := &envoy_config_bootstrap_v3.Bootstrap_DynamicResources{}
	if err := protojson.Unmarshal(dynamic, dynamicResources); err != nil {
		log.DefaultLogger.Errorf("fail to unmarshal dynamic_resources: %v", err)
		return nil, err
	}
	if err := dynamicResources.Validate(); err != nil {
		log.DefaultLogger.Errorf("Invalid static_resources: %v", err)
		return nil, err
	}
	return dynamicResources, nil
}

func unmarshalStatic(static json.RawMessage) (*envoy_config_bootstrap_v3.Bootstrap_StaticResources, error) {
	if len(static) <= 0 {
		return nil, nil
	}
	staticResources := &envoy_config_bootstrap_v3.Bootstrap_StaticResources{}
	if err := protojson.Unmarshal(static, staticResources); err != nil {
		log.DefaultLogger.Errorf("fail to unmarshal static_resources: %v", err)
		return nil, err
	}
	if err := staticResources.Validate(); err != nil {
		log.DefaultLogger.Errorf("Invalid static_resources: %v", err)
		return nil, err
	}
	return staticResources, nil
}

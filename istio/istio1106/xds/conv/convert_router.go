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
	"fmt"
	"strings"

	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3" // some config contains this protobuf, mosn does not parse it yet.
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"mosn.io/mosn/pkg/filter/stream/sca"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/any"
	"mosn.io/api"
	"mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/featuregate"
	"mosn.io/mosn/pkg/log"
)

func ConvertRouterConf(routeConfigName string, xdsRouteConfig *envoy_config_route_v3.RouteConfiguration) (*v2.RouterConfiguration, bool) {
	if routeConfigName != "" {
		return &v2.RouterConfiguration{
			RouterConfigurationConfig: v2.RouterConfigurationConfig{
				RouterConfigName: routeConfigName,
			},
		}, true
	}

	if xdsRouteConfig == nil {
		return nil, false
	}

	virtualHosts := make([]v2.VirtualHost, 0)

	for _, xdsVirtualHost := range xdsRouteConfig.GetVirtualHosts() {
		virtualHost := v2.VirtualHost{
			Name:    xdsVirtualHost.GetName(),
			Domains: xdsVirtualHost.GetDomains(),
			Routers: convertRoutes(xdsVirtualHost.GetRoutes()),
			// RequireTLS:              xdsVirtualHost.GetRequireTls().String(),
			// VirtualClusters:         convertVirtualClusters(xdsVirtualHost.GetVirtualClusters()),
			RequestHeadersToAdd:     convertHeadersToAdd(xdsVirtualHost.GetRequestHeadersToAdd()),
			RequestHeadersToRemove:  xdsVirtualHost.GetRequestHeadersToRemove(),
			ResponseHeadersToAdd:    convertHeadersToAdd(xdsVirtualHost.GetResponseHeadersToAdd()),
			ResponseHeadersToRemove: xdsVirtualHost.GetResponseHeadersToRemove(),
		}
		virtualHosts = append(virtualHosts, virtualHost)
	}

	return &v2.RouterConfiguration{
		RouterConfigurationConfig: v2.RouterConfigurationConfig{
			RouterConfigName:        xdsRouteConfig.GetName(),
			RequestHeadersToAdd:     convertHeadersToAdd(xdsRouteConfig.GetRequestHeadersToAdd()),
			RequestHeadersToRemove:  xdsRouteConfig.GetRequestHeadersToRemove(),
			ResponseHeadersToAdd:    convertHeadersToAdd(xdsRouteConfig.GetResponseHeadersToAdd()),
			ResponseHeadersToRemove: xdsRouteConfig.GetResponseHeadersToRemove(),
		},
		VirtualHosts: virtualHosts,
	}, false
}

func convertRoutes(xdsRoutes []*envoy_config_route_v3.Route) []v2.Router {
	if xdsRoutes == nil {
		return nil
	}
	routes := make([]v2.Router, 0, len(xdsRoutes))
	for _, xdsRoute := range xdsRoutes {
		if xdsRouteAction := xdsRoute.GetRoute(); xdsRouteAction != nil {
			route := v2.Router{
				RouterConfig: v2.RouterConfig{
					Match: convertRouteMatch(xdsRoute.GetMatch()),
					Route: convertRoute(xdsRoute),
					// Decorator: v2.Decorator(xdsRoute.GetDecorator().String()),
					RequestMirrorPolicies: convertMirrorPolicy(xdsRouteAction),
				},
				Metadata: convertMeta(xdsRoute.GetMetadata()),
			}
			route.PerFilterConfig = convertPerRouteConfig(xdsRoute.GetTypedPerFilterConfig())
			routes = append(routes, route)
		} else if xdsRouteAction := xdsRoute.GetRedirect(); xdsRouteAction != nil {
			route := v2.Router{
				RouterConfig: v2.RouterConfig{
					Match:    convertRouteMatch(xdsRoute.GetMatch()),
					Redirect: convertRedirectAction(xdsRouteAction),
					// Decorator: v2.Decorator(xdsRoute.GetDecorator().String()),
				},
				Metadata: convertMeta(xdsRoute.GetMetadata()),
			}
			route.PerFilterConfig = convertPerRouteConfig(xdsRoute.GetTypedPerFilterConfig())
			routes = append(routes, route)
		} else if xdsRouteAction := xdsRoute.GetDirectResponse(); xdsRouteAction != nil {
			route := v2.Router{
				RouterConfig: v2.RouterConfig{
					Match:          convertRouteMatch(xdsRoute.GetMatch()),
					DirectResponse: convertDirectResponseAction(xdsRouteAction),
					// Decorator: v2.Decorator(xdsRoute.GetDecorator().String()),
				},
				Metadata: convertMeta(xdsRoute.GetMetadata()),
			}
			route.PerFilterConfig = convertPerRouteConfig(xdsRoute.GetTypedPerFilterConfig())
			routes = append(routes, route)
		} else {
			log.DefaultLogger.Errorf("unsupported route actin, just Route, Redirect and DirectResponse support yet, ignore this route")
			continue
		}
	}
	return routes
}

func convertPerRouteConfig(xdsPerRouteConfig map[string]*any.Any) map[string]interface{} {
	perRouteConfig := make(map[string]interface{}, 0)

	for key, config := range xdsPerRouteConfig {
		switch key {
		case v2.FaultStream, wellknown.Fault:
			cfg, err := convertStreamFaultInjectConfig(config)
			if err != nil {
				log.DefaultLogger.Infof("convertPerRouteConfig[%s] error: %v", v2.FaultStream, err)
				continue
			}
			log.DefaultLogger.Debugf("add a fault inject stream filter in router")
			perRouteConfig[v2.FaultStream] = cfg
		case v2.PayloadLimit:
			if featuregate.Enabled(featuregate.PayLoadLimitEnable) {
				// cfg, err := convertStreamPayloadLimitConfig(config)
				// if err != nil {
				//      log.DefaultLogger.Infof("convertPerRouteConfig[%s] error: %v", v2.PayloadLimit, err)
				//      continue
				// }
				// log.DefaultLogger.Debugf("add a payload limit stream filter in router")
				// perRouteConfig[v2.PayloadLimit] = cfg
			}
		case v2.HTTP_SCA:
			cfg, err := sca.ConvertAnyToConfig(config)
			if err != nil {
				log.DefaultLogger.Infof(" error: %v", v2.HTTP_SCA, err)
				continue
			}
			log.DefaultLogger.Debugf("add a sbomgen stream filter in router")
			perRouteConfig[v2.HTTP_SCA] = cfg
		default:
			log.DefaultLogger.Warnf("unknown per route config: %s", key)
		}
	}

	return perRouteConfig
}

func convertRouteMatch(xdsRouteMatch *envoy_config_route_v3.RouteMatch) v2.RouterMatch {
	rm := v2.RouterMatch{
		Prefix: xdsRouteMatch.GetPrefix(),
		Path:   xdsRouteMatch.GetPath(),
		// CaseSensitive: xdsRouteMatch.GetCaseSensitive().GetValue(),
		// Runtime:       convertRuntime(xdsRouteMatch.GetRuntime()),
		Headers: convertHeaders(xdsRouteMatch.GetHeaders()),
	}
	if xdsRouteMatch.GetSafeRegex() != nil {
		rm.Regex = xdsRouteMatch.GetSafeRegex().Regex
	}
	return rm
}

func convertHeaders(xdsHeaders []*envoy_config_route_v3.HeaderMatcher) []v2.HeaderMatcher {
	if xdsHeaders == nil {
		return nil
	}
	headerMatchers := make([]v2.HeaderMatcher, 0, len(xdsHeaders))
	for _, xdsHeader := range xdsHeaders {
		headerMatcher := v2.HeaderMatcher{
			Name:  xdsHeader.GetName(),
			Regex: true,
		}

		switch t := (xdsHeader.GetHeaderMatchSpecifier()).(type) {
		case *envoy_config_route_v3.HeaderMatcher_ExactMatch:
			headerMatcher.Regex = false
			headerMatcher.Value = t.ExactMatch
		case *envoy_config_route_v3.HeaderMatcher_SafeRegexMatch:
			headerMatcher.Value = t.SafeRegexMatch.Regex
		case *envoy_config_route_v3.HeaderMatcher_ContainsMatch:
			headerMatcher.Value = ".*" + t.ContainsMatch + ".*"
		case *envoy_config_route_v3.HeaderMatcher_PrefixMatch:
			headerMatcher.Value = "^" + t.PrefixMatch + ".*"
		case *envoy_config_route_v3.HeaderMatcher_SuffixMatch:
			headerMatcher.Value = ".*" + t.SuffixMatch + "$"
		case *envoy_config_route_v3.HeaderMatcher_RangeMatch:
			headerMatcher.Value = fmt.Sprintf("[%d,%d]", t.RangeMatch.Start, t.RangeMatch.End-1)
		case *envoy_config_route_v3.HeaderMatcher_PresentMatch:
			headerMatcher.Value = ".*"
		case *envoy_config_route_v3.HeaderMatcher_StringMatch:
			switch tt := (t.StringMatch.GetMatchPattern()).(type) {
			case *envoy_type_matcher_v3.StringMatcher_Exact:
				headerMatcher.Regex = false
				headerMatcher.Value = tt.Exact
			case *envoy_type_matcher_v3.StringMatcher_SafeRegex:
				headerMatcher.Value = tt.SafeRegex.Regex
			case *envoy_type_matcher_v3.StringMatcher_Contains:
				headerMatcher.Value = ".*" + tt.Contains + ".*"
			case *envoy_type_matcher_v3.StringMatcher_Prefix:
				headerMatcher.Value = "^" + tt.Prefix + ".*"
			case *envoy_type_matcher_v3.StringMatcher_Suffix:
				headerMatcher.Value = ".*" + tt.Suffix + "$"
			}
		}

		// as pseudo headers not support when Http1.x upgrade to Http2, change pseudo headers to normal headers
		// this would be fix soon
		if strings.HasPrefix(headerMatcher.Name, ":") {
			headerMatcher.Name = headerMatcher.Name[1:]
		}
		headerMatchers = append(headerMatchers, headerMatcher)
	}
	return headerMatchers
}

func convertMeta(xdsMeta *envoy_config_core_v3.Metadata) api.Metadata {
	if xdsMeta == nil {
		return nil
	}
	meta := make(map[string]string, len(xdsMeta.GetFilterMetadata()))
	for key, value := range xdsMeta.GetFilterMetadata() {
		meta[key] = value.String()
	}
	return meta
}

func convertRoute(xdsRoute *envoy_config_route_v3.Route) v2.RouteAction {
	if xdsRoute == nil {
		return v2.RouteAction{}
	}
	xdsRouteAction := xdsRoute.GetRoute()
	return v2.RouteAction{
		RouterActionConfig: v2.RouterActionConfig{
			ClusterName:             xdsRouteAction.GetCluster(),
			ClusterHeader:           xdsRouteAction.GetClusterHeader(),
			WeightedClusters:        convertWeightedClusters(xdsRouteAction.GetWeightedClusters()),
			HashPolicy:              convertHashPolicy(xdsRouteAction.GetHashPolicy()),
			RetryPolicy:             convertRetryPolicy(xdsRouteAction.GetRetryPolicy()),
			PrefixRewrite:           xdsRouteAction.GetPrefixRewrite(),
			RegexRewrite:            convertRegexRewrite(xdsRouteAction.GetRegexRewrite()),
			HostRewrite:             xdsRouteAction.GetHostRewriteLiteral(),
			AutoHostRewriteHeader:   xdsRouteAction.GetHostRewriteHeader(),
			AutoHostRewrite:         xdsRouteAction.GetAutoHostRewrite().GetValue(),
			RequestHeadersToAdd:     convertHeadersToAdd(xdsRoute.GetRequestHeadersToAdd()),
			RequestHeadersToRemove:  xdsRoute.GetRequestHeadersToRemove(),
			ResponseHeadersToAdd:    convertHeadersToAdd(xdsRoute.GetResponseHeadersToAdd()),
			ResponseHeadersToRemove: xdsRoute.GetResponseHeadersToRemove(),
		},
		MetadataMatch: convertMeta(xdsRouteAction.GetMetadataMatch()),
		Timeout:       ConvertDuration(xdsRouteAction.GetTimeout()),
	}
}

func convertHeadersToAdd(headerValueOption []*envoy_config_core_v3.HeaderValueOption) []*v2.HeaderValueOption {
	if len(headerValueOption) < 1 {
		return nil
	}
	valueOptions := make([]*v2.HeaderValueOption, 0, len(headerValueOption))
	for _, opt := range headerValueOption {
		var isAppend *bool
		if opt.Append != nil {
			appendVal := opt.GetAppend().GetValue()
			isAppend = &appendVal
		}
		valueOptions = append(valueOptions, &v2.HeaderValueOption{
			Header: &v2.HeaderValue{
				Key:   opt.GetHeader().GetKey(),
				Value: opt.GetHeader().GetValue(),
			},
			Append: isAppend,
		})
	}
	return valueOptions
}

func convertRegexRewrite(xdsRegexRewrite *envoy_type_matcher_v3.RegexMatchAndSubstitute) *v2.RegexRewrite {
	if xdsRegexRewrite == nil {
		return nil
	}
	return &v2.RegexRewrite{
		Pattern: v2.PatternConfig{
			Regex: xdsRegexRewrite.GetPattern().GetRegex(),
		},
		Substitution: xdsRegexRewrite.GetSubstitution(),
	}
}

func convertRetryPolicy(xdsRetryPolicy *envoy_config_route_v3.RetryPolicy) *v2.RetryPolicy {
	if xdsRetryPolicy == nil {
		return &v2.RetryPolicy{}
	}
	return &v2.RetryPolicy{
		RetryPolicyConfig: v2.RetryPolicyConfig{
			RetryOn:    len(xdsRetryPolicy.GetRetryOn()) > 0,
			NumRetries: xdsRetryPolicy.GetNumRetries().GetValue(),
		},
		RetryTimeout: ConvertDuration(xdsRetryPolicy.GetPerTryTimeout()),
	}
}

func convertRedirectAction(xdsRedirectAction *envoy_config_route_v3.RedirectAction) *v2.RedirectAction {
	if xdsRedirectAction == nil {
		return nil
	}
	return &v2.RedirectAction{
		SchemeRedirect: xdsRedirectAction.GetSchemeRedirect(),
		HostRedirect:   xdsRedirectAction.GetHostRedirect(),
		PathRedirect:   xdsRedirectAction.GetPathRedirect(),
		ResponseCode:   int(xdsRedirectAction.GetResponseCode()),
	}
}

func convertDirectResponseAction(xdsDirectResponseAction *envoy_config_route_v3.DirectResponseAction) *v2.DirectResponseAction {
	if xdsDirectResponseAction == nil {
		return nil
	}

	var body string
	if rawData := xdsDirectResponseAction.GetBody(); rawData != nil {
		body = rawData.GetInlineString()
	}

	return &v2.DirectResponseAction{
		StatusCode: int(xdsDirectResponseAction.GetStatus()),
		Body:       body,
	}
}

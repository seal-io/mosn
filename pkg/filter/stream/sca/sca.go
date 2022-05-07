//go:generate protoc --go_out=. --proto_path=. --go_opt=paths=source_relative sca.proto

package sca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	stdhttp "net/http"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"mosn.io/api"
	v2 "mosn.io/mosn/pkg/config/v2"
)

func ConvertAnyToGlobalConfig(anyInput *anypb.Any) (*ResourceGlobalConfig, error) {
	var c ResourceGlobalConfig
	var err = anypb.UnmarshalTo(anyInput, &c, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	err = c.Validate()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func ConvertMapToGlobalConfig(m map[string]interface{}) (*ResourceGlobalConfig, error) {
	if m == nil {
		return nil, errors.New("nil input map")
	}
	self, exit := m["@data"]
	if !exit {
		return nil, errors.New("cannot find '@data' ref")
	}
	y, ok := self.(*ResourceGlobalConfig)
	if !ok {
		return nil, errors.New("unexpected type")
	}
	return y, nil
}

func ConvertAnyToConfig(anyInput *anypb.Any) (*ResourceConfig, error) {
	var c ResourceConfig
	var err = anypb.UnmarshalTo(anyInput, &c, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	err = c.Validate()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func ExtractConfigFromRouteConfig(r api.Route) *ResourceConfig {
	if r == nil {
		return nil
	}
	var m = r.RouteRule().PerFilterConfig()
	if m == nil {
		return nil
	}
	var v, ok = m[v2.HTTP_SCA]
	if !ok {
		return nil
	}
	return v.(*ResourceConfig)
}

func (x *ResourceGlobalConfig) Validate() error {
	return nil
}

func (x *ResourceGlobalConfig) Encapsulate() map[string]interface{} {
	if x == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"@data": x,
	}
}

func (x *ResourceConfig) Validate() error {
	return nil
}

func (x *ResourceConfig) Encapsulate() map[string]interface{} {
	if x == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"@data": x,
	}
}

func (x *ResourceEvaluator) Evaluate(ctx context.Context, headers api.HeaderMap, input map[string]interface{}) error {
	if x.GetServer() == "" || input == nil {
		return nil
	}

	var reqBody, err = json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal http request body: %w", err)
	}

	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, x.GetServer(), bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	for _, k := range x.GetInheritHeader() {
		var v, exist = headers.Get(k)
		if !exist {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "sealio/mosn/v1.0.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if x.GetToken() != "" {
		req.Header.Set("Authorization", "Basic "+x.GetToken())
	}

	resp, err := stdhttp.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read http response body: %w", err)
	}

	var output = struct {
		Action    string `json:"action"`
		Message   string `json:"message"`
		ReportURL string `json:"reportURL"`
		Error     string `json:"error"` // internal interface error
	}{}
	err = json.Unmarshal(respContent, &output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal http respone body: %w", err)
	}
	if output.Action == "block" {
		var content = "the resource is blocked as: " + output.Message + ", for more information ref to " + output.ReportURL
		return HijackReplyError{
			StatusCode:    stdhttp.StatusForbidden,
			StatusMessage: "Quarantined Item: " + content,
			ContentType:   "text/plain",
			CauseContent:  content,
		}
	} else if resp.StatusCode != stdhttp.StatusOK {
		var content = output.Error
		if content == "" {
			content = string(respContent)
		}
		if content == "" {
			content = stdhttp.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("failed to evaluate as received code %d, body %s", resp.StatusCode, content)
	}
	return nil
}

//go:generate protoc --go_out=. --proto_path=. --go_opt=paths=source_relative sca.proto

package sca

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	stdhttp "net/http"
	"time"

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

var evaluateIncompleteError = errors.New("incomplete evaluation")

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

	var cli = &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// need more detail to evaluate
	if resp.StatusCode == stdhttp.StatusPreconditionRequired {
		return evaluateIncompleteError
	}
	respContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read http response body: %w", err)
	}
	var output = struct {
		Action    string `json:"action"`
		Message   string `json:"message"`
		ReportURL string `json:"reportURL"`
		Code      string `json:"code"`
	}{}
	err = json.Unmarshal(respContent, &output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal http respone body: %w", err)
	}
	// unexpected error
	if resp.StatusCode != stdhttp.StatusOK {
		var content = output.Message
		if content == "" {
			content = string(respContent)
		}
		if content == "" {
			content = output.Code
		}
		if content == "" {
			content = stdhttp.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("failed to evaluate as received code %d, body %s", resp.StatusCode, content)
	}
	// block
	if output.Action == "block" {
		var content = "The resource is blocked. Reason: " + output.Message + ". For more information, please refer to " + output.ReportURL
		return HijackReplyError{
			StatusCode:    stdhttp.StatusForbidden,
			StatusMessage: "Quarantined Item: " + content,
			ContentType:   "text/plain",
			CauseContent:  content,
		}
	}
	// allow
	return nil
}

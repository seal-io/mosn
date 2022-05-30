//go:generate protoc --go_out=. --proto_path=. --go_opt=paths=source_relative sca.proto

package sca

import (
	"bytes"
	"context"
	"crypto/tls"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	stdhttp "net/http"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"mosn.io/api"

	v2 "mosn.io/mosn/pkg/config/v2"
)

func ConvertAnyToGlobalConfig(anyInput *anypb.Any) (*GlobalConfig, error) {
	var c GlobalConfig
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

func ConvertMapToGlobalConfig(m map[string]interface{}) (*GlobalConfig, error) {
	if m == nil {
		return nil, errors.New("nil input map")
	}
	self, exit := m["@data"]
	if !exit {
		return nil, errors.New("cannot find '@data' ref")
	}
	y, ok := self.(*GlobalConfig)
	if !ok {
		return nil, errors.New("unexpected type")
	}
	return y, nil
}

func ConvertAnyToConfig(anyInput *anypb.Any) (*Config, error) {
	var c Config
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

func ExtractConfigFromRouteConfig(r api.Route) *Config {
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
	return v.(*Config)
}

func (x *GlobalConfig) Validate() error {
	return nil
}

func (x *GlobalConfig) Encapsulate() map[string]interface{} {
	if x == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"@data": x,
	}
}

func (x *Config) Validate() error {
	return nil
}

func (x *Config) Encapsulate() map[string]interface{} {
	if x == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"@data": x,
	}
}

var evaluateIncompleteError = errors.New("incomplete evaluation")

type EvaluateInput struct {
	EventType string             `json:"eventType"`
	Checksum  string             `json:"checksum,omitempty"`
	SBOM      stdjson.RawMessage `json:"sbom,omitempty"`
	ExtraArgs map[string]string  `json:"-"`
}

func (in EvaluateInput) MarshalJSON() ([]byte, error) {
	type evaluateInput EvaluateInput
	var bs, err = json.Marshal(evaluateInput(in))
	if err != nil {
		return nil, err
	}

	var m map[string]stdjson.RawMessage
	err = json.Unmarshal(bs, &m)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling to map: %w", err)
	}
	for k, v := range in.ExtraArgs {
		m[k] = stdjson.RawMessage(`"` + v + `"`)
	}

	return json.Marshal(m)
}

func (x *Evaluator) Evaluate(ctx context.Context, headers api.HeaderMap, input *EvaluateInput) error {
	if x.GetServer() == "" || input == nil {
		return nil
	}
	if input.Checksum == "" && len(input.SBOM) == 0 {
		return evaluateIncompleteError
	}

	var reqBody, err = json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal http request body: %w", err)
	}

	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, x.GetServer(), bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	for _, k := range x.GetRequestInheritHeaders() {
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
				InsecureSkipVerify: x.GetRequestInsecure(),
			},
		},
		Timeout: x.GetRequestTimeout().AsDuration(),
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

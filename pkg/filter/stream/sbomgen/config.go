package sbomgen

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"mosn.io/api"
	"mosn.io/mosn/pkg/variable"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func ConvertAnyToFilterConfig(in *anypb.Any) (*FilterConfig, error) {
	if in == nil {
		return nil, nil
	}

	var cs structpb.Struct
	err := anypb.UnmarshalTo(in, &cs, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	b, err := cs.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var c FilterConfig
	if err = json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func ConfigFromMap(m map[string]interface{}) FilterConfig {
	var r FilterConfig
	r.FromMap(m)
	return r
}

type FilterConfig struct {
	Kind              string                `json:"kind"`
	Name              string                `json:"name"`
	Validator         FilterConfigValidator `json:"validate"`
	SenderSelectors   FilterConfigSelectors `json:"pullWith"`
	ReceiverSelectors FilterConfigSelectors `json:"pushWith"`
}

func (in *FilterConfig) FromMap(m map[string]interface{}) {
	if in == nil || m == nil {
		return
	}
	in.Kind = getString(m, "kind")
	in.Name = getString(m, "name")
	in.Validator = getFilterConfigValidator(m, "validate")
	in.SenderSelectors = getFilterConfigSelectors(m, "pullWith")
	in.ReceiverSelectors = getFilterConfigSelectors(m, "pushWith")
}

func (in *FilterConfig) AsMap() map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"kind":     in.Kind,
		"name":     in.Name,
		"validate": in.Validator,
		"pullWith": in.SenderSelectors,
		"pushWith": in.ReceiverSelectors,
	}
}

type FilterConfigValidator struct {
	Endpoint         string            `json:"endpoint"`
	Token            string            `json:"token"`
	HeadersAsInherit []string          `json:"headersAsInherit"`
	HeadersAsInput   map[string]string `json:"headersAsInput"`
}

func (in FilterConfigValidator) Validate(ctx context.Context, headers api.HeaderMap, eventType string, sbom stdjson.RawMessage) error {
	if in.Endpoint == "" {
		return errValidationEmptyEndpoint
	}

	var input = map[string]interface{}{
		"eventType": eventType,
		"sbom":      sbom,
	}
	for k, ka := range in.HeadersAsInput {
		var v, exist = headers.Get(k)
		if !exist {
			continue
		}
		input[ka] = v
	}
	var reqBody, err = json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal http request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	for _, k := range in.HeadersAsInherit {
		var v, exist = headers.Get(k)
		if !exist {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "sealio/mosn/v1.0.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+in.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var output = struct {
		Action    string `json:"action"`
		Message   string `json:"message"`
		ReportURL string `json:"reportURL"`
	}{
		Action: "block",
	}
	err = json.NewDecoder(resp.Body).Decode(&output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal http respone body: %w", err)
	}

	if output.Action == "block" {
		return &validationBlockError{
			message:    output.Message,
			requestURL: output.ReportURL,
		}
	}
	return nil
}

type FilterConfigSelectors []FilterConfigSelector

func (in FilterConfigSelectors) MatchAll(ctx context.Context, headers api.HeaderMap) bool {
	if len(in) == 0 {
		return false
	}

	for i := range in {
		s := &in[i]
		av, err := variable.GetString(ctx, s.Name)
		if err != nil {
			var exist bool
			av, exist = headers.Get(s.Name)
			if !exist {
				return false
			}
		}
		if !s.MatchAny(av) {
			return false
		}
	}
	return true
}

type FilterConfigSelector struct {
	// Name indicates the name of request/response header.
	Name string `json:"name"`

	// Matchers indicates the matcher of request/response.
	Matchers []FilterConfigMatcher `json:"matchers"`
}

func (s *FilterConfigSelector) MatchAny(av string) bool {
	if s == nil {
		return false
	}

	for j := range s.Matchers {
		ev := s.Matchers[j]
		if ev.Match(av) {
			return true
		}
	}
	return false
}

// FilterConfigMatcher using some specified prefixes to guide the filter processing:
// - #:*,  case-insensitive contain the * value
// - ?:*,  regex match the * value
// - $:*,  suffix match the * value
// - ^:*,  prefix match the * value
// -   *,  exact match the * value
type FilterConfigMatcher string

func (in FilterConfigMatcher) Match(out string) bool {
	if len(in) > 2 {
		switch in[:2] {
		case "#:":
			return strings.Contains(strings.ToLower(out), string(in[2:]))
		case "?:":
			var r, _ = regexp.MatchString(string(in[2:]), out)
			return r
		case "$:":
			return strings.HasSuffix(out, string(in[2:]))
		case "^:":
			return strings.HasPrefix(out, string(in[2:]))
		}
	}
	return out == string(in)
}

func getString(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		return v.(string)
	}
	return ""
}

func getFilterConfigValidator(m map[string]interface{}, k string) FilterConfigValidator {
	if v, ok := m[k]; ok {
		return v.(FilterConfigValidator)
	}
	return FilterConfigValidator{}
}

func getFilterConfigSelectors(m map[string]interface{}, k string) FilterConfigSelectors {
	if v, ok := m[k]; ok {
		return v.(FilterConfigSelectors)
	}
	return FilterConfigSelectors{}
}

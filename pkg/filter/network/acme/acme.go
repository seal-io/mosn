//go:generate protoc --go_out=. --proto_path=. --go_opt=paths=source_relative acme.proto

package acme

import (
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func ConvertAnyToGlobalConfig(anyInput *anypb.Any) (*ResourceGlobalConfig, error) {
	var c ResourceGlobalConfig
	var err = anypb.UnmarshalTo(anyInput, &c, proto.UnmarshalOptions{})
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

func (x *ResourceGlobalConfig) Encapsulate() map[string]interface{} {
	if x == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"@data": x,
	}
}

const (
	defaultChallengeTimeout  = 60 * time.Second
	defaultChallengeInterval = 2 * time.Second
)

func (x *ResourceGlobalConfig) GetChallengeTimer() (timeout, interval time.Duration) {
	timeout = defaultChallengeTimeout
	interval = defaultChallengeInterval
	if v := x.GetChallengeTimeout(); v != nil {
		if d := v.AsDuration(); d > timeout {
			timeout = d
		}
	}
	if v := x.GetChallengeInterval(); v != nil {
		if d := v.AsDuration(); timeout > d && d > interval {
			interval = d
		}
	}
	return
}

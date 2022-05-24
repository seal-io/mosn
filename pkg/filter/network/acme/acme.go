//go:generate protoc --go_out=. --proto_path=. --go_opt=paths=source_relative acme.proto

package acme

import (
	"errors"
	"reflect"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func ConvertAnyToGlobalConfig(anyInput *anypb.Any) (*GlobalConfig, error) {
	var c GlobalConfig
	var err = anypb.UnmarshalTo(anyInput, &c, proto.UnmarshalOptions{})
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

func (x *GlobalConfig) Encapsulate() map[string]interface{} {
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

func (x *GlobalConfig) GetChallengeTimer() (timeout, interval time.Duration) {
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

func (x *GlobalConfig) Equal(y *GlobalConfig) bool {
	// left.GetListenerName() == y.GetListenerName() is excluded.
	return x.GetAuthEmail() == y.GetAuthEmail() &&
		reflect.DeepEqual(x.GetAuthSignKey(), y.GetAuthSignKey()) &&
		reflect.DeepEqual(x.GetCertDomains(), y.GetCertDomains()) &&
		reflect.DeepEqual(x.GetCertPrivateKey(), y.GetCertPrivateKey()) &&
		x.GetCertCaDirectory() == y.GetCertCaDirectory() &&
		x.GetChallengeTimeout().AsDuration() == y.GetChallengeTimeout().AsDuration() &&
		x.GetChallengeInterval().AsDuration() == y.GetChallengeInterval().AsDuration() &&
		reflect.DeepEqual(x.GetDnsNameservers(), y.GetDnsNameservers()) &&
		x.GetDnsTimeout().AsDuration() == y.GetDnsTimeout().AsDuration() &&
		x.GetDnsDisableCompletePropagation() == y.GetDnsDisableCompletePropagation()
}

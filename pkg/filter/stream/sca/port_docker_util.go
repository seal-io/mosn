package sca

import (
	stdjson "encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"strings"
)

// dockerPackageDescriptor holds the descriptor of a docker image.
type dockerPackageDescriptor struct {
	checksumAlgorithm string
	checksum          string

	path       string
	repository string
	namespace  string
	name       string
	tag        string

	rawManifest stdjson.RawMessage
}

// getName returns the name of the docker image.
func (s dockerPackageDescriptor) getName() string {
	var sb strings.Builder
	if s.repository != "registry-1.docker.io" && s.repository != "docker.io" {
		sb.WriteString(s.repository)
		sb.WriteString("/")
	}
	if s.namespace == "library" && sb.Len() != 0 ||
		s.namespace != "library" {
		sb.WriteString(s.namespace)
		sb.WriteString("/")
	}
	sb.WriteString(s.name)
	sb.WriteString("@")
	sb.WriteString(s.tag)
	return sb.String()
}

// getChecksum returns the checksum within type and algorithm,
// it might be blank if it does not have a checksum.
func (s dockerPackageDescriptor) getChecksum() string {
	if len(s.checksum) < 3 {
		return ""
	}
	return "/docker/" + s.checksumAlgorithm + "/" + s.checksum[:2] + "/" + s.checksum
}

// dockerResponseErrorWrap wraps error in docker reply, ref to
// https://github.com/distribution/distribution/blob/main/registry/api/errcode/register.go.
func dockerResponseErrorWrap(causeErr error) error {
	if causeErr == nil {
		return nil
	}

	var (
		statusCode = stdhttp.StatusInternalServerError
		code       = "UNKNOWN"
		message    = "unexpected upstream error"
	)

	var re HijackReplyError
	if errors.As(causeErr, &re) {
		if re.StatusCode == stdhttp.StatusForbidden {
			statusCode = stdhttp.StatusForbidden
			code = "UNAUTHORIZED"
			message = re.CauseContent
		}
	}
	return HijackReplyError{
		StatusCode:    statusCode,
		StatusMessage: stdhttp.StatusText(statusCode),
		ContentType:   "application/json",
		CauseError:    causeErr,
		CauseContent:  fmt.Sprintf(`{"errors":[{"code":"%s","message":"%v"}]}`, code, message),
	}
}

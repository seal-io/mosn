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
	ChecksumAlgorithm string
	Checksum          string

	Path       string
	Repository string
	Namespace  string
	Name       string
	Tag        string

	RawManifest stdjson.RawMessage
}

// getName returns the name of the docker image.
func (s dockerPackageDescriptor) getName() string {
	var sb strings.Builder
	if s.Repository != "registry-1.docker.io" && s.Repository != "docker.io" {
		sb.WriteString(s.Repository)
		sb.WriteString("/")
	}
	if s.Namespace == "library" && sb.Len() != 0 ||
		s.Namespace != "library" {
		sb.WriteString(s.Namespace)
		sb.WriteString("/")
	}
	sb.WriteString(s.Name)
	sb.WriteString("@")
	sb.WriteString(s.Tag)
	return sb.String()
}

// getChecksum returns the checksum within type and algorithm,
// it might be blank if it does not have a checksum.
func (s dockerPackageDescriptor) getChecksum() string {
	if len(s.Checksum) < 3 {
		return ""
	}
	return "/docker/" + s.ChecksumAlgorithm + "/" + s.Checksum[:2] + "/" + s.Checksum
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

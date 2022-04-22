package sca

import (
	"errors"
	"fmt"
	stdhttp "net/http"
)

type HijackReplyErrorBodyParser func() string

func (x HijackReplyErrorBodyParser) String() string {
	return x()
}

type HijackReplyError struct {
	StatusCode    int
	StatusMessage string
	ContentType   string
	CauseError    error
	CauseContent  string
}

func (x HijackReplyError) Error() string {
	if x.CauseError != nil { // show cause error at first
		return x.CauseError.Error()
	}
	return x.CauseContent
}

func (x HijackReplyError) Content() string {
	if x.CauseContent != "" { // show cause content at first
		return x.CauseContent
	}
	return x.Error()
}

// EncodeDockerReplyError encodes error in docker reply, ref to
// https://github.com/distribution/distribution/blob/main/registry/api/errcode/register.go.
func EncodeDockerReplyError(causeErr error) error {
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

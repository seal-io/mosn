package sca

import (
	"context"
	"errors"
	stdhttp "net/http"

	"github.com/valyala/fasthttp"
	"mosn.io/api"
	"mosn.io/pkg/protocol/http"

	"mosn.io/mosn/pkg/protocol"
)

type StreamDualFilter interface {
	api.StreamSenderFilter
	api.StreamReceiverFilter
}

type bridge struct {
	receiveHandler api.StreamReceiverFilterHandler
	sendHandler    api.StreamSenderFilterHandler
}

func (x *bridge) OnDestroy() {}

func (x *bridge) Append(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	return api.StreamFilterContinue
}

func (x *bridge) SetSenderFilterHandler(handler api.StreamSenderFilterHandler) {
	x.sendHandler = handler
}

func (x *bridge) OnReceive(ctx context.Context, headers api.HeaderMap, buf api.IoBuffer, trailers api.HeaderMap) api.StreamFilterStatus {
	return api.StreamFilterContinue
}

func (x *bridge) SetReceiveFilterHandler(handler api.StreamReceiverFilterHandler) {
	x.receiveHandler = handler
}

func (x *bridge) SendHijackReplyError(err error) {
	var cre CausedHijackReplyError
	if errors.As(err, &cre) {
		x.SendHijackReplyWithBody(cre.StatusCode, cre.StatusMessage, cre.ContentType, cre.Content())
		return
	}
	var re HijackReplyError
	if errors.As(err, &re) {
		x.SendHijackReplyWithBody(re.StatusCode, re.StatusMessage, re.ContentType, re.Error())
		return
	}
	x.SendHijackReplyWithBody(0, "", "", "")
}

func (x *bridge) SendHijackReplyWithBody(statusCode int, statusMessage string, contentType, content string) {
	var headers = http.ResponseHeader{ResponseHeader: &fasthttp.ResponseHeader{}}
	if statusCode == 0 {
		statusCode = stdhttp.StatusInternalServerError
	}
	if statusMessage != "" {
		// NB(thxCode): immediate net proxies might be able to clean this irregular message.
		switch x.receiveHandler.RequestInfo().Protocol() {
		case protocol.HTTP1:
			headers.SetStatusMessage([]byte(statusMessage))
		case protocol.HTTP2:
			headers.Set(":status", statusMessage)
		}
	}
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	if content == "" {
		x.receiveHandler.SendHijackReply(statusCode, headers)
	} else {
		x.receiveHandler.SendHijackReplyWithBody(statusCode, headers, content)
	}
}

type HijackReplyError struct {
	StatusCode    int
	StatusMessage string
	ContentType   string
	CauseContent  string
}

func (x HijackReplyError) Error() string {
	return x.CauseContent
}

type CausedHijackReplyError struct {
	HijackReplyError

	CauseError error
}

func (x CausedHijackReplyError) Error() string {
	if x.CauseError != nil { // show cause error at first
		return x.CauseError.Error()
	}
	return x.CauseContent
}

func (x CausedHijackReplyError) Content() string {
	if x.CauseContent != "" { // show cause content at first
		return x.CauseContent
	}
	return x.Error()
}

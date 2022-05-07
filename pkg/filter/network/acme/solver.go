package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"mosn.io/api"
	"mosn.io/pkg/buffer"

	"mosn.io/mosn/pkg/log"
)

func NewSolver(globalCtx context.Context, chag *challenger) api.ReadFilter {
	return &solver{
		globalCtx:  globalCtx,
		challenger: chag,
	}
}

type solver struct {
	globalCtx  context.Context
	challenger *challenger

	readCallbacks api.ReadFilterCallbacks
}

func (x *solver) OnData(reqBuf api.IoBuffer) api.FilterStatus {
	defer func() {
		reqBuf.Drain(reqBuf.Len())
		_ = x.readCallbacks.Connection().Close(api.FlushWrite, api.RemoteClose)
	}()

	var fqdn, value = x.challenger.GetChallengeInfo()
	var query = &dnsmessage.Message{}
	var err = query.Unpack(reqBuf.Bytes())
	if err != nil {
		log.Proxy.Errorf(x.globalCtx, "error unpacking query message: %v", err)
		return api.Stop
	}
	if len(query.Questions) != 1 {
		log.Proxy.Errorf(x.globalCtx, "expected one question but got %d", len(query.Questions))
		return api.Stop
	}

	var question = query.Questions[0]
	var questionName = strings.ToLower(question.Name.String())
	if !strings.HasPrefix(fqdn, questionName) {
		log.Proxy.Errorf(x.globalCtx, "expected fqdn %s but got %s",
			fqdn, questionName)
		return api.Stop
	}

	var replyBody dnsmessage.ResourceBody
	switch question.Type {
	case dnsmessage.TypeNS:
		replyBody, err = constructNSReply(fqdn)
	case dnsmessage.TypeSOA:
		replyBody, err = constructSOAReply(fqdn, x.challenger.GetEmail())
	case dnsmessage.TypeTXT:
		replyBody, err = constructTXTReply(value)
	default:
		err = fmt.Errorf("invalid question: %s", question.GoString())
	}
	if err != nil {
		log.Proxy.Errorf(x.globalCtx, "error constructing %s reply: %v",
			query.Questions[0].Type, err)
		return api.Stop
	}

	var reply = &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               query.ID,
			Response:         true,
			Authoritative:    true,
			RecursionDesired: query.RecursionDesired,
		},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  question.Type,
				Class: question.Class,
				TTL:   60,
			},
			Body: replyBody,
		}},
	}
	replyRaw, err := reply.Pack()
	if err != nil {
		log.Proxy.Errorf(x.globalCtx, "error packing reply message: %v", err)
		return api.Stop
	}
	err = x.readCallbacks.Connection().Write(buffer.NewIoBufferBytes(replyRaw))
	if err != nil {
		log.Proxy.Errorf(x.globalCtx, "error writing reply message: %v", err)
		return api.Stop
	}

	return api.Stop
}

func (x *solver) OnNewConnection() api.FilterStatus {
	if !x.challenger.IsPresentPhase() {
		return api.Stop
	}
	return api.Continue
}

func (x *solver) InitializeReadFilterCallbacks(cb api.ReadFilterCallbacks) {
	x.readCallbacks = cb
	x.readCallbacks.Connection().SetReadDisable(false)
}

func constructSOAReply(fqdn, email string) (dnsmessage.ResourceBody, error) {
	nsName, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("failed to create ns name: %w", err)
	}
	emailName, err := func() (dnsmessage.Name, error) {
		var v = email
		var vs = strings.SplitN(v, "@", 2)
		v = strings.ReplaceAll(vs[0], `.`, `\`)
		if len(vs) == 2 {
			v = v + "." + vs[1]
		}
		v = v + "."
		return dnsmessage.NewName(v)
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to create email name: %w", err)
	}

	return &dnsmessage.SOAResource{
		NS:      nsName,
		MBox:    emailName,
		Serial:  uint32(time.Now().Unix()),
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  180,
	}, nil
}

func constructNSReply(fqdn string) (dnsmessage.ResourceBody, error) {
	var nsName, err = func() (dnsmessage.Name, error) {
		var vs = strings.SplitN(fqdn, ".", 2)
		return dnsmessage.NewName(vs[len(vs)-1])
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to create ns name: %w", err)
	}

	return &dnsmessage.NSResource{
		NS: nsName,
	}, nil
}

func constructTXTReply(value string) (dnsmessage.ResourceBody, error) {
	return &dnsmessage.TXTResource{
		TXT: []string{value},
	}, nil
}

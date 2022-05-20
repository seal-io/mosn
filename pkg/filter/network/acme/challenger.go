package acme

import (
	"context"
	"crypto"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/atomic"

	"mosn.io/mosn/pkg/log"
)

const (
	challengingStart uint64 = iota + 1
	challengingPresent
	challengingCleanUp
	challengingStop
	challengingClose
)

func newChallenger(rctx context.Context, cfg *ResourceGlobalConfig) (*challenger, error) {
	var opts []dns01.ChallengeOption
	if v := cfg.GetDnsNameservers(); len(v) != 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(v))
	}
	if v := cfg.GetDnsTimeout(); v != nil {
		if d := v.AsDuration(); d > 10*time.Second {
			opts = append(opts, dns01.AddDNSTimeout(d))
		}
	}
	if cfg.GetDnsDisableCompletePropagation() {
		opts = append(opts, dns01.DisableCompletePropagationRequirement())
	}

	var err error

	var authSignKey crypto.PrivateKey
	if v := cfg.GetAuthSignKey(); len(v) != 0 {
		authSignKey, err = certcrypto.ParsePEMPrivateKey(v)
		if err != nil {
			return nil, fmt.Errorf("invalid pass-in auth sign key: %w", err)
		}
	} else {
		authSignKey, err = certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("invalid auto-gen auth sign key: %w", err)
		}
	}

	var certPriKey crypto.PrivateKey
	if v := cfg.GetCertPrivateKey(); len(v) != 0 {
		certPriKey, err = certcrypto.ParsePEMPrivateKey(v)
		if err != nil {
			return nil, fmt.Errorf("invalid pass-in cert private key: %w", err)
		}
	}

	var ctx, cancel = context.WithCancel(rctx)
	var chag = &challenger{
		ctx:         ctx,
		cancel:      cancel,
		cfg:         cfg,
		phase:       atomic.NewUint64(0),
		opts:        opts,
		authSignKey: authSignKey,
		certPriKey:  certPriKey,
	}

	return chag, nil
}

type challenger struct {
	ctx         context.Context
	cancel      context.CancelFunc
	cfg         *ResourceGlobalConfig
	phase       *atomic.Uint64
	opts        []dns01.ChallengeOption
	authSignKey crypto.PrivateKey
	certPriKey  crypto.PrivateKey

	// user info
	authResource *registration.Resource

	// challenge info
	fqdn  string
	value string

	// certificate info
	certLock     sync.RWMutex
	certResource *certificate.Resource
	certHandle   func(certChain, privateKey []byte)
}

func (x *challenger) GetEmail() string {
	return x.cfg.GetAuthEmail()
}

func (x *challenger) GetPrivateKey() crypto.PrivateKey {
	return x.authSignKey
}

func (x *challenger) GetRegistration() *registration.Resource {
	return x.authResource
}

func (x *challenger) Present(domain, token, keyAuth string) error {
	x.fqdn, x.value = dns01.GetRecord(domain, keyAuth)
	x.phase.Store(challengingPresent)
	return nil
}

func (x *challenger) CleanUp(domain, token, keyAuth string) error {
	x.phase.Store(challengingCleanUp)
	x.fqdn, x.value = "", ""
	return nil
}

func (x *challenger) Timeout() (timeout, interval time.Duration) {
	return x.cfg.GetChallengeTimer()
}

func (x *challenger) IsPresentPhase() bool {
	return x.phase.CAS(challengingPresent, challengingPresent)
}

func (x *challenger) GetChallengeInfo() (fqdn, value string) {
	return x.fqdn, x.value
}

func (x *challenger) SetCertificateHandler(handle func(certChain, privateKey []byte)) {
	var cert = x.getCertificate()
	if cert != nil {
		handle(cert.Certificate, cert.PrivateKey)
	}
	x.certLock.Lock()
	x.certHandle = handle
	x.certLock.Unlock()
}

func (x *challenger) setCertificate(cert *certificate.Resource) {
	var certPriKey, _ = certcrypto.ParsePEMPrivateKey(cert.PrivateKey)
	x.certLock.Lock()
	x.certResource = cert
	x.certPriKey = certPriKey
	if x.certHandle != nil {
		x.certHandle(cert.Certificate, cert.PrivateKey)
	}
	x.certLock.Unlock()
}

func (x *challenger) getCertificate() *certificate.Resource {
	x.certLock.RLock()
	defer x.certLock.RUnlock()
	return x.certResource
}

func (x *challenger) runChallenge() {
	var timer = time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-x.ctx.Done():
			return
		default:
		}

		x.doChallenge()

		var cert = x.getCertificate()
		if cert != nil {
			var x509Crt, err = certcrypto.ParsePEMCertificate(cert.Certificate)
			if err != nil {
				log.DefaultLogger.Errorf("error parsing certificate: %v", err)
				break
			}
			var deadline = time.Now().Add(7 * 24 * time.Hour)
			timer.Reset(x509Crt.NotAfter.Sub(deadline))
		}

		select {
		case <-x.ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (x *challenger) doChallenge() {
	x.phase.Store(challengingStart)
	defer x.phase.Store(challengingStop)

	var cli, err = x.getClient(x.cfg.GetCertCaDirectory())
	if err != nil {
		log.DefaultLogger.Errorf("error getting challenging client: %v", err)
		return
	}
	err = cli.Challenge.SetDNS01Provider(x, x.opts...)
	if err != nil {
		log.DefaultLogger.Errorf("error setting DNS-01 challenge provider: %v", err)
		return
	}
	var req = certificate.ObtainRequest{
		Domains:    x.cfg.GetCertDomains(),
		PrivateKey: x.certPriKey,
		Bundle:     true,
	}
	cert, err := cli.Certificate.Obtain(req)
	if err != nil {
		log.DefaultLogger.Errorf("error obtaining DNS-01 challenge certificate: %v", err)
		return
	}
	x.setCertificate(cert)
}

func (x *challenger) closeChallenge() {
	x.phase.Store(challengingClose)
	x.cancel()
}

func (x *challenger) equalConfig(newCfg *ResourceGlobalConfig) bool {
	var left, right = x.cfg, newCfg
	// left.GetListenerName() == right.GetListenerName() is excluded.
	return left.GetAuthEmail() == right.GetAuthEmail() &&
		reflect.DeepEqual(left.GetAuthSignKey(), right.GetAuthSignKey()) &&
		reflect.DeepEqual(left.GetCertDomains(), right.GetCertDomains()) &&
		reflect.DeepEqual(left.GetCertPrivateKey(), right.GetCertPrivateKey()) &&
		left.GetCertCaDirectory() == right.GetCertCaDirectory() &&
		left.GetChallengeTimeout().AsDuration() == right.GetChallengeTimeout().AsDuration() &&
		left.GetChallengeInterval().AsDuration() == right.GetChallengeInterval().AsDuration() &&
		reflect.DeepEqual(left.GetDnsNameservers(), right.GetDnsNameservers()) &&
		left.GetDnsTimeout().AsDuration() == right.GetDnsTimeout().AsDuration() &&
		left.GetDnsDisableCompletePropagation() == right.GetDnsDisableCompletePropagation()
}

func (x *challenger) register() error {
	cli, err := x.getClient(x.cfg.GetCertCaDirectory())
	if err != nil {
		return fmt.Errorf("error getting challenging client: %v", err)
	}
	var regOption = registration.RegisterOptions{TermsOfServiceAgreed: true}
	res, err := cli.Registration.Register(regOption)
	if err != nil {
		return fmt.Errorf("error doing registration: %v", err)
	}
	x.authResource = res
	return nil
}

func (x *challenger) getClient(certCADirectory string) (*lego.Client, error) {
	var config = lego.NewConfig(x)
	config.UserAgent = "sealio/mosn/v1.0.0"
	if certCADirectory != "" {
		config.CADirURL = certCADirectory
	}
	return lego.NewClient(config)
}

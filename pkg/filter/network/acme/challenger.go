package acme

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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
	challengingStart uint64 = iota
	challengingPresent
	challengingCleanUp
	challengingStop
	challengingClose
)

func newChallenger(rctx context.Context, cfg *GlobalConfig) (*challenger, error) {
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

	if v := cfg.GetCertDomains(); len(v) == 0 {
		return nil, errors.New("empty domains is not supported")
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
		phase:       atomic.NewUint64(challengingStop),
		opts:        opts,
		authSignKey: authSignKey,
		certPriKey:  certPriKey,
	}

	return chag, nil
}

type challenger struct {
	sync.Once

	ctx         context.Context
	cancel      context.CancelFunc
	cfg         *GlobalConfig
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
	x.certLock.Lock()
	x.certResource = cert
	if x.cfg.GetCertPrivateKey() == nil {
		x.certPriKey, _ = certcrypto.ParsePEMPrivateKey(cert.PrivateKey)
	}
	if x.certHandle != nil {
		x.certHandle(cert.Certificate, cert.PrivateKey)
	}
	x.certLock.Unlock()

	x.saveCert(cert)
}

func (x *challenger) getCertificate() *certificate.Resource {
	x.loadCertOnce()

	x.certLock.RLock()
	var res = x.certResource
	x.certLock.RUnlock()
	return res
}

func (x *challenger) runChallenge() {
	var d = 2 * time.Second

	var cert = x.getCertificate()
	if cert != nil {
		var x509Crt, err = certcrypto.ParsePEMCertificate(cert.Certificate)
		if err != nil {
			log.DefaultLogger.Errorf("error parsing certificate: %v", err)
		} else {
			var deadline = time.Now().Add(7 * 24 * time.Hour)
			var next = x509Crt.NotAfter.Sub(deadline)
			if next > 0 {
				log.DefaultLogger.Infof("next time challenge is %v", deadline.Add(next).Format(time.RFC3339))
				d = next
			}
		}
	}

	var timer = time.NewTimer(d)
	defer timer.Stop()

	for {
		select {
		case <-x.ctx.Done():
			return
		case <-timer.C:
		}

		var err error
		d = 2 * time.Second
		cert, err = x.doChallenge()
		if err == nil {
			var x509Crt, err = certcrypto.ParsePEMCertificate(cert.Certificate)
			if err != nil {
				log.DefaultLogger.Errorf("error parsing certificate: %v", err)
				continue
			}
			var deadline = time.Now().Add(7 * 24 * time.Hour)
			var next = x509Crt.NotAfter.Sub(deadline)
			if next > 0 {
				log.DefaultLogger.Infof("next time challenge is %v", deadline.Add(next).Format(time.RFC3339))
				d = next
			}
		}
		timer.Reset(d)

		select {
		case <-x.ctx.Done():
			return
		default:
		}
	}
}

func (x *challenger) doChallenge() (*certificate.Resource, error) {
	x.phase.Store(challengingStart)
	defer x.phase.Store(challengingStop)

	var err = x.register()
	if err != nil {
		var cert = x.getCertificate()
		if cert != nil {
			// use previous certificate.
			return cert, nil
		}
		log.DefaultLogger.Errorf("error registering user %s: %v", x.GetEmail(), err)
		return nil, err
	}

	cli, err := x.getClient(x.cfg.GetCertCaDirectory())
	if err != nil {
		log.DefaultLogger.Errorf("error getting challenging client: %v", err)
		return nil, err
	}
	err = cli.Challenge.SetDNS01Provider(x, x.opts...)
	if err != nil {
		log.DefaultLogger.Errorf("error setting DNS-01 challenge provider: %v", err)
		return nil, err
	}
	var req = certificate.ObtainRequest{
		Domains:    x.cfg.GetCertDomains(),
		PrivateKey: x.certPriKey,
		Bundle:     true,
	}
	cert, err := cli.Certificate.Obtain(req)
	if err != nil {
		log.DefaultLogger.Errorf("error obtaining DNS-01 challenge certificate: %v", err)
		return nil, err
	}
	x.setCertificate(cert)
	return cert, nil
}

func (x *challenger) closeChallenge() {
	x.phase.Store(challengingClose)
	x.cancel()
}

func (x *challenger) equalConfig(newCfg *GlobalConfig) bool {
	return x.cfg.Equal(newCfg)
}

func (x *challenger) register() error {
	if x.authResource != nil {
		return nil
	}
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

func (x *challenger) saveCert(cert *certificate.Resource) {
	if s := x.cfg.GetCertStorage().GetPath(); s != nil {
		var err = saveCertificateToPath(s.GetPath(), x.cfg.GetCertDomains()[0], *cert)
		if err != nil {
			log.DefaultLogger.Errorf("error saving certificate: %v", err)
		}
	}
}

func (x *challenger) loadCertOnce() {
	x.Once.Do(func() {
		if s := x.cfg.GetCertStorage().GetPath(); s != nil {
			x.certLock.Lock()
			var v, err = loadCertificateFromPath(s.GetPath(), x.cfg.GetCertDomains()[0])
			if err != nil {
				x.certLock.Unlock()
				log.DefaultLogger.Errorf("error loading certificate: %v", err)
				return
			}
			x.certResource = &v
			if x.cfg.GetCertPrivateKey() == nil {
				x.certPriKey, _ = certcrypto.ParsePEMPrivateKey(v.PrivateKey)
			}
			x.certLock.Unlock()
		}
	})
}

func loadCertificateFromPath(path, domain string) (certRes certificate.Resource, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	certResBytes, err := readBytes(filepath.Join(path, "proxy", domain, "certificate.res"))
	if err != nil {
		return
	}
	err = json.Unmarshal(certResBytes, &certRes)
	if err != nil {
		return
	}

	certRes.Certificate, err = readBytes(filepath.Join(path, "proxy", domain, "certificate.crt"))
	if err != nil {
		return
	}

	certRes.PrivateKey, err = readBytes(filepath.Join(path, "proxy", domain, "certificate.key"))
	return
}

func saveCertificateToPath(path, domain string, certRes certificate.Resource) (err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	certResBytes, err := json.Marshal(certRes)
	if err != nil {
		return
	}

	err = writeBytes(filepath.Join(path, "proxy", domain, "certificate.res"), certResBytes)
	if err != nil {
		return
	}

	err = writeBytes(filepath.Join(path, "proxy", domain, "certificate.crt"), certRes.Certificate)
	if err != nil {
		return
	}

	err = writeBytes(filepath.Join(path, "proxy", domain, "certificate.key"), certRes.PrivateKey)
	return
}

func readBytes(path string) ([]byte, error) {
	var bs, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", path, err)
	}
	return bs, nil
}

func writeBytes(path string, bs []byte) error {
	var dir = filepath.Dir(path)
	var err = os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("error creating directory %s: %w", dir, err)
	}
	err = ioutil.WriteFile(path, bs, 0600)
	if err != nil {
		return fmt.Errorf("error writing file %s: %w", path, err)
	}
	return nil
}

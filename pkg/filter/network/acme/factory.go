package acme

import (
	"context"
	"fmt"
	"sync"

	"mosn.io/api"

	v2 "mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/log"
	"mosn.io/mosn/pkg/server"
)

func init() {
	api.RegisterNetwork(v2.NETWORK_ACME, CreateFilterChainFactory)
}

var challengers sync.Map

func CreateFilterChainFactory(config map[string]interface{}) (api.NetworkFilterChainFactory, error) {
	var cfg, err = ConvertMapToGlobalConfig(config)
	if err != nil {
		return nil, err
	}

	var chag *challenger
	if cached, exist := challengers.Load(cfg.GetAuthEmail()); exist {
		chag = cached.(*challenger)
		if !chag.equalConfig(cfg) {
			challengers.Delete(cfg.GetAuthEmail())
			chag.closeChallenge()
			chag = nil
		}
	}
	if chag == nil {
		chag, err = newChallenger(context.Background(), cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create challenger: %w", err)
		}
		err = chag.register()
		if err != nil {
			return nil, fmt.Errorf("failed to register user %s: %v", chag.GetEmail(), err)
		}
		go chag.runChallenge()
		challengers.Store(cfg.GetAuthEmail(), chag)
	}

	// NB(thxCode): even if we update the affected listener list,
	// it will never start a new challenge round.
	var affectedListenerNames = cfg.GetAffectedListenerNames()
	chag.SetCertificateHandler(func(certChain, privateKey []byte) {
		var mosnListenerMgr = server.GetListenerAdapterInstance()
		if mosnListenerMgr == nil {
			log.DefaultLogger.Errorf("listener adapter is nil and hasn't been initiated at this time")
			return
		}
		for _, listenerName := range affectedListenerNames {
			var mosnListener = mosnListenerMgr.FindListenerByName("", listenerName).Config()
			mosnListener.FilterChains[0].TLSContexts = []v2.TLSConfig{{
				Status:     true,
				CertChain:  string(certChain),
				PrivateKey: string(privateKey),
			}}
			var err = mosnListenerMgr.AddOrUpdateListener("", mosnListener)
			if err != nil {
				log.DefaultLogger.Errorf("listener adapter failed to update listener %s: %v",
					listenerName, err)
				return
			}
		}
	})

	var x = factory{
		chag: chag,
	}
	return x, nil
}

type factory struct {
	chag *challenger
}

func (x factory) CreateFilterChain(ctx context.Context, callbacks api.NetWorkFilterChainFactoryCallbacks) {
	var filter = NewSolver(ctx, x.chag)
	callbacks.AddReadFilter(filter)
}

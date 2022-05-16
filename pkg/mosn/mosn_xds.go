package mosn

import (
	"context"

	"mosn.io/mosn/istio/istio1106"
	v2 "mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/configmanager"
	"mosn.io/mosn/pkg/istio"
	"mosn.io/mosn/pkg/router"
	"mosn.io/mosn/pkg/server"
	"mosn.io/mosn/pkg/upstream/cluster"
)

// StartXDSMosn creates the mosn application with fewer dependencies,
// which is only served for XDS.
func StartXDSMosn(ctx context.Context, mosnCfg *v2.MOSNConfig) *Mosn {
	// NB(thxCode): seal leverage the mosn as the proxy,
	// so we don't need to enable all things of mosn.

	var m = &Mosn{
		Config:  mosnCfg,
		Upgrade: UpgradeData{},
	}

	// TODO(thxCode): ignore pkg/mosn#InitDebugServe
	// TODO(thxCode): ignore, pkg/admin/store#StartService

	// initial cluster manager
	m.Clustermanager = cluster.NewClusterManagerSingleton(nil, nil, &mosnCfg.ClusterManager.TLSContext)

	// initial route manager
	m.RouterManager = router.NewRouterManager()

	// initial default server
	var cfg = configmanager.ParseServerConfig(&mosnCfg.Servers[0])
	var srvCfg = server.NewConfig(cfg)
	server.InitDefaultLogger(srvCfg)
	var srv = server.NewServer(srvCfg, nil, m.Clustermanager)
	m.servers = append(m.servers, srv)

	// initial xds configuration
	var info = istio1106.ParseXdsInfo(mosnCfg.Node)
	istio.SetServiceCluster(info.ServiceCluster)
	istio.SetServiceNode(info.ServiceNode)
	istio.SetMetadata(info.Metadata)
	m.StartXdsClient(ctx)

	return m
}

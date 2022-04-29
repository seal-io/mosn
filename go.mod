module mosn.io/mosn

go 1.18

replace github.com/anchore/syft => github.com/seal-io/syft v0.44.1-0.20220415015834-1f502b668ab4

replace github.com/envoyproxy/go-control-plane => github.com/envoyproxy/go-control-plane v0.10.1

replace istio.io/api => istio.io/api v0.0.0-20211103171850-665ed2b92d52

require (
	github.com/SkyAPM/go2sky v0.5.0
	github.com/TarsCloud/TarsGo v1.1.4
	github.com/alibaba/sentinel-golang v1.0.2-0.20210112133552-db6063eb263e
	github.com/allegro/bigcache/v3 v3.0.2
	github.com/anchore/stereoscope v0.0.0-20220406160859-c03a18a6b270
	github.com/anchore/syft v0.44.0
	github.com/apache/dubbo-go-hessian2 v1.10.2
	github.com/apache/thrift v0.13.0
	github.com/c2h5oh/datasize v0.0.0-20171227191756-4eba002a5eae
	github.com/cch123/supermonkey v1.0.1-0.20210420090843-d792ef7fb1d7
	github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4
	github.com/dchest/siphash v1.2.1
	github.com/eko/gocache/v2 v2.3.0
	github.com/envoyproxy/go-control-plane v0.10.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-resty/resty/v2 v2.6.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/cel-go v0.5.1
	github.com/google/go-containerregistry v0.8.1-0.20220209165246-a44adc326839
	github.com/hashicorp/go-plugin v1.4.3
	github.com/json-iterator/go v1.1.12
	github.com/juju/errors v0.0.0-20200330140219-3fe23663418f
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/miekg/dns v1.1.41
	github.com/opentracing/opentracing-go v1.2.0
	github.com/opentrx/seata-golang/v2 v2.0.4
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.12.1
	github.com/prometheus/client_model v0.2.0
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0
	github.com/stretchr/testify v1.7.1
	github.com/trainyao/go-maglev v0.0.0-20200611125015-4c1ae64d96a8
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	github.com/urfave/cli v1.22.5
	github.com/valyala/fasthttp v1.35.0
	github.com/valyala/fasttemplate v1.2.1
	github.com/vifraa/gopom v0.1.0
	github.com/wasmerio/wasmer-go v1.0.3
	go.uber.org/atomic v1.9.0
	go.uber.org/automaxprocs v1.3.0
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/net v0.0.0-20220412020605-290c469a71a5
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad
	golang.org/x/tools v0.1.8
	google.golang.org/genproto v0.0.0-20220218161850-94dd64e39d7c
	google.golang.org/grpc v1.44.0
	google.golang.org/grpc/examples v0.0.0-20210818220435-8ab16ef276a3
	google.golang.org/protobuf v1.28.0
	istio.io/api v0.0.0-20211103171850-665ed2b92d52
	istio.io/gogo-genproto v0.0.0-20210113155706-4daf5697332f
	k8s.io/klog v1.0.0
	mosn.io/api v0.0.0-20220308091133-b233c56e98c7
	mosn.io/holmes v0.0.0-20220314072258-139da3429e04
	mosn.io/pkg v0.0.0-20220331064139-949046a47fa2
	mosn.io/proxy-wasm-go-host v0.1.1-0.20210524020952-3fb13ba763a6
	vimagination.zapto.org/byteio v0.0.0-20200222190125-d27cba0f0b10
)

require (
	github.com/CycloneDX/cyclonedx-go v0.5.0 // indirect
	github.com/HdrHistogram/hdrhistogram-go v1.0.1 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/XiaoMi/pegasus-go-client v0.0.0-20210427083443-f3b6b08bc4c2 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/anchore/go-macholibre v0.0.0-20220308212642-53e6d0aaf6fb // indirect
	github.com/anchore/go-rpmdb v0.0.0-20210914181456-a9c52348da63 // indirect
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b // indirect
	github.com/anchore/packageurl-go v0.1.1-0.20220314153042-1bcd40e5206b // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/antlr/antlr4 v0.0.0-20200503195918-621b933c7a7f // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.0.2 // indirect
	github.com/bradfitz/gomemcache v0.0.0-20220106215444-fb4bf637b56d // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/census-instrumentation/opencensus-proto v0.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cncf/xds/go v0.0.0-20211130200136-a8f946100490 // indirect
	github.com/containerd/containerd v1.5.10 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.10.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/docker/cli v20.10.12+incompatible // indirect
	github.com/docker/distribution v2.8.0+incompatible // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.4 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/dubbogo/getty v1.3.4 // indirect
	github.com/dubbogo/go-zookeeper v1.0.3 // indirect
	github.com/dubbogo/gost v1.11.16 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v0.6.2 // indirect
	github.com/facebookincubator/nvdtools v0.1.4 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-hclog v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-syslog v1.0.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20211028200310-0bc27b27de87 // indirect
	github.com/jinzhu/copier v0.3.2 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible // indirect
	github.com/klauspost/compress v1.15.0 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20220114050600-8b9d41f48198 // indirect
	github.com/pegasus-kv/thrift v0.13.0 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.33.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/shirou/gopsutil v3.20.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.21.10 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spdx/tools-golang v0.2.0 // indirect
	github.com/spf13/afero v1.8.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	github.com/tklauser/numcpus v0.3.0 // indirect
	github.com/uber/jaeger-lib v2.4.0+incompatible // indirect
	github.com/ugorji/go/codec v1.1.7 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20210627031916-db1f5573bbc5 // indirect
	github.com/wagoodman/go-progress v0.0.0-20200731105512-1020f39e6240 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/arch v0.0.0-20200826200359-b19915210f00 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/errgo.v2 v2.1.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/apimachinery v0.23.5 // indirect
	vimagination.zapto.org/memio v0.0.0-20200222190306-588ebc67b97d // indirect
)

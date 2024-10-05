module github.com/anchore/grype

go 1.23.0

require (
	github.com/CycloneDX/cyclonedx-go v0.9.1
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/OneOfOne/xxhash v1.2.8
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d
	github.com/adrg/xdg v0.5.0
	github.com/anchore/bubbly v0.0.0-20231115134915-def0aba654a9
	github.com/anchore/clio v0.0.0-20240522144804-d81e109008aa
	github.com/anchore/go-collections v0.0.0-20240216171411-9321230ce537
	github.com/anchore/go-logger v0.0.0-20230725134548-c21dafa1ec5a
	github.com/anchore/go-testutils v0.0.0-20200925183923-d5f45b0d3c04
	github.com/anchore/go-version v1.2.2-0.20210903204242-51efa5b487c4
	github.com/anchore/packageurl-go v0.1.1-0.20240507183024-848e011fc24f
	github.com/anchore/stereoscope v0.0.3
	github.com/anchore/syft v1.13.0
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46
	github.com/bmatcuk/doublestar/v2 v2.0.4
	github.com/charmbracelet/bubbletea v1.1.1
	github.com/charmbracelet/lipgloss v0.13.0
	github.com/dave/jennifer v1.7.1
	github.com/docker/docker v27.3.1+incompatible
	github.com/dustin/go-humanize v1.0.1
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/gabriel-vasile/mimetype v1.4.5
	github.com/gkampitakis/go-snaps v0.5.7
	github.com/glebarez/sqlite v1.11.0
	github.com/go-test/deep v1.1.1
	github.com/google/go-cmp v0.6.0
	github.com/google/go-containerregistry v0.20.2
	github.com/google/uuid v1.6.0
	github.com/gookit/color v1.5.4
	github.com/hako/durafmt v0.0.0-20210608085754-5c1018a4e16b
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-getter v1.7.6
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.7.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08
	github.com/mholt/archiver/v3 v3.5.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.5.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/openvex/go-vex v0.2.5
	github.com/owenrumney/go-sarif v1.1.2-0.20231003122901-1000f5e05554
	// pinned to pull in 386 arch fix: https://github.com/scylladb/go-set/commit/cc7b2070d91ebf40d233207b633e28f5bd8f03a5
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3
	github.com/spf13/afero v1.11.0
	github.com/spf13/cobra v1.8.1
	github.com/stretchr/testify v1.9.0
	github.com/ulikunitz/xz v0.5.12
	github.com/wagoodman/go-partybus v0.0.0-20230516145632-8ccac152c651
	github.com/wagoodman/go-presenter v0.0.0-20211015174752-f9c01afc824b
	github.com/wagoodman/go-progress v0.0.0-20230925121702-07e42b3cdba0
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8
	gorm.io/gorm v1.25.12
)

require (
	cloud.google.com/go v0.112.1 // indirect
	cloud.google.com/go/compute v1.24.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v1.1.6 // indirect
	cloud.google.com/go/storage v1.38.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/DataDog/zstd v1.5.5 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Microsoft/hcsshim v0.11.4 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/anchore/fangs v0.0.0-20240903175602-e716ef12c23d // indirect
	github.com/anchore/go-macholibre v0.0.0-20220308212642-53e6d0aaf6fb // indirect
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/aws/aws-sdk-go v1.44.288 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/becheran/wildmatch-go v1.0.0 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bmatcuk/doublestar/v4 v4.6.1 // indirect
	github.com/charmbracelet/bubbles v0.20.0 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/x/ansi v0.2.3 // indirect
	github.com/charmbracelet/x/term v0.2.0 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/containerd v1.7.11 // indirect
	github.com/containerd/continuity v0.4.2 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.3 // indirect
	github.com/containerd/ttrpc v1.2.2 // indirect
	github.com/containerd/typeurl/v2 v2.1.1 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deitch/magic v0.0.0-20230404182410-1ff89d7342da // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.1.1+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/elliotchance/phpserialize v1.4.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/felixge/fgprof v0.9.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/github/go-spdx/v2 v2.3.2 // indirect
	github.com/gkampitakis/ciinfo v0.3.0 // indirect
	github.com/gkampitakis/go-diff v1.3.2 // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/go-git/go-git/v5 v5.12.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/licensecheck v0.3.1 // indirect
	github.com/google/pprof v0.0.0-20240409012703-83162a5b38cd // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kastenhq/goversion v0.0.0-20230811215019-93b2f8823953 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/knqyf263/go-rpmdb v0.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/maruel/natural v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.2-0.20220822084749-2491eb6c1c75 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/microsoft/go-rustaudit v0.0.0-20220730194248-4b17361d90a5 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runc v1.1.14 // indirect
	github.com/opencontainers/runtime-spec v1.1.0-rc.1 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/package-url/packageurl-go v0.1.1 // indirect
	github.com/pborman/indent v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.19 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.7.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/saferwall/pe v1.5.4 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/sassoftware/go-rpmutils v0.4.0 // indirect
	github.com/secDre4mer/pkcs7 v0.0.0-20240322103146-665324a4461d // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.2.2 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spdx/tools-golang v0.5.5 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sylabs/sif/v2 v2.17.1 // indirect
	github.com/sylabs/squashfs v1.0.0 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/tidwall/gjson v1.17.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/vbatts/go-mtree v0.5.4 // indirect
	github.com/vbatts/tar-split v0.11.3 // indirect
	github.com/vifraa/gopom v1.0.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/zclconf/go-cty v1.14.0 // indirect
	github.com/zyedidia/generic v1.2.2-0.20230320175451-4410d2372cb1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/oauth2 v0.19.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/term v0.24.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/api v0.171.0 // indirect
	google.golang.org/genproto v0.0.0-20240213162025-012b6fc9bca9 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240311132316-a219d84964c2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240314234333-6e1732d8331c // indirect
	google.golang.org/grpc v1.62.1 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.33.1 // indirect
)

replace github.com/mholt/archiver/v3 v3.5.1 => github.com/anchore/archiver/v3 v3.5.2

// this is a breaking change, so we need to pin the version until glebarez/go-sqlite is updated to use internal/libc
replace modernc.org/sqlite v1.33.0 => modernc.org/sqlite v1.32.0

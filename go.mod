module github.com/anchore/vulnscan

go 1.14

require (
	github.com/adrg/xdg v0.2.1
	github.com/anchore/imgbom v0.0.0-20200526132012-dcba50eaa89c
	github.com/anchore/stereoscope v0.0.0-20200523232006-be5f3c18958f
	github.com/anchore/vulnscan-db v0.0.0-20200528193934-4a3f5d48b4c8
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-version v1.1.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.0
	go.etcd.io/etcd v3.3.22+incompatible
	go.uber.org/zap v1.15.0
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/imgbom => ../imgbom

replace github.com/anchore/vulnscan-db => ../vulnscan-db

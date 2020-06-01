module github.com/anchore/vulnscan

go 1.14

require (
	github.com/adrg/xdg v0.2.1
	github.com/anchore/imgbom v0.0.0-20200601144731-83e486d6ca48
	github.com/anchore/stereoscope v0.0.0-20200526174659-b4e33a02f45d
	github.com/anchore/vulnscan-db v0.0.0-20200528193934-4a3f5d48b4c8
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.0
	go.uber.org/zap v1.15.0
	golang.org/x/net v0.0.0-20200528225125-3c3fba18258b // indirect
	google.golang.org/genproto v0.0.0-20200601130524-0f60399e6634 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/vulnscan-db => ../vulnscan-db

module github.com/anchore/vulnscan

go 1.14

require (
	github.com/adrg/xdg v0.2.1
	github.com/anchore/imgbom v0.0.0-20200603004815-b6122a413ba8
	github.com/anchore/stereoscope v0.0.0-20200602123205-6c2ce3c0b2d5
	github.com/anchore/vulnscan-db v0.0.0-20200528193934-4a3f5d48b4c8
	github.com/hashicorp/go-version v1.2.0
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	go.uber.org/zap v1.15.0
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9 // indirect
	golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980 // indirect
	google.golang.org/genproto v0.0.0-20200602104108-2bb8d6132df6 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/vulnscan-db => ../vulnscan-db

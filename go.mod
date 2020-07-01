module github.com/anchore/vulnscan

go 1.14

require (
	github.com/adrg/xdg v0.2.1
	github.com/anchore/go-testutils v0.0.0-20200520222037-edc2bf1864fe
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/imgbom v0.0.0-20200616171024-2cb7dad96784
	github.com/anchore/stereoscope v0.0.0-20200616152009-189722bdb61b
	github.com/anchore/vulnscan-db v0.0.0-20200628111346-8c1d0888ed4c
	github.com/facebookincubator/nvdtools v0.1.4-0.20200622182922-aed862a62ae6
	github.com/go-test/deep v1.0.6
	github.com/hashicorp/go-getter v1.4.1
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/mitchellh/go-homedir v1.1.0
	github.com/sergi/go-diff v1.1.0
	github.com/spf13/afero v1.3.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	go.uber.org/zap v1.15.0
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/vulnscan-db => ../vulnscan-db

module github.com/anchore/grype

go 1.14

require (
	github.com/adrg/xdg v0.2.1
	github.com/anchore/go-testutils v0.0.0-20200624184116-66aa578126db
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/grype-db v0.0.0-20200727124815-9139f1175e84
	github.com/anchore/stereoscope v0.0.0-20200706164556-7cf39d7f4639
	github.com/anchore/syft v0.0.0-20200724122256-9ec5da24dd28
	github.com/facebookincubator/nvdtools v0.1.4-0.20200622182922-aed862a62ae6
	github.com/go-test/deep v1.0.7
	github.com/gookit/color v1.2.5
	github.com/hashicorp/go-getter v1.4.1
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.4
	github.com/sergi/go-diff v1.1.0
	github.com/spf13/afero v1.3.2
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	github.com/wagoodman/go-partybus v0.0.0-20200526224238-eb215533f07d
	github.com/wagoodman/jotframe v0.0.0-20200622123948-2995cbd43525
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/syft => ../syft

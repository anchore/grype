package config

import "github.com/spf13/viper"

type development struct {
	ProfileCPU bool `yaml:"profile-cpu" json:"profile-cpu" mapstructure:"profile-cpu"`
	ProfileMem bool `yaml:"profile-mem" json:"profile-mem" mapstructure:"profile-mem"`
}

func (cfg development) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("dev.profile-cpu", false)
	v.SetDefault("dev.profile-mem", false)
}

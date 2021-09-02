package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type logging struct {
	Structured   bool         `mapstructure:"structured"`
	LevelOpt     logrus.Level `json:"-"`
	Level        string       `mapstructure:"level"`
	FileLocation string       `mapstructure:"file"`
}

func (cfg logging) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("log.level", "")
	v.SetDefault("log.file", "")
	v.SetDefault("log.structured", false)
}

package config

import (
	"codetube.cn/core/config"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
)

type Config struct {
	Mysql map[string]*config.MysqlConfig `yaml:"mysql"` //数据库连接配置
	Redis map[string]*config.RedisConfig `yaml:"redis"`
}

// NewConfig 创建配置
func NewConfig() *Config {
	return &Config{}
}

// InitConfig 初始化配置
func InitConfig() *Config {
	configFile := "config.yaml"
	configFileContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	config := NewConfig()
	err = yaml.Unmarshal(configFileContent, config)
	if err != nil {
		log.Fatal(err)
	}

	return config
}

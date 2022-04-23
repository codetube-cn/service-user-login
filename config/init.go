package config

// ServiceConfig 服务配置
var ServiceConfig *Config

func init() {
	//初始化配置
	ServiceConfig = InitConfig()
}

package bootstrap

import (
	"codetube.cn/core/service"
	"github.com/joho/godotenv"
	"log"
	"os"
)

//项目需要使用的服务
var useServices = []string{"UserLogin"}

func init() {
	//加载 .env 文件环境变量
	_, err := os.Stat(".env")
	if err == nil {
		err = godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}
	//初始化服务连接
	err = service.InitServices(useServices...)
	if err != nil {
		log.Fatal("init services connection fail: ", err)
	}
}

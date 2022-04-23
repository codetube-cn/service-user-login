package components

import (
	"codetube.cn/service-user-login/config"
	"github.com/go-redis/redis/v8"
)

// Redis 连接
var Redis = newRedis()

// CommonRedis 公共缓存连接
var CommonRedis *redis.Client

// UserRedis 用户缓存连接
var UserRedis *redis.Client

// 数据库连接列表
type redisConnection struct {
	Common *redis.Client // 公共缓存使用的连接
	User   *redis.Client // 用户缓存使用的连接
}

// 创建数据库连接列表
func newRedis() *redisConnection {
	return &redisConnection{
		Common: redis.NewClient(&redis.Options{
			Addr:     config.ServiceConfig.Redis["common"].Addr(),
			Password: config.ServiceConfig.Redis["common"].Password,
			DB:       config.ServiceConfig.Redis["common"].Db,
		}),
		User: redis.NewClient(&redis.Options{
			Addr:     config.ServiceConfig.Redis["user"].Addr(),
			Password: config.ServiceConfig.Redis["user"].Password,
			DB:       config.ServiceConfig.Redis["user"].Db,
		}),
	}
}

// RedisInit 初始化Redis连接
func (c *redisConnection) RedisInit() (err error) {
	CommonRedis = c.Common
	UserRedis = c.User
	//其他连接...
	return
}

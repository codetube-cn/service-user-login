package server

import (
	"codetube.cn/proto/service_user_login"
)

type UserLoginServer struct {
	service_user_login.UnimplementedUserLoginServer
}

func NewUserLoginServer() *UserLoginServer {
	return &UserLoginServer{}
}

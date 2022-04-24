package server

import (
	"codetube.cn/core/codes"
	"codetube.cn/proto/service_user_login"
	"codetube.cn/service-user-login/components"
	"codetube.cn/service-user-login/libraries"
	"codetube.cn/service-user-login/libraries/password"
	"codetube.cn/service-user-login/models"
	"context"
	"github.com/google/uuid"
	"log"
	"strconv"
)

// Username 使用用户名和密码注册
func (s *UserLoginServer) Username(c context.Context, request *service_user_login.LoginUsernameRequest) (*service_user_login.LoginResultResponse, error) {
	message := "success"
	status := s.checkUsernameParams(request)
	if status != codes.Success {
		return &service_user_login.LoginResultResponse{
			Status:  int64(status),
			Message: message, //@todo 数字转文字
			Token:   "",
		}, nil
	}

	var token = ""
	username := request.GetUsername()
	passwd := request.GetPassword()

	user := models.User{
		Username: username,
	}

	result := components.UserDB.Find(&user)
	if result.Error != nil {
		status = codes.UserLoginFailed
		log.Println("[err:"+strconv.Itoa(codes.UserLoginFailed)+"]查询用户信息失败：", result.Error)
	} else if user.ID == uuid.Nil {
		status = codes.UserNotExist
	} else if !password.ComparePassword(user.Password, passwd) {
		status = codes.UserLoginPasswordNotMatched
	} else if user.Enabled != 1 {
		status = codes.UserIsDisabled
	} else {
		j, err := libraries.MakeUserJwtToken(user.ID.String())
		if err != nil {
			status = codes.UserLoginFailed
			log.Println("[err:"+strconv.Itoa(codes.UserLoginFailed)+"]生成 JWT 失败：", err)
		} else {
			token = j
		}
	}

	return &service_user_login.LoginResultResponse{
		Status:  int64(status),
		Message: message,
		Token:   token,
	}, nil
}

func (s *UserLoginServer) checkUsernameParams(request *service_user_login.LoginUsernameRequest) int {
	username := request.GetUsername()
	passwd := request.GetPassword()

	//检查用户名和密码格式
	if len(username) < 5 || len(username) > 20 {
		return codes.UserAccountInvalid
	}
	if !password.CheckPassword(passwd) {
		return codes.UserPasswordInvalid
	}
	return codes.Success
}

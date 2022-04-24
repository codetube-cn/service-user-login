package server

import (
	"codetube.cn/core/codes"
	"codetube.cn/core/libraries"
	"codetube.cn/proto/service_user_login"
	"codetube.cn/service-user-login/components"
	libraries2 "codetube.cn/service-user-login/libraries"
	"codetube.cn/service-user-login/libraries/password"
	"codetube.cn/service-user-login/models"
	"context"
	"github.com/google/uuid"
	"log"
	"strconv"
)

// Email 使用邮箱注册
func (s *UserLoginServer) Email(c context.Context, request *service_user_login.LoginEmailRequest) (*service_user_login.LoginResultResponse, error) {
	message := "success"
	status := s.checkEmailParams(request)
	if status != codes.Success {
		return &service_user_login.LoginResultResponse{
			Status:  int64(status),
			Message: message, //@todo 数字转文字
			Token:   "",
		}, nil
	}

	var token = ""
	email := request.GetEmail()
	passwd := request.GetPassword()

	user := &models.User{
		Email: email,
	}

	result := components.UserDB.Where(user).Find(user)
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
		j, err := libraries2.MakeUserJwtToken(user.ID.String())
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

func (s *UserLoginServer) checkEmailParams(request *service_user_login.LoginEmailRequest) int {
	email := request.GetEmail()
	passwd := request.GetPassword()
	//检查邮箱和密码格式
	if !libraries.CheckEmail(email) {
		return codes.UserEmailInvalid
	}
	if !password.CheckPassword(passwd) {
		return codes.UserPasswordInvalid
	}
	return codes.Success
}

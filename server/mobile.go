package server

import (
	"codetube.cn/core/codes"
	core_libraries "codetube.cn/core/libraries"
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

// MobilePassword 使用手机号+密码登录
func (s *UserLoginServer) MobilePassword(c context.Context, request *service_user_login.LoginMobilePasswordRequest) (*service_user_login.LoginResultResponse, error) {
	message := "success"
	status := s.checkMobilePasswordParams(request)
	if status != codes.Success {
		return &service_user_login.LoginResultResponse{
			Status:  int64(status),
			Message: message, //@todo 数字转文字
			Token:   "",
		}, nil
	}

	var token = ""
	mobile := request.GetMobile()
	passwd := request.GetPassword()

	user := &models.User{
		Mobile: mobile,
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

// MobileVerifyCode 使用手机号+验证码登录
func (s *UserLoginServer) MobileVerifyCode(c context.Context, request *service_user_login.LoginMobileVerifyCodeRequest) (*service_user_login.LoginResultResponse, error) {
	message := "success"
	status := s.checkMobileVerifyCodeParams(request)
	if status != codes.Success {
		return &service_user_login.LoginResultResponse{
			Status:  int64(status),
			Message: message, //@todo 数字转文字
			Token:   "",
		}, nil
	}

	var token = ""
	mobile := request.GetMobile()

	user := &models.User{
		Mobile: mobile,
	}

	result := components.UserDB.Where(user).Find(user)
	if result.Error != nil {
		status = codes.UserLoginFailed
		log.Println("[err:"+strconv.Itoa(codes.UserLoginFailed)+"]查询用户信息失败：", result.Error)
	} else if user.ID == uuid.Nil {
		status = codes.UserNotExist
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
	//清除验证码
	cacheKey := libraries.GetMobileLoginVerifyCodeCacheKey(mobile)
	_, err := components.CommonRedis.Del(context.Background(), cacheKey).Result()
	if err != nil {
		log.Println("用户手机号登录从缓存删除验证码失败：", cacheKey, err)
	}

	return &service_user_login.LoginResultResponse{
		Status:  int64(status),
		Message: message,
		Token:   token,
	}, nil
}

func (s *UserLoginServer) checkMobilePasswordParams(request *service_user_login.LoginMobilePasswordRequest) int {
	mobile := request.GetMobile()
	passwd := request.GetPassword()
	//检查手机号格式
	if !core_libraries.CheckMobile(mobile) {
		return codes.UserMobileInvalid
	}
	if !password.CheckPassword(passwd) {
		return codes.UserPasswordInvalid
	}
	return codes.Success
}

func (s *UserLoginServer) checkMobileVerifyCodeParams(request *service_user_login.LoginMobileVerifyCodeRequest) int {
	mobile := request.GetMobile()
	verifyCode := request.GetVerifyCode()
	//检查手机号格式
	if !core_libraries.CheckMobile(mobile) {
		return codes.UserMobileInvalid
	}
	if len(verifyCode) < 4 || len(verifyCode) > 8 {
		return codes.VerifyCodeInvalid
	}
	//检查验证码是否正确
	cacheKey := libraries.GetMobileLoginVerifyCodeCacheKey(mobile)
	cacheVerifyCode, err := components.CommonRedis.Get(context.Background(), cacheKey).Result()
	if err != nil {
		log.Println("用户手机号登录从缓存获取验证码失败：", cacheKey, err)
		return codes.VerifyCodeInvalid
	}
	if cacheVerifyCode != verifyCode {
		return codes.VerifyCodeInvalid
	}
	return codes.Success
}

package check

import (
	"codetube.cn/service-user-login/components"
	"codetube.cn/service-user-login/models"
	"github.com/google/uuid"
)

// UserExistByUsername 检查用户名是否存在
func UserExistByUsername(username string) bool {
	user := &models.User{}
	components.UserDB.Where("username = ?", username).First(user)
	if user.ID == uuid.Nil {
		return false
	}
	return true
}

// UserExistByEmail 检查邮箱是否存在
func UserExistByEmail(username string) bool {
	user := &models.User{}
	components.UserDB.Where("email = ?", username).First(user)
	if user.ID == uuid.Nil {
		return false
	}
	return true
}

// UserExistByMobile 检查手机号是否存在
func UserExistByMobile(mobile string) bool {
	user := &models.User{}
	components.UserDB.Where("mobile = ?", mobile).First(user)
	if user.ID == uuid.Nil {
		return false
	}
	return true
}

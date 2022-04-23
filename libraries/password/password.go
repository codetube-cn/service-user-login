package password

import (
	"golang.org/x/crypto/bcrypt"
)

//CheckPassword 检查密码格式
func CheckPassword(password string) bool {
	passwordLen := len(password)
	if passwordLen < 8 || passwordLen > 40 {
		return false
	}

	return true
}

//HashPassword 加密密码
func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return ""
	}
	return string(hash)
}

//ComparePassword 验证密码
func ComparePassword(hashedPassword string, password string) bool {
	byteHash := []byte(hashedPassword)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(password))
	if err != nil {
		return false
	}
	return true
}

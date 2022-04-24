package libraries

import (
	"codetube.cn/service-user-login/config"
	"codetube.cn/service-user-login/models"
	"github.com/dgrijalva/jwt-go"
	"time"
)

//GetMobileLoginVerifyCodeCacheKey 获取手机号登录时验证码缓存 key
func GetMobileLoginVerifyCodeCacheKey(mobile string) string {
	return "user_mobile_login_verify_code_" + mobile
}

//MakeUserJwtToken 生成 jwt
func MakeUserJwtToken(uuid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, models.UserClaims{
		ID:         uuid,
		CreateTime: time.Now(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 30*86400, //30 天有效期
		},
	})
	tokenString, err := token.SignedString([]byte(config.ServiceConfig.JwtKey))
	return tokenString, err
}

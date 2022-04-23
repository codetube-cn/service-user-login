package libraries

//GetMobileLoginVerifyCodeCacheKey 获取手机号登录时验证码缓存 key
func GetMobileLoginVerifyCodeCacheKey(mobile string) string {
	return "user_mobile_login_verify_code_" + mobile
}

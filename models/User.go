package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	gorm.Model
	ID           uuid.UUID `json:"id" gorm:"type:char(36);primary_key"`
	Username     string    `gorm:"uniqueIndex;default:null"` //账号
	Mobile       string    `gorm:"uniqueIndex;default:null"` //手机号
	Email        string    `gorm:"uniqueIndex;default:null"` //邮箱
	Nickname     string    //昵称
	Password     string    //密码
	Avatar       string    //头像
	Enabled      int       //是否启用
	Certificated int       //是否已实名认证
	IsAdmin      int       //是否是管理员
	IsTeacher    int       //是否是讲师
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	u.ID = uuid.New()
	return
}

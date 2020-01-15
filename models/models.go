package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

type Login struct {
	LoginID      string `gorm:"type:varchar(50);primary_key"`
	ProfileHash  string `gorm:"type:varchar(255)"`
	PasswordHash []byte
	Locked       *time.Time
	AntBaseModel
}

func (model *Login) BeforeCreate(scope *gorm.Scope) error {

	if err := model.AntBaseModel.BeforeCreate(scope); err != nil{
		return err
	}
	return scope.SetColumn("LoginID", model.IDGen("lg"))
}


type LoginEvent struct {
	LoginEventID string `gorm:"type:varchar(50);primary_key"`
	LoginID      string `gorm:"type:varchar(50)"`
	AccessID     string `gorm:"type:varchar(50)"`
	IPAddress    string
	UserAgent    string
	Client       string
	Status       int
	Context      string `gorm:"type:text"`
	AntBaseModel
}

func (model *LoginEvent) BeforeCreate(scope *gorm.Scope) error {

	if err := model.AntBaseModel.BeforeCreate(scope); err != nil{
		return err
	}
	return scope.SetColumn("LoginEventID", model.IDGen("lge"))
}

type Session struct {
	SessionID    string `gorm:"type:varchar(50);primary_key"`
	LoginEventID string `gorm:"type:varchar(50)"`
	ExpiresAt    time.Time
	IssuedAt     time.Time
	ProfileID    string `gorm:"type:varchar(50)"`
	AntBaseModel
}


func (model *Session) BeforeCreate(scope *gorm.Scope) error {

	if err := model.AntBaseModel.BeforeCreate(scope); err != nil{
		return err
	}
	return scope.SetColumn("SessionID", model.IDGen("ses"))
}

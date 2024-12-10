package gormadapter

import "gorm.io/gorm"

type GetDB interface {
	GetDB() *gorm.DB
}

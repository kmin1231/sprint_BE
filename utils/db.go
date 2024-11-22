package utils

import (
	"github.com/kmin1231/sprint_BE/config"
)

func CheckDBConnection() error {
	sqlDB, err := config.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

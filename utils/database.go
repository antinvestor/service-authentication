package utils

import (
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"

	// Gorm relies on this dialect for initialization
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/smacker/opentracing-gorm"
)


// ConfigureDatabase Database Access for environment is configured here
func ConfigureDatabase(log *logrus.Entry, replica bool) (*gorm.DB, error) {

	driver := GetEnv(ConfigDatabaseDriver, "postgres")

	datasource := GetEnv(ConfigDatabaseUrl, "")
	if replica {
		datasource = GetEnv(ConfigReplicaDatabaseUrl, datasource)
	}

	log.Debugf("Connecting using driver %v and source %v ", driver, datasource)

	db, err := gorm.Open(driver, datasource)

	if db != nil {
		otgorm.AddGormCallbacks(db)
	}
	return db, err
}

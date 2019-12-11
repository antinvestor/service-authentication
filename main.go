package main

import (
	"log"
	"os"
	"time"

	"antinvestor.com/service/auth/service"
	"antinvestor.com/service/auth/utils"
)

func main() {

	serviceName := "auth"

	logger, err := utils.ConfigureLogging(serviceName)
	if err != nil {
		log.Fatal("Failed to configure logging: " + err.Error())
	}

	closer, err := utils.ConfigureJuegler(serviceName)
	if err != nil {
		logger.Fatal("Failed to configure Juegler: " + err.Error())
	}

	defer closer.Close()

	database, err := utils.ConfigureDatabase(logger, false)
	if err != nil {
		logger.Warnf("Configuring write database has error: %v", err)
	}

	replicaDatabase, err := utils.ConfigureDatabase(logger, true)
	if err != nil {
		logger.Warnf("Configuring read only database has error: %v", err)
	}

	isMigration := utils.GetEnv(utils.ConfigOnlyMigrate, "")
	stdArgs := os.Args[1:]
	if (len(stdArgs) > 0 && stdArgs[0] == "migrate") || isMigration == "true" {
		logger.Info("Initiating migrations")

		service.PerformMigration(logger, database)

	} else {
		logger.Infof("Initiating the service at %v", time.Now())

		healthChecker, err := utils.ConfigureHealthChecker(logger, database, replicaDatabase)
		if err != nil {
			logger.Warnf("Error configuring health checks: %v", err)
		}

		env := utils.Env{
			Logger:             logger,
			Health:             healthChecker,
		}
		env.SetWriteDb(database)
		env.SetReadDb(replicaDatabase)

		service.RunServer(&env)
	}

}

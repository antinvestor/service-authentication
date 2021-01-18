package main

import (
	"context"
	"fmt"
	"github.com/antinvestor/apis"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/models"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
	"gocloud.dev/server"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/antinvestor/service-authentication/service"
	"github.com/antinvestor/service-authentication/utils"
)

func main() {

	serviceName := "auth"
	ctx := context.Background()

	var serviceOptions []frame.Option

	datasource := frame.GetEnv(config.EnvDatabaseUrl, "postgres://ant:@nt@localhost/service_profile")
	mainDb := frame.Datastore(ctx, datasource, false)
	serviceOptions = append(serviceOptions, mainDb)

	readOnlydatasource := frame.GetEnv(config.EnvReplicaDatabaseUrl, datasource)
	readDb := frame.Datastore(ctx, readOnlydatasource, true)
	serviceOptions = append(serviceOptions, readDb)


	waitDuration := time.Second * 15

	csrfSecret := frame.GetEnv(config.EnvCsrfSecret,
		"\\xf80105efab6d863fd8fc243d269094469e2277e8f12e5a0a9f401e88494f7b4b")
	serverPort := frame.GetEnv(config.EnvServerPort, "7000")
	router := service.NewAuthRouterV1(env)

	handlers.RecoveryHandler()(
		csrf.Protect(
			[]byte(csrfSecret),
			csrf.Secure(false),
		)(router))


	httpOptions := &server.Options{

	}

	defaultServer := frame.HttpServer(httpOptions)
	serviceOptions = append(serviceOptions, defaultServer)

	sysService := frame.NewService(serviceName, serviceOptions...)

	isMigration, err := strconv.ParseBool(frame.GetEnv(config.EnvMigrate, "false"))
	if err != nil {
		isMigration = false
	}

	stdArgs := os.Args[1:]
	if (len(stdArgs) > 0 && stdArgs[0] == "migrate") || isMigration {

		migrationPath := frame.GetEnv(config.EnvMigrationPath, "./migrations/0001")
		err := sysService.MigrateDatastore(ctx, migrationPath,
			&models.Login{}, &models.LoginEvent{})

		if err != nil {
			log.Printf("main -- Could not migrate successfully because : %v", err)
		}

	} else {

		serverPort := frame.GetEnv(config.EnvServerPort, "7005")

		log.Printf(" main -- Initiating server operations on : %s", serverPort)
		err := sysService.Run(ctx, fmt.Sprintf(":%v", serverPort))
		if err != nil {
			log.Printf("main -- Could not run Server : %v", err)
		}

	}
}

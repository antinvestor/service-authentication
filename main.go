package main

import (
	"context"
	"fmt"
	"github.com/antinvestor/apis"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service"
	"github.com/antinvestor/service-authentication/service/models"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/pitabwire/frame"
	"log"
	"os"
	"strconv"
)

func main() {

	serviceName := "auth"
	ctx := context.Background()

	var err error
	var profileCli *papi.ProfileClient
	var serviceOptions []frame.Option

	sysService := frame.NewService(serviceName)

	datasource := frame.GetEnv(config.EnvDatabaseUrl, "postgres://ant:@nt@localhost/service_auth")
	mainDb := frame.Datastore(ctx, datasource, false)
	serviceOptions = append(serviceOptions, mainDb)

	readOnlydatasource := frame.GetEnv(config.EnvReplicaDatabaseUrl, datasource)
	readDb := frame.Datastore(ctx, readOnlydatasource, true)
	serviceOptions = append(serviceOptions, readDb)

	profileServiceUrl := frame.GetEnv(config.EnvProfileServiceUri, "127.0.0.1:7005")
	profileCli, err = papi.NewProfileClient(ctx, apis.WithEndpoint(profileServiceUrl))
	if err != nil {
		log.Printf("main -- Could not setup profile service : %v", err)
	}

	csrfSecret := frame.GetEnv(config.EnvCsrfSecret,
		"\\xf80105efab6d863fd8fc243d269094469e2277e8f12e5a0a9f401e88494f7b4b")

	authServiceHandlers := handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(
		csrf.Protect(
			[]byte(csrfSecret),
			csrf.Secure(false),
		)(service.NewAuthRouterV1(sysService, profileCli)))

	defaultServer := frame.HttpHandler(authServiceHandlers)
	serviceOptions = append(serviceOptions, defaultServer)

	sysService.Init(serviceOptions...)

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

		serverPort := frame.GetEnv(config.EnvServerPort, "7000")

		log.Printf(" main -- Initiating server operations on : %s", serverPort)
		err := sysService.Run(ctx, fmt.Sprintf(":%v", serverPort))
		if err != nil {
			log.Printf("main -- Could not run Server : %v", err)
		}

	}
}

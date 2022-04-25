package main

import (
	"context"
	"fmt"
	"github.com/antinvestor/apis"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service"
	"github.com/antinvestor/service-authentication/service/models"
	prtapi "github.com/antinvestor/service-partition-api"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/pitabwire/frame"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {

	serviceName := "service_authentication"
	ctx := context.Background()

	var err error
	var profileCli *papi.ProfileClient
	var partitionCli *prtapi.PartitionClient
	var serviceOptions []frame.Option

	sysService := frame.NewService(serviceName)

	datasource := frame.GetEnv(config.EnvDatabaseURL, "postgres://ant:@nt@localhost/service_auth")
	mainDB := frame.Datastore(ctx, datasource, false)
	serviceOptions = append(serviceOptions, mainDB)

	readOnlydatasource := frame.GetEnv(config.EnvReplicaDatabaseURL, datasource)
	readDB := frame.Datastore(ctx, readOnlydatasource, true)
	serviceOptions = append(serviceOptions, readDB)

	profileServiceURL := frame.GetEnv(config.EnvProfileServiceURI, "127.0.0.1:7005")

	oauth2ServiceHost := frame.GetEnv(config.EnvOauth2ServiceURI, "")
	oauth2ServiceURL := fmt.Sprintf("%s/oauth2/token", oauth2ServiceHost)
	oauth2ServiceSecret := frame.GetEnv(config.EnvOauth2ServiceClientSecret, "")

	var audienceList []string
	oauth2ServiceAudience := frame.GetEnv(config.EnvOauth2ServiceAudience, "")
	if oauth2ServiceAudience != "" {
		audienceList = strings.Split(oauth2ServiceAudience, ",")
	}
	profileCli, err = papi.NewProfileClient(ctx,
		apis.WithEndpoint(profileServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(serviceName),
		apis.WithTokenPassword(oauth2ServiceSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup profile service : %v", err)
	}

	partitionServiceURL := frame.GetEnv(config.EnvPartitionServiceURI, "127.0.0.1:7003")
	partitionCli, err = prtapi.NewPartitionsClient(ctx,
		apis.WithEndpoint(partitionServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(serviceName),
		apis.WithTokenPassword(oauth2ServiceSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup partition service client: %v", err)
	}

	serviceTranslations := frame.Translations("en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	csrfSecret := frame.GetEnv(config.EnvCsrfSecret,
		"\\xf80105efab6d863fd8fc243d269094469e2277e8f12e5a0a9f401e88494f7b4b")

	authServiceHandlers := handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(
		csrf.Protect(
			[]byte(csrfSecret),
			csrf.Secure(false),
		)(service.NewAuthRouterV1(sysService, profileCli, partitionCli)))

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
		err := sysService.MigrateDatastore(ctx, migrationPath, &models.Login{}, &models.LoginEvent{})

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

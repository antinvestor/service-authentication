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
	"github.com/sirupsen/logrus"
	"strings"
)

func main() {

	serviceName := "service_authentication"
	ctx := context.Background()

	var authenticationConfig config.AuthenticationConfig
	err := frame.ConfigProcess("", &authenticationConfig)
	if err != nil {
		logrus.WithError(err).Fatal("could not process configs")
		return
	}

	sysService := frame.NewService(serviceName, frame.Config(&authenticationConfig), frame.Datastore(ctx))
	log := sysService.L()

	var serviceOptions []frame.Option

	if authenticationConfig.DoDatabaseMigrate() {

		sysService.Init(serviceOptions...)

		err := sysService.MigrateDatastore(ctx, authenticationConfig.GetDatabaseMigrationPath(),
			&models.Login{}, &models.LoginEvent{}, &models.APIKey{}, &models.Session{})

		if err != nil {
			log.Fatalf("main -- Could not migrate successfully because : %+v", err)
		}

		return

	}

	var profileCli *papi.ProfileClient
	var partitionCli *prtapi.PartitionClient

	profileServiceURL := authenticationConfig.ProfileServiceURI

	oauth2ServiceHost := authenticationConfig.GetOauth2ServiceURI()
	oauth2ServiceURL := fmt.Sprintf("%s/oauth2/token", oauth2ServiceHost)

	audienceList := make([]string, 0)
	oauth2ServiceAudience := authenticationConfig.Oauth2ServiceAudience
	if oauth2ServiceAudience != "" {
		audienceList = strings.Split(oauth2ServiceAudience, ",")
	}
	profileCli, err = papi.NewProfileClient(ctx,
		apis.WithEndpoint(profileServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(serviceName),
		apis.WithTokenPassword(authenticationConfig.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup profile service : %v", err)
	}

	partitionServiceURL := authenticationConfig.PartitionServiceURI
	partitionCli, err = prtapi.NewPartitionsClient(ctx,
		apis.WithEndpoint(partitionServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(serviceName),
		apis.WithTokenPassword(authenticationConfig.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup partition service client: %v", err)
	}

	serviceTranslations := frame.Translations("en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	csrfSecret := authenticationConfig.CsrfSecret

	authServiceHandlers := handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(
		csrf.Protect(
			[]byte(csrfSecret),
			csrf.Secure(false),
		)(service.NewAuthRouterV1(sysService, &authenticationConfig, profileCli, partitionCli)))

	defaultServer := frame.HttpHandler(authServiceHandlers)
	serviceOptions = append(serviceOptions, defaultServer)

	sysService.Init(serviceOptions...)

	serverPort := authenticationConfig.ServerPort
	log.Printf(" main -- Initiating server operations on : %s", serverPort)
	err = sysService.Run(ctx, fmt.Sprintf(":%v", serverPort))
	if err != nil {
		log.Printf("main -- Could not run Server : %v", err)
	}

}

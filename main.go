package main

import (
	"fmt"
	apis "github.com/antinvestor/apis/go/common"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/gorilla/handlers"
	"github.com/pitabwire/frame"
	"github.com/sirupsen/logrus"
	"strings"
)

func main() {

	serviceName := "service_authentication"

	var authenticationConfig config.AuthenticationConfig
	err := frame.ConfigProcess("", &authenticationConfig)
	if err != nil {
		logrus.WithError(err).Fatal("could not process configs")
		return
	}

	ctx, srv := frame.NewService(serviceName, frame.Config(&authenticationConfig))
	log := srv.L(ctx)

	serviceOptions := []frame.Option{frame.Datastore(ctx), frame.Translations("/localization", "en")}
	if authenticationConfig.DoDatabaseMigrate() {
		srv.Init(serviceOptions...)

		err = srv.MigrateDatastore(ctx,
			authenticationConfig.GetDatabaseMigrationPath(),
			&models.APIKey{}, &models.Session{},
			&models.Login{}, &models.LoginEvent{})

		if err != nil {
			log.Fatalf("main -- Could not migrate successfully because : %+v", err)
		}
		return
	}

	err = srv.RegisterForJwt(ctx)
	if err != nil {
		log.WithError(err).Fatal("main -- could not register for jwt")
	}

	var profileCli *profilev1.ProfileClient
	var partitionCli *partitionv1.PartitionClient

	oauth2ServiceHost := authenticationConfig.GetOauth2ServiceURI()
	oauth2ServiceURL := fmt.Sprintf("%s/oauth2/token", oauth2ServiceHost)
	audienceList := make([]string, 0)
	oauth2ServiceAudience := authenticationConfig.Oauth2ServiceAudience
	if oauth2ServiceAudience != "" {
		audienceList = strings.Split(oauth2ServiceAudience, ",")
	}
	profileCli, err = profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(authenticationConfig.ProfileServiceURI),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(srv.JwtClientID()),
		apis.WithTokenPassword(authenticationConfig.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup profile service : %v", err)
	}

	partitionServiceURL := authenticationConfig.PartitionServiceURI
	partitionCli, err = partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(partitionServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(srv.JwtClientID()),
		apis.WithTokenPassword(authenticationConfig.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup partition service client: %v", err)
	}

	serviceTranslations := frame.Translations("en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	authServiceHandlers := handlers.RecoveryHandler(
		handlers.PrintRecoveryStack(true))(
		service.NewAuthRouterV1(srv, &authenticationConfig, profileCli, partitionCli))

	defaultServer := frame.HttpHandler(authServiceHandlers)
	serviceOptions = append(serviceOptions, defaultServer)

	srv.Init(serviceOptions...)

	log.WithField("server http port", authenticationConfig.HttpServerPort).
		WithField("server grpc port", authenticationConfig.GrpcServerPort).
		Info(" Initiating server operations")
	err = srv.Run(ctx, "")
	if err != nil {
		log.Printf("main -- Could not run Server : %v", err)
	}
}

package main

import (
	"context"
	"fmt"
	"strings"

	apis "github.com/antinvestor/apis/go/common"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/gorilla/handlers"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

func main() {

	ctx := context.Background()
	serviceName := "service_authentication"

	cfg, err := frame.ConfigLoadWithOIDC[config.AuthenticationConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	ctx, svc := frame.NewServiceWithContext(ctx, serviceName, frame.WithConfig(&cfg))
	log := svc.Log(ctx)

	serviceOptions := []frame.Option{frame.WithDatastore()}

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, svc, cfg, log) {
		return
	}

	err = svc.RegisterForJwt(ctx)
	if err != nil {
		log.WithError(err).Fatal("main -- could not register for jwt")
	}

	var profileCli *profilev1.ProfileClient
	var partitionCli *partitionv1.PartitionClient

	oauth2ServiceHost := cfg.GetOauth2ServiceURI()
	oauth2ServiceURL := fmt.Sprintf("%s/oauth2/token", oauth2ServiceHost)
	audienceList := make([]string, 0)
	oauth2ServiceAudience := cfg.Oauth2ServiceAudience
	if oauth2ServiceAudience != "" {
		audienceList = strings.Split(oauth2ServiceAudience, ",")
	}
	profileCli, err = profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(cfg.ProfileServiceURI),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(cfg.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup profile service : %v", err)
	}

	partitionServiceURL := cfg.PartitionServiceURI
	partitionCli, err = partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(partitionServiceURL),
		apis.WithTokenEndpoint(oauth2ServiceURL),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(cfg.Oauth2ServiceClientSecret),
		apis.WithAudiences(audienceList...))
	if err != nil {
		log.Printf("main -- Could not setup partition service client: %v", err)
	}

	serviceTranslations := frame.WithTranslations("/localization", "en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	authServiceHandlers := handlers.RecoveryHandler(
		handlers.PrintRecoveryStack(true))(
		service.NewAuthRouterV1(ctx, svc, &cfg, profileCli, partitionCli))

	defaultServer := frame.WithHTTPHandler(authServiceHandlers)
	serviceOptions = append(serviceOptions, defaultServer)

	svc.Init(ctx, serviceOptions...)

	log.WithField("server http port", cfg.HTTPServerPort).
		WithField("server grpc port", cfg.GrpcServerPort).
		Info(" Initiating server operations")
	err = svc.Run(ctx, "")
	if err != nil {
		log.Printf("main -- Could not run Server : %v", err)
	}
}

// handleDatabaseMigration performs database migration if configured to do so.
func handleDatabaseMigration(
	ctx context.Context,
	svc *frame.Service,
	cfg config.AuthenticationConfig,
	log *util.LogEntry,
) bool {
	serviceOptions := []frame.Option{frame.WithDatastore()}

	if cfg.DoDatabaseMigrate() {
		svc.Init(ctx, serviceOptions...)

		err := repository.Migrate(ctx, svc, cfg.GetDatabaseMigrationPath())
		if err != nil {
			log.WithError(err).Fatal("main -- Could not migrate successfully")
		}
		return true
	}
	return false
}

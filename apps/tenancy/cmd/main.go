package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"buf.build/go/protovalidate"
	apis "github.com/antinvestor/apis/go/common"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/queue"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	protovalidateinterceptor "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	serviceName := "service_partition"
	ctx := context.Background()

	cfg, err := frame.ConfigLoadWithOIDC[config.PartitionConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	ctx, svc := frame.NewServiceWithContext(ctx, serviceName, frame.WithConfig(&cfg))
	log := svc.Log(ctx)

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, svc, cfg, log) {
		return
	}

	err = svc.RegisterForJwt(ctx)
	if err != nil {
		log.WithError(err).Fatal("could not register for jwt")
		return
	}

	// Setup GRPC server
	grpcServer, implementation := setupGRPCServer(ctx, svc, cfg, serviceName, log)

	// Setup HTTP handlers and proxy
	serviceOptions, httpErr := setupHTTPHandlers(ctx, svc, implementation, cfg, grpcServer)
	if httpErr != nil {
		log.WithError(httpErr).Fatal("could not setup HTTP handlers")
	}

	partitionSyncQueueHandler := queue.PartitionSyncQueueHandler{
		Service: svc,
	}
	partitionSyncQueueURL := cfg.QueuePartitionSyncURL
	partitionSyncQueue := frame.WithRegisterSubscriber(
		cfg.PartitionSyncName,
		partitionSyncQueueURL,
		&partitionSyncQueueHandler,
	)
	partitionSyncQueueP := frame.WithRegisterPublisher(cfg.PartitionSyncName, partitionSyncQueueURL)

	serviceOptions = append(serviceOptions, partitionSyncQueue, partitionSyncQueueP)

	svc.Init(ctx, serviceOptions...)

	log.WithField("server http port", cfg.HTTPPort()).
		WithField("server grpc port", cfg.GrpcPort()).
		Info(" Initiating server operations")
	err = implementation.Service.Run(ctx, "")
	if err != nil {
		log = log.WithError(err)

		if errors.Is(err, context.Canceled) {
			log.Error("server stopping")
		} else {
			log.Fatal("server stopping with error")
		}
	}
}

// handleDatabaseMigration performs database migration if configured to do so.
func handleDatabaseMigration(
	ctx context.Context,
	svc *frame.Service,
	cfg config.PartitionConfig,
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

// setupGRPCServer initialises and configures the gRPC server.
func setupGRPCServer(_ context.Context, svc *frame.Service,
	cfg config.PartitionConfig,
	serviceName string,
	log *util.LogEntry) (*grpc.Server, *handlers.PartitionServer) {
	jwtAudience := cfg.Oauth2JwtVerifyAudience
	if jwtAudience == "" {
		jwtAudience = serviceName
	}

	validator, err := protovalidate.New()
	if err != nil {
		log.WithError(err).Fatal("could not load validator for proto messages")
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandlerContext(frame.RecoveryHandlerFun)),
			svc.UnaryAuthInterceptor(jwtAudience, cfg.GetOauth2Issuer()),
			protovalidateinterceptor.UnaryServerInterceptor(validator)),

		grpc.ChainStreamInterceptor(
			recovery.StreamServerInterceptor(recovery.WithRecoveryHandlerContext(frame.RecoveryHandlerFun)),
			svc.StreamAuthInterceptor(jwtAudience, cfg.GetOauth2Issuer()),
			protovalidateinterceptor.StreamServerInterceptor(validator),
		),
	)

	implementation := &handlers.PartitionServer{
		Service: svc,
	}
	partitionv1.RegisterPartitionServiceServer(grpcServer, implementation)

	return grpcServer, implementation
}

// setupHTTPHandlers configures HTTP handlers and proxy.
func setupHTTPHandlers(
	ctx context.Context,
	svc *frame.Service,
	implementation *handlers.PartitionServer,
	cfg config.PartitionConfig,
	grpcServer *grpc.Server,
) ([]frame.Option, error) {
	// Start with framedata option
	serviceOptions := []frame.Option{frame.WithDatastore()}

	// Add GRPC server option
	grpcServerOpt := frame.WithGRPCServer(grpcServer)
	serviceOptions = append(serviceOptions, grpcServerOpt)

	// Setup proxy
	proxyOptions := apis.ProxyOptions{
		GrpcServerEndpoint: fmt.Sprintf("localhost:%s", cfg.GrpcPort()),
		GrpcServerDialOpts: []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
	}

	proxyMux, err := partitionv1.CreateProxyHandler(ctx, proxyOptions)
	if err != nil {
		return nil, err
	}

	// Setup REST handlers
	jwtAudience := cfg.Oauth2JwtVerifyAudience
	if jwtAudience == "" {
		jwtAudience = svc.Name()
	}

	partitionServiceRestHandlers := svc.AuthenticationMiddleware(
		implementation.NewSecureRouterV1(), jwtAudience, cfg.Oauth2JwtVerifyIssuer)

	proxyMux.Handle("/public/", http.StripPrefix("/public", partitionServiceRestHandlers))
	serviceOptions = append(serviceOptions, frame.WithHTTPHandler(proxyMux))

	return serviceOptions, nil
}

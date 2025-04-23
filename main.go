package main

import (
	"context"
	"log"
	"net/http"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/server"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/sync/errgroup"

	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/gateway/nats"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/gateway/rest"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/service"
)

var conf config.IssuanceServiceConfig

func main() {
	if err := envconfig.Process("ISSUANCE", &conf); err != nil {
		panic(err)
	}

	logger, err := logr.New(conf.LogLevel, conf.IsDev, nil)
	if err != nil {
		panic(err)
	}

	logger.Info("starting service...")
	errGrp, ctx := errgroup.WithContext(context.Background())

	// Will be kept for later retry purposes
	// redisDB, err := database.NewRedisDB(ctx, conf.Redis)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	credentialService := service.NewCredentialService(
		cloudeventprovider.Config{
			Protocol: cloudeventprovider.ProtocolTypeNats,
			Settings: conf.Nats,
		},
		*logger,
	)

	logger.Info("starting nats gateway...")
	natsGW := nats.NewNatsGateway(conf.Nats, credentialService, *logger)
	errGrp.Go(func() error {
		return natsGW.Listen(ctx)
	})

	restGW := rest.NewGateway(credentialService, *logger, conf.JwksUrl, conf.Audience)

	srv := server.New(common.GetEnvironment())
	srv.AddHandler(http.MethodPost, "/credential", restGW.RequestCredential)

	logger.Info("starting rest gateway...")

	errGrp.Go(func() error {
		return srv.Run(conf.ListenPort, conf.ListenAddr)
	})

	logger.Info("ready to accept connections")
	if err := errGrp.Wait(); err != nil {
		log.Fatal(err)
	}

	if err := errGrp.Wait(); err != nil {
		log.Fatal(err)
	}
}

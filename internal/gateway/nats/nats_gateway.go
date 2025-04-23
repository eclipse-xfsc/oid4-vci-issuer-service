package nats

import (
	"context"
	"encoding/json"

	"github.com/cloudevents/sdk-go/v2/event"
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"golang.org/x/sync/errgroup"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/service"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/pkg/messaging"
)

type preAuthReply struct {
	AuthCode string `json:"authCode"`
}

const (
	SourceIssuanceService = "issuance/issuance-service"
)

type NatsGateway struct {
	conf cloudeventprovider.NatsConfig
	svc  service.CredentialService
	log  logr.Logger
}

func NewNatsGateway(conf cloudeventprovider.NatsConfig, svc service.CredentialService, log logr.Logger) NatsGateway {
	log.Info("NATS URL:" + conf.Url)
	return NatsGateway{
		conf: conf,
		svc:  svc,
		log:  log,
	}
}

func (g NatsGateway) Listen(ctx context.Context) error {
	errGrp, errGrpCtx := errgroup.WithContext(ctx)

	errGrp.Go(func() error {
		return g.offerListener(errGrpCtx)
	})

	return errGrp.Wait()
}

func (g NatsGateway) offerListener(ctx context.Context) error {
	g.log.Info("Listen for Requests on " + messaging.TopicOffering)
	offerClient, err := cloudeventprovider.New(cloudeventprovider.Config{
		Settings: cloudeventprovider.NatsConfig{
			Url:          g.conf.Url,
			QueueGroup:   g.conf.QueueGroup,
			TimeoutInSec: g.conf.TimeoutInSec,
		},
		Protocol: "nats",
	}, cloudeventprovider.ConnectionTypeRep, messaging.TopicOffering)

	if err != nil {
		return err
	}

	for {
		if err := offerClient.ReplyCtx(ctx, g.offerHandler); err != nil {
			ctxPkg.GetLogger(ctx).Error(err, "Reply with offerHandler failed")
		}
	}
}

func (g NatsGateway) offerHandler(ctx context.Context, event event.Event) (*event.Event, error) {
	g.log.Info("Offer request received", event.Data())
	var req messaging.OfferingURLReq
	if err := json.Unmarshal(event.Data(), &req); err != nil {
		g.log.Error(err, "could not unmarshal offer")

		return nil, err
	}

	offer, err := g.svc.Offer(ctx, req.TenantId, req.Params)
	if err != nil {
		g.log.Error(err, "failed to create credential offer url")
		return nil, err
	}

	reply := messaging.OfferingURLResp{
		Reply: common.Reply{
			TenantId:  req.TenantId,
			RequestId: req.RequestId,
		},
		CredentialOffer: *offer,
	}

	offerReplyData, err := json.Marshal(reply)
	if err != nil {
		g.log.Error(err, "could not marshal credentialOfferUrl to offerReplyData")
		return nil, err
	}

	offerReplyEvent, err := cloudeventprovider.NewEvent(SourceIssuanceService, messaging.EventTypeOffering, offerReplyData)
	if err != nil {
		g.log.Error(err, "could not create offerReplyEvent")
		return nil, err
	}

	return &offerReplyEvent, nil
}

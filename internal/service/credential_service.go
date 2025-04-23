package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	preAuth "github.com/eclipse-xfsc/oid4-vci-authorization-bridge/pkg/messaging"

	ce "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	wellknown "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/google/uuid"
)

type CredentialService struct {
	cloudEventConfig ce.Config
	log              logr.Logger
}

const supportedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

func NewCredentialService(ceConfig ce.Config, logger logr.Logger) CredentialService {
	return CredentialService{
		cloudEventConfig: ceConfig,
		log:              logger,
	}
}

func (s CredentialService) Offer(ctx context.Context, tenantID string, params messaging.AuthorizationReq) (*credential.CredentialOffer, error) {
	if err := params.Validate(); err != nil {
		s.log.Error(err, "currentOffer not valid")

		return nil, err
	}

	if params.GrantType != supportedGrantType {
		err := fmt.Errorf("grantType '%s' is not supported", params.GrantType)
		s.log.Error(err, "could not proceed with offer")

		return nil, err
	}

	_, issuer, err := s.GetCredentialIssuer(ctx, tenantID, nil, &params.CredentialType)
	if err != nil {
		return nil, err
	}

	preAuthRequestData, err := json.Marshal(preAuth.GenerateAuthorizationReq{
		Request: common.Request{
			TenantId:  tenantID,
			RequestId: uuid.NewString(),
		},
		Nonce:                     params.Nonce,
		CredentialConfigurationId: params.CredentialType,
		CredentialIdentifier:      params.CredentialIdentifier,
		TwoFactor: preAuth.TwoFactor{
			Enabled:          params.TwoFactor.Enabled,
			RecipientType:    params.TwoFactor.RecipientType,
			RecipientAddress: params.TwoFactor.RecipientAddress,
		},
	})
	if err != nil {
		s.log.Error(err, "could not marshal preAuthRequestData")
		return nil, err
	}

	preAuthRequestEvent, err := cloudeventprovider.NewEvent(messaging.SourceIssuanceService, "pre.auth.request.v1", preAuthRequestData)
	if err != nil {
		s.log.Error(err, "could not create preAuthRequestEvent")

		return nil, err
	}

	preAuthClient, err := ce.New(s.cloudEventConfig, ce.ConnectionTypeReq, preAuth.TopicGenerateAuthorization)
	if err != nil {
		s.log.Error(err, "error creating auth client")
		return nil, err
	}

	preAuthReplyEvent, err := preAuthClient.RequestCtx(ctx, preAuthRequestEvent)
	if err != nil {
		s.log.Error(err, "error in request ctx")
		return nil, err
	}

	if preAuthReplyEvent != nil {
		s.log.Info("received auth reply : " + string(preAuthReplyEvent.Data()))
		var preAuthReplyData preAuth.GenerateAuthorizationRep
		if err = json.Unmarshal(preAuthReplyEvent.Data(), &preAuthReplyData); err != nil {
			s.log.Error(err, "could not unmarshal preAuth.GenerateAuthorizationRep")
			return nil, err
		}

		parameters := credential.CredentialOfferParameters{
			CredentialIssuer: *issuer,
			Credentials:      []string{params.CredentialType},
			Grants: credential.Grants{
				PreAuthorizedCode: &credential.PreAuthorizedCode{
					PreAuthorizationCode: preAuthReplyData.Authentication.Code,
					Interval:             5,
				},
			},
		}

		if preAuthReplyData.TxCode != nil {
			parameters.Grants.PreAuthorizedCode.TxCode = preAuthReplyData.TxCode
		}

		link, err := parameters.CreateOfferLink()

		if err != nil {
			return nil, err
		}
		return link, nil
	} else {
		return nil, errors.New("no auth code availble")
	}

}

func (s CredentialService) GetCredential(ctx context.Context, tenantID string, req credential.CredentialRequest, nonce string, configurationId *string) (*types.GetCredentialRespImmediate, error) {

	conf, _, err := s.GetCredentialIssuer(ctx, tenantID, &req.Format, configurationId)
	if err != nil {
		s.log.Error(err, "error during get credential issuer")
		return nil, err
	}
	s.log.Info(fmt.Sprintf("Credential requested for %s and type %s", req.Format, req.CredentialIdentifier))

	credentialRequestData, err := json.Marshal(messaging.IssuanceModuleReq{
		Request: common.Request{
			TenantId:  tenantID,
			RequestId: uuid.NewString(),
		},
		CredentialConfigId:   *configurationId,
		CredentialIdentifier: req.CredentialIdentifier,
		Format:               req.Format,
		Code:                 nonce,
		Holder:               *req.Proof.GetProof(),
		ProofType:            req.Proof.ProofType,
	})

	if err != nil {
		s.log.Error(err, "error during issuing marshalling")
		return nil, err
	}

	getCredentialEvent, err := cloudeventprovider.NewEvent(messaging.SourceIssuanceService, conf.Subject, credentialRequestData)

	if err != nil {
		s.log.Error(err, "create credential event failed")
		return nil, err
	}

	getCredentialClient, err := ce.New(s.cloudEventConfig, ce.ConnectionTypeReq, conf.Subject+".issue")

	if err != nil {
		s.log.Error(err, "create client failed")
		return nil, err
	}

	credentialReplyEvent, err := getCredentialClient.RequestCtx(ctx, getCredentialEvent)
	if err != nil {
		s.log.Error(err, "request credential failed")
		return nil, err
	}

	if credentialReplyEvent != nil {
		s.log.Info("received auth reply " + string(credentialReplyEvent.Data()))

		var credentialReply messaging.IssuanceModuleRep
		if err = json.Unmarshal(credentialReplyEvent.Data(), &credentialReply); err != nil {
			s.log.Error(err, "could not unmarshal messaging.IssuanceModuleRep")
			return nil, err
		}

		if credentialReply.Error != nil {
			s.log.Error(err, credentialReply.Error.Msg)
			return nil, err
		}

		return &types.GetCredentialRespImmediate{
			Reply: common.Reply{
				TenantId:  tenantID,
				RequestId: uuid.NewString(),
			},
			Credential: credentialReply.Credential,
			CNonce:     nonce,
			Format:     credentialReply.Format,
		}, nil
	}

	return &types.GetCredentialRespImmediate{
		Reply: common.Reply{
			TenantId:  tenantID,
			RequestId: uuid.NewString(),
			Error: &common.Error{
				Status: 500,
				Msg:    "No credential reply",
			},
		},
	}, nil
}

func (s CredentialService) GetCredentialIssuer(ctx context.Context, tenantID string, format, credentialType *string) (*credential.CredentialConfiguration, *string, error) {
	if format == nil && credentialType == nil {
		return nil, nil, credential.ErrInvalidCredentialRequest
	}

	issuer, err := s.GetCompleteCredentialIssuer(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}

	if credentialType != nil {
		if conf, ok := issuer.CredentialConfigurationsSupported[*credentialType]; ok {
			return &conf, &issuer.CredentialIssuer, nil
		}

		return nil, nil, credential.ErrUnsupportedCredentialType
	}

	for _, conf := range issuer.CredentialConfigurationsSupported {
		if format != nil && conf.Format == *format {
			return &conf, &issuer.CredentialIssuer, nil
		}
	}

	if format != nil {
		return nil, nil, credential.ErrUnsupportedCredentialFormat
	}

	return nil, nil, fmt.Errorf("no matching issuer found")
}

func (s CredentialService) GetCompleteCredentialIssuer(ctx context.Context, tenantId string) (*credential.IssuerMetadata, error) {
	req := wellknown.GetIssuerMetadataReq{
		Request: common.Request{
			TenantId:  tenantId,
			RequestId: uuid.NewString(),
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request")
	}

	event, err := cloudeventprovider.NewEvent("issuance.service", wellknown.EventTypeGetIssuerMetadata, data)
	if err != nil {

		return nil, fmt.Errorf("could not create requestEvent: %w", err)
	}

	client, err := s.getCloudEventClient(ce.ConnectionTypeReq, wellknown.TopicGetIssuerMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to getCEClient: %w", err)
	}

	res, err := client.RequestCtx(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("could not request wellknown information: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("response data from well known nil. Request was " + string(data))
	}

	var credentialIssuer wellknown.GetIssuerMetadataReply
	if err := json.Unmarshal(res.Data(), &credentialIssuer); err != nil {
		return nil, fmt.Errorf("could not unmarshal wellknown response '%v': %w", res.Data(), err)
	}

	return credentialIssuer.Issuer, nil
}

func (s CredentialService) VerifyAuthToken(ctx context.Context, headerValue string) (string, *string, error) {
	if headerValue == "" {
		return "", nil, fmt.Errorf("missing Authorization")
	}

	parts := strings.Split(headerValue, " ")
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", nil, fmt.Errorf("invalid authorization header, expecting Bearer token")
	}

	token := parts[1]

	req := preAuth.ValidateAuthenticationReq{
		Request: common.Request{
			RequestId: uuid.NewString(),
		},
		Params: preAuth.ValidateAuthenticationReqParams{
			Key: token,
		},
	}

	reqJson, err := json.Marshal(req)
	if err != nil {
		return "", nil, err
	}

	validateEvent, err := ce.NewEvent(messaging.SourceIssuanceService, preAuth.EventTypeValidation, reqJson)

	if err != nil {
		return "", nil, err
	}

	authClient, err := s.getCloudEventClient(ce.ConnectionTypeReq, preAuth.TopicValidation)
	if err != nil {
		return "", nil, err
	}

	respEvent, err := authClient.RequestCtx(ctx, validateEvent)
	if err != nil {
		return "", nil, err
	}

	var reply preAuth.ValidateAuthenticationRep
	if err := json.Unmarshal(respEvent.Data(), &reply); err != nil {
		return "", nil, err
	}

	if !reply.Valid {
		return "", nil, fmt.Errorf("invalid nonce")
	}

	return reply.Nonce, reply.CredentialConfigurationId, nil
}

func (s CredentialService) ValidateProof(proof credential.Proof, audience *string, nonce string) (bool, error) {

	tok, err := proof.CheckProof(*audience, nonce)

	if err != nil {
		return false, err
	}

	token := *tok

	nonceInf, isSet := token.Get("nonce")
	if !isSet {
		return false, fmt.Errorf("invalid authorization specified (missing nonce)")
	}

	if _, ok := nonceInf.(string); !ok {
		return false, fmt.Errorf("invalid nonce sepcified (expected string)")
	}

	if nonceInf.(string) != nonce {
		return false, fmt.Errorf("nonce is not matching")
	}
	return true, nil
}

func (s CredentialService) getCloudEventClient(connectionType ce.ConnectionType, topic string) (*ce.CloudEventProviderClient, error) {
	return ce.New(s.cloudEventConfig, connectionType, topic)
}

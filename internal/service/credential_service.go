package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	preAuth "github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"

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

func (s CredentialService) Offer(ctx context.Context, req messaging.OfferingURLReq, params messaging.AuthorizationReq) (*credential.CredentialOffer, *string, error) {
	if err := params.Validate(); err != nil {
		s.log.Error(err, "currentOffer not valid")

		return nil, nil, err
	}

	if params.GrantType != supportedGrantType {
		err := fmt.Errorf("grantType '%s' is not supported", params.GrantType)
		s.log.Error(err, "could not proceed with offer")

		return nil, nil, err
	}

	_, issuer, err := s.GetCredentialIssuer(ctx, req.TenantId, nil, params.CredentialConfigurations)
	if err != nil {
		return nil, nil, err
	}

	preAuthRequestData, err := json.Marshal(preAuth.GenerateAuthorizationReq{
		Request: common.Request{
			TenantId:  req.TenantId,
			RequestId: req.RequestId,
			GroupId:   req.GroupId,
		},
		Nonce:                    params.Nonce,
		CredentialConfigurations: params.CredentialConfigurations,
		TwoFactor: preAuth.TwoFactor{
			Enabled:          params.TwoFactor.Enabled,
			RecipientType:    params.TwoFactor.RecipientType,
			RecipientAddress: params.TwoFactor.RecipientAddress,
		},
	})

	if err != nil {
		s.log.Error(err, "could not marshal preAuthRequestData")
		return nil, nil, err
	}

	preAuthRequestEvent, err := cloudeventprovider.NewEvent(messaging.SourceIssuanceService, "pre.auth.request.v1", preAuthRequestData)
	if err != nil {
		s.log.Error(err, "could not create preAuthRequestEvent")

		return nil, nil, err
	}

	preAuthClient, err := ce.New(s.cloudEventConfig, ce.ConnectionTypeReq, preAuth.TopicGenerateAuthorization)
	if err != nil {
		s.log.Error(err, "error creating auth client")
		return nil, nil, err
	}

	preAuthReplyEvent, err := preAuthClient.RequestCtx(ctx, preAuthRequestEvent)
	if err != nil {
		s.log.Error(err, "error in request ctx")
		return nil, nil, err
	}

	if preAuthReplyEvent != nil {
		s.log.Info("received auth reply : " + string(preAuthReplyEvent.Data()))
		var preAuthReplyData preAuth.GenerateAuthorizationRep
		if err = json.Unmarshal(preAuthReplyEvent.Data(), &preAuthReplyData); err != nil {
			s.log.Error(err, "could not unmarshal preAuth.GenerateAuthorizationRep")
			return nil, nil, err
		}

		var configIds []string

		for _, c := range params.CredentialConfigurations {
			configIds = append(configIds, c.Id)
		}

		parameters := credential.CredentialOfferParameters{
			CredentialIssuer: *issuer,
			Credentials:      configIds,
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
			return nil, nil, err
		}
		return link, &preAuthReplyData.Code, nil
	} else {
		return nil, nil, errors.New("no auth code availble")
	}

}

func (s CredentialService) GetCredential(ctx context.Context, authRep *preAuth.ValidateAuthenticationRep,
	req credential.CredentialRequest, code, audience, signerKey string) (*types.GetCredentialRespImmediate, error) {

	identifier := credential.CredentialConfigurationIdentifier{
		Id: req.CredentialConfigurationId,
	}

	if req.CredentialIdentifier != "" {
		identifier.CredentialIdentifier = []string{req.CredentialIdentifier}
	}

	conf, _, err := s.GetCredentialIssuer(ctx, authRep.TenantId, &req.Format, []credential.CredentialConfigurationIdentifier{identifier})
	if err != nil {
		s.log.Error(err, "error during get credential issuer")
		return nil, err
	}

	s.log.Info(fmt.Sprintf("Credential requested for %s and type %s", req.Format, req.CredentialIdentifier))
	cmReq := common.Request{
		TenantId:  authRep.TenantId,
		RequestId: authRep.RequestId,
		GroupId:   authRep.GroupId,
	}

	issReq := messaging.IssuanceModuleReq{
		Request:                 cmReq,
		CredentialConfiguration: identifier,
		Format:                  req.Format,
		Nonce:                   authRep.Nonce,
		Subject:                 cmReq.BuildSubject(),
		Code:                    code,
		Origin:                  audience,
		SignerKey:               signerKey,
	}

	if req.Proof != nil {
		issReq.Holder = *req.Proof.GetProof()
		issReq.ProofType = req.Proof.ProofType
	}

	//Build Data for Plugin
	credentialRequestData, err := json.Marshal(issReq)

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
				TenantId:  authRep.TenantId,
				RequestId: authRep.RequestId,
				GroupId:   authRep.GroupId,
			},
			Credential: credentialReply.Credential,
			CNonce:     authRep.Nonce,
			Format:     credentialReply.Format,
		}, nil
	}

	return &types.GetCredentialRespImmediate{
		Reply: common.Reply{
			TenantId:  authRep.TenantId,
			RequestId: uuid.NewString(),
			Error: &common.Error{
				Status: 500,
				Msg:    "No credential reply",
			},
		},
	}, nil
}

func (s CredentialService) GetCredentialIssuer(ctx context.Context, tenantID string, format *string, credentialConfigurations []credential.CredentialConfigurationIdentifier) (*credential.CredentialConfiguration, *string, error) {
	if format == nil && len(credentialConfigurations) == 0 {
		return nil, nil, credential.ErrInvalidCredentialRequest
	}

	issuer, err := s.GetCompleteCredentialIssuer(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}

	if len(credentialConfigurations) != 0 {
		for _, c := range credentialConfigurations {
			if conf, ok := issuer.CredentialConfigurationsSupported[c.Id]; ok {
				return &conf, &issuer.CredentialIssuer, nil
			}
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

func (s CredentialService) VerifyAuthToken(ctx context.Context, tenantId, groupId, headerValue string) (*preAuth.ValidateAuthenticationRep, error) {
	if headerValue == "" {
		return nil, fmt.Errorf("missing Authorization")
	}

	parts := strings.Split(headerValue, " ")
	if !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid authorization header, expecting Bearer token")
	}

	token := parts[1]

	req := preAuth.ValidateAuthenticationReq{
		Request: common.Request{
			RequestId: uuid.NewString(),
			TenantId:  tenantId,
			GroupId:   groupId,
		},
		Params: preAuth.ValidateAuthenticationReqParams{
			Key: token,
		},
	}

	reqJson, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	validateEvent, err := ce.NewEvent(messaging.SourceIssuanceService, preAuth.EventTypeValidation, reqJson)

	if err != nil {
		return nil, err
	}

	authClient, err := s.getCloudEventClient(ce.ConnectionTypeReq, preAuth.TopicValidation)
	if err != nil {
		return nil, err
	}

	respEvent, err := authClient.RequestCtx(ctx, validateEvent)
	if err != nil {
		return nil, err
	}

	if respEvent == nil {
		return nil, errors.New("token not more valid")
	}

	var reply preAuth.ValidateAuthenticationRep
	if err := json.Unmarshal(respEvent.Data(), &reply); err != nil {
		return nil, err
	}

	if !reply.Valid {
		return nil, fmt.Errorf("invalid nonce")
	}

	return &reply, nil
}

func (s CredentialService) getCloudEventClient(connectionType ce.ConnectionType, topic string) (*ce.CloudEventProviderClient, error) {
	return ce.New(s.cloudEventConfig, connectionType, topic)
}

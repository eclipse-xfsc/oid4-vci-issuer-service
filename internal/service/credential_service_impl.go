package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ce "github.com/eclipse-xfsc/cloud-event-provider"
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	wellknown "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	preAuth "github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
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

func NewCredentialService(
	ceConfig ce.Config,
	logger logr.Logger,
) CredentialService {
	return CredentialService{
		cloudEventConfig: ceConfig,
		log:              logger,
	}
}

func (s CredentialService) Offer(
	ctx context.Context,
	req messaging.OfferingURLReq,
	params messaging.AuthorizationReq,
) (*credential.CredentialOffer, *string, error) {

	if err := params.Validate(); err != nil {
		s.log.Error(err, "current offer not valid")
		return nil, nil, err
	}

	if params.GrantType != supportedGrantType {
		err := fmt.Errorf(
			"grant type %q is not supported",
			params.GrantType,
		)

		s.log.Error(
			err,
			"could not proceed with offer",
		)

		return nil, nil, err
	}

	_, issuer, err := s.GetCredentialIssuer(
		ctx,
		req.TenantId,
		params.CredentialConfigurations,
	)
	if err != nil {
		return nil, nil, err
	}

	preAuthRequestData, err := json.Marshal(
		preAuth.GenerateAuthorizationReq{
			Request: common.Request{
				TenantId:  req.TenantId,
				RequestId: req.RequestId,
				GroupId:   req.GroupId,
			},

			Nonce: params.Nonce,

			CredentialConfigurations: params.CredentialConfigurations,

			TwoFactor: preAuth.TwoFactor{
				Enabled:          params.TwoFactor.Enabled,
				RecipientType:    params.TwoFactor.RecipientType,
				RecipientAddress: params.TwoFactor.RecipientAddress,
			},
		},
	)
	if err != nil {
		s.log.Error(
			err,
			"could not marshal preAuthRequestData",
		)

		return nil, nil, err
	}

	preAuthRequestEvent, err := cloudeventprovider.NewEvent(
		messaging.SourceIssuanceService,
		"pre.auth.request.v1",
		preAuthRequestData,
	)
	if err != nil {
		s.log.Error(
			err,
			"could not create preAuthRequestEvent",
		)

		return nil, nil, err
	}

	preAuthClient, err := ce.New(
		s.cloudEventConfig,
		ce.ConnectionTypeReq,
		preAuth.TopicGenerateAuthorization,
	)
	if err != nil {
		s.log.Error(
			err,
			"error creating auth client",
		)

		return nil, nil, err
	}

	preAuthReplyEvent, err := preAuthClient.RequestCtx(
		ctx,
		preAuthRequestEvent,
	)
	if err != nil {
		s.log.Error(
			err,
			"error in request ctx",
		)

		return nil, nil, err
	}

	if preAuthReplyEvent == nil {
		return nil, nil, errors.New(
			"no authorization code available",
		)
	}

	s.log.Info(
		"received auth reply: " +
			string(preAuthReplyEvent.Data()),
	)

	var preAuthReplyData preAuth.GenerateAuthorizationRep

	if err := json.Unmarshal(
		preAuthReplyEvent.Data(),
		&preAuthReplyData,
	); err != nil {

		s.log.Error(
			err,
			"could not unmarshal preAuth.GenerateAuthorizationRep",
		)

		return nil, nil, err
	}

	credentialConfigurationIDs := make(
		[]string,
		0,
		len(params.CredentialConfigurations),
	)

	for _, configuration := range params.CredentialConfigurations {
		credentialConfigurationIDs = append(
			credentialConfigurationIDs,
			configuration.Id,
		)
	}

	parameters := credential.CredentialOfferParameters{
		CredentialIssuer: *issuer,

		CredentialConfigurationIDs: credentialConfigurationIDs,

		Grants: &credential.Grants{
			PreAuthorizedCode: &credential.PreAuthorizedCode{
				PreAuthorizedCode: preAuthReplyData.Authentication.Code,
			},
		},
	}

	if preAuthReplyData.TxCode != nil {
		parameters.Grants.PreAuthorizedCode.TxCode =
			preAuthReplyData.TxCode
	}

	link, err := parameters.CreateOfferLink()
	if err != nil {
		return nil, nil, err
	}

	return link, &preAuthReplyData.Code, nil
}

func (s CredentialService) GetCredential(
	ctx context.Context,
	authRep *preAuth.ValidateAuthenticationRep,
	req credential.CredentialRequest,
	code string,
	audience string,
	signerKey string,
	namespace string,
	group string,
) (*types.GetCredentialRespImmediate, error) {

	if authRep == nil {
		return nil, errors.New(
			"authentication response is nil",
		)
	}

	identifier, conf, err := s.resolveCredentialRequest(
		ctx,
		authRep,
		req,
	)
	if err != nil {
		s.log.Error(
			err,
			"could not resolve credential request",
		)

		return nil, err
	}

	s.log.Info(
		fmt.Sprintf(
			"credential requested for configuration %s",
			identifier.Id,
		),
	)

	cmReq := common.Request{
		TenantId:  authRep.TenantId,
		RequestId: authRep.RequestId,
		GroupId:   authRep.GroupId,
	}

	issReq := messaging.IssuanceModuleReq{
		Request: cmReq,

		CredentialConfiguration: *identifier,

		Format: conf.Format,

		Nonce: authRep.Nonce,

		Subject: cmReq.BuildSubject(),

		Code: code,

		Origin: audience,

		SignerKey: signerKey,

		Namespace: namespace,

		Group: group,
	}

	//
	// OID4VCI 1.0 uses proofs instead of proof.
	//
	if req.Proofs != nil {
		switch {
		case len(req.Proofs.JWT) > 0:
			issReq.Holder = req.Proofs.JWT[0]
			issReq.ProofType = string(
				credential.ProofTypeJWT,
			)

		case len(req.Proofs.DIVP) > 0:
			holder, err := json.Marshal(
				req.Proofs.DIVP[0],
			)
			if err != nil {
				return nil, fmt.Errorf(
					"could not marshal di_vp proof: %w",
					err,
				)
			}

			issReq.Holder = string(holder)
			issReq.ProofType = string(
				credential.ProofTypeDIVP,
			)

		case len(req.Proofs.Attestation) > 0:
			issReq.Holder = req.Proofs.Attestation[0]
			issReq.ProofType = string(
				credential.ProofTypeAttestation,
			)
		}
	}

	credentialRequestData, err := json.Marshal(
		issReq,
	)
	if err != nil {
		s.log.Error(
			err,
			"error during issuing marshalling",
		)

		return nil, err
	}

	getCredentialEvent, err := cloudeventprovider.NewEvent(
		messaging.SourceIssuanceService,
		conf.Subject,
		credentialRequestData,
	)
	if err != nil {
		s.log.Error(
			err,
			"create credential event failed",
		)

		return nil, err
	}

	getCredentialClient, err := ce.New(
		s.cloudEventConfig,
		ce.ConnectionTypeReq,
		conf.Subject+".issue",
	)
	if err != nil {
		s.log.Error(
			err,
			"create client failed",
		)

		return nil, err
	}

	credentialReplyEvent, err := getCredentialClient.RequestCtx(
		ctx,
		getCredentialEvent,
	)
	if err != nil {
		s.log.Error(
			err,
			"request credential failed",
		)

		return nil, err
	}

	if credentialReplyEvent == nil {
		return nil, errors.New("No credential reply")
	}

	s.log.Info(
		"received credential reply " +
			string(credentialReplyEvent.Data()),
	)

	var credentialReply messaging.IssuanceModuleRep

	if err := json.Unmarshal(
		credentialReplyEvent.Data(),
		&credentialReply,
	); err != nil {

		s.log.Error(
			err,
			"could not unmarshal messaging.IssuanceModuleRep",
		)

		return nil, err
	}

	if credentialReply.Error != nil {
		err := errors.New(
			credentialReply.Error.Msg,
		)

		s.log.Error(
			err,
			"credential issuance failed",
		)

		return nil, err
	}

	return &types.GetCredentialRespImmediate{
		Credentials: []types.CredentialResponseItem{
			types.CredentialResponseItem{
				Credential: credentialReply.Credential,
			},
		},
	}, nil
}

func (s CredentialService) resolveCredentialRequest(
	ctx context.Context,
	authRep *preAuth.ValidateAuthenticationRep,
	req credential.CredentialRequest,
) (
	*credential.CredentialConfigurationIdentifier,
	*credential.CredentialConfiguration,
	error,
) {

	//
	// credential_configuration_id flow
	//

	if req.CredentialConfigurationID != "" {
		identifier := credential.CredentialConfigurationIdentifier{
			Id: req.CredentialConfigurationID,
		}

		conf, _, err := s.GetCredentialIssuer(
			ctx,
			authRep.TenantId,
			[]credential.CredentialConfigurationIdentifier{
				identifier,
			},
		)
		if err != nil {
			return nil, nil, err
		}

		return &identifier, conf, nil
	}

	//
	// credential_identifier flow
	//

	if req.CredentialIdentifier == "" {
		return nil, nil,
			credential.ErrInvalidCredentialRequest
	}

	identifier, err := resolveCredentialIdentifier(
		authRep,
		req.CredentialIdentifier,
	)
	if err != nil {
		return nil, nil, err
	}

	conf, _, err := s.GetCredentialIssuer(
		ctx,
		authRep.TenantId,
		[]credential.CredentialConfigurationIdentifier{
			*identifier,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	return identifier, conf, nil
}

func resolveCredentialIdentifier(
	authRep *preAuth.ValidateAuthenticationRep,
	credentialIdentifier string,
) (
	*credential.CredentialConfigurationIdentifier,
	error,
) {

	if authRep == nil {
		return nil,
			credential.ErrInvalidCredentialRequest
	}

	for _, configuration := range authRep.CredentialConfigurations {
		for _, identifier := range configuration.CredentialIdentifiers {

			if identifier != credentialIdentifier {
				continue
			}

			resolved := configuration

			resolved.CredentialIdentifiers = []string{
				credentialIdentifier,
			}

			return &resolved, nil
		}
	}

	return nil,
		credential.ErrUnknownCredentialIdentifier
}

func (s CredentialService) GetCredentialIssuer(
	ctx context.Context,
	tenantID string,
	credentialConfigurations []credential.CredentialConfigurationIdentifier,
) (
	*credential.CredentialConfiguration,
	*string,
	error,
) {

	if len(credentialConfigurations) == 0 {
		return nil, nil,
			credential.ErrInvalidCredentialRequest
	}

	issuer, err := s.GetCompleteCredentialIssuer(
		ctx,
		tenantID,
	)
	if err != nil {
		return nil, nil, err
	}

	if issuer == nil {
		return nil, nil,
			errors.New("credential issuer metadata is nil")
	}

	for _, requested := range credentialConfigurations {
		if requested.Id == "" {
			continue
		}

		conf, ok :=
			issuer.CredentialConfigurationsSupported[requested.Id]

		if ok {
			return &conf,
				&issuer.CredentialIssuer,
				nil
		}
	}

	return nil, nil,
		credential.ErrUnknownCredentialConfiguration
}

func (s CredentialService) GetCompleteCredentialIssuer(
	ctx context.Context,
	tenantID string,
) (*credential.IssuerMetadata, error) {

	req := wellknown.GetIssuerMetadataReq{
		Request: common.Request{
			TenantId:  tenantID,
			RequestId: uuid.NewString(),
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to marshal request: %w",
			err,
		)
	}

	event, err := cloudeventprovider.NewEvent(
		messaging.SourceIssuanceService,
		wellknown.EventTypeGetIssuerMetadata,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create request event: %w",
			err,
		)
	}

	client, err := s.getCloudEventClient(
		ce.ConnectionTypeReq,
		wellknown.TopicGetIssuerMetadata,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get cloud event client: %w",
			err,
		)
	}

	res, err := client.RequestCtx(
		ctx,
		event,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not request well-known information: %w",
			err,
		)
	}

	if res == nil {
		return nil, fmt.Errorf(
			"well-known response is nil; request was %s",
			string(data),
		)
	}

	var credentialIssuer wellknown.GetIssuerMetadataReply

	if err := json.Unmarshal(
		res.Data(),
		&credentialIssuer,
	); err != nil {

		return nil, fmt.Errorf(
			"could not unmarshal well-known response %q: %w",
			string(res.Data()),
			err,
		)
	}

	if credentialIssuer.Issuer == nil {
		return nil, errors.New(
			"credential issuer metadata is missing",
		)
	}

	return credentialIssuer.Issuer, nil
}

func (s CredentialService) VerifyAuthToken(
	ctx context.Context,
	tenantID string,
	groupID string,
	headerValue string,
) (*preAuth.ValidateAuthenticationRep, error) {

	if headerValue == "" {
		return nil, errors.New(
			"missing Authorization header",
		)
	}

	parts := strings.Fields(headerValue)

	if len(parts) != 2 {
		return nil, errors.New(
			"invalid Authorization header",
		)
	}

	if !strings.EqualFold(
		parts[0],
		"Bearer",
	) {
		return nil, errors.New(
			"invalid authorization scheme, expected Bearer",
		)
	}

	token := parts[1]

	if token == "" {
		return nil, errors.New(
			"bearer token is empty",
		)
	}

	req := preAuth.ValidateAuthenticationReq{
		Request: common.Request{
			RequestId: uuid.NewString(),
			TenantId:  tenantID,
			GroupId:   groupID,
		},

		Params: preAuth.ValidateAuthenticationReqParams{
			Key: token,
		},
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	validateEvent, err := ce.NewEvent(
		messaging.SourceIssuanceService,
		preAuth.EventTypeValidation,
		reqJSON,
	)
	if err != nil {
		return nil, err
	}

	authClient, err := s.getCloudEventClient(
		ce.ConnectionTypeReq,
		preAuth.TopicValidation,
	)
	if err != nil {
		return nil, err
	}

	respEvent, err := authClient.RequestCtx(
		ctx,
		validateEvent,
	)
	if err != nil {
		return nil, err
	}

	if respEvent == nil {
		return nil, errors.New(
			"access token is no longer valid",
		)
	}

	var reply preAuth.ValidateAuthenticationRep

	if err := json.Unmarshal(
		respEvent.Data(),
		&reply,
	); err != nil {

		return nil, err
	}

	if !reply.Valid {
		return nil, errors.New(
			"access token is invalid",
		)
	}

	return &reply, nil
}

func (s CredentialService) getCloudEventClient(
	connectionType ce.ConnectionType,
	topic string,
) (*ce.CloudEventProviderClient, error) {

	return ce.New(
		s.cloudEventConfig,
		connectionType,
		topic,
	)
}

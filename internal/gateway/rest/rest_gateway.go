package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/service"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	crypto "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/gin-gonic/gin"
)

type RestGateway struct {
	svc         service.CredentialService
	log         logr.Logger
	audience    string
	jwksURL     string
	nonceSecret string
}

func NewGateway(
	svc service.CredentialService,
	log logr.Logger,
	jwksURL string,
	audience string,
	nonceSecret string,
) RestGateway {
	return RestGateway{
		svc:         svc,
		log:         log,
		audience:    audience,
		jwksURL:     jwksURL,
		nonceSecret: nonceSecret,
	}
}

func (g RestGateway) RequestCredential(c *gin.Context) {
	tenantID := c.Param("tenantId")

	if tenantID == "" {
		err := errors.New("tenant ID is empty")

		g.log.Error(err, "tenant ID missing")

		c.JSON(
			http.StatusBadRequest,
			credential.ErrInvalidCredentialRequest,
		)

		return
	}

	//
	// Resolve runtime configuration.
	//

	jwksURL := g.jwksURL

	if header := c.GetHeader("x-jwks-url"); header != "" {
		jwksURL = header
	}

	audience := g.audience

	if header := c.GetHeader("x-audience-url"); header != "" {
		audience = header
	}

	signerKey := "signerKey"

	if header := c.GetHeader("x-signerkey"); header != "" {
		signerKey = header
	}

	groupID := ""

	if header := c.GetHeader("x-groupId"); header != "" {
		groupID = header
	}

	namespace := ""

	if header := c.GetHeader("x-namespace"); header != "" {
		namespace = header
	}

	group := ""

	if header := c.GetHeader("x-group"); header != "" {
		group = header
	}

	//
	// Verify Access Token signature.
	//

	token, err := crypto.ParseRequestWithJWKS(
		c.Request,
		jwksURL,
	)
	if err != nil {
		g.log.Info(
			"Parameters:",
			"data",
			map[string]string{
				"audience":  audience,
				"jwks":      jwksURL,
				"groupId":   groupID,
				"group":     group,
				"tenantid":  tenantID,
				"signerkey": signerKey,
				"namespace": namespace,
			},
		)

		g.log.Error(
			err,
			"access token signature validation failed",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	if token == nil {
		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	subject := token.Subject()

	if subject == "" {
		err := errors.New(
			"access token contains no subject",
		)

		g.log.Error(
			err,
			"subject validation failed",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	//
	// Decode Credential Request.
	//

	var req credential.CredentialRequest

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		g.log.Error(
			err,
			"could not decode credential request",
		)

		c.JSON(
			http.StatusBadRequest,
			credential.ErrInvalidCredentialRequest,
		)

		return
	}

	//
	// Exactly one of:
	//
	//   credential_identifier
	//   credential_configuration_id
	//
	// must be present.
	//

	hasCredentialIdentifier :=
		req.CredentialIdentifier != ""

	hasCredentialConfigurationID :=
		req.CredentialConfigurationID != ""

	if hasCredentialIdentifier == hasCredentialConfigurationID {
		err := errors.New(
			"exactly one of credential_identifier or credential_configuration_id must be present",
		)

		g.log.Error(
			err,
			"invalid credential request",
		)

		c.JSON(
			http.StatusBadRequest,
			credential.ErrInvalidCredentialRequest,
		)

		return
	}

	//
	// Validate Access Token against authorization bridge state.
	//

	authRep, err := g.svc.VerifyAuthToken(
		c.Request.Context(),
		tenantID,
		groupID,
		c.Request.Header.Get("Authorization"),
	)
	if err != nil {
		g.log.Error(
			err,
			"access token validation failed",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	if authRep == nil {
		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	//
	// Tenant binding.
	//

	if authRep.TenantId != tenantID {
		err := errors.New(
			"tenant ID does not match access token",
		)

		g.log.Error(
			err,
			"tenant mismatch",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	//
	// Subject binding.
	//

	tokenRequest := common.Request{
		TenantId:  authRep.TenantId,
		RequestId: authRep.RequestId,
		GroupId:   authRep.GroupId,
	}

	if tokenRequest.BuildSubject() != subject {
		err := errors.New(
			"access token subject does not match request context",
		)

		g.log.Error(
			err,
			"subject mismatch",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	//
	// Load issuer metadata.
	//

	metadata, err := g.svc.GetCompleteCredentialIssuer(
		c.Request.Context(),
		tenantID,
	)
	if err != nil {
		g.log.Error(
			err,
			"could not load credential issuer metadata",
		)

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "server_error",
			},
		)

		return
	}

	if metadata == nil {
		err := errors.New(
			"credential issuer metadata is nil",
		)

		g.log.Error(
			err,
			"could not load credential issuer metadata",
		)

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "server_error",
			},
		)

		return
	}

	//
	// Resolve Credential Configuration.
	//

	credentialConfigurationID, err :=
		resolveCredentialConfigurationID(
			req,
			authRep.CredentialConfigurations,
		)

	if err != nil {
		g.log.Error(
			err,
			"could not resolve credential configuration",
		)

		if errors.Is(
			err,
			credential.ErrUnknownCredentialIdentifier,
		) {
			c.JSON(
				http.StatusBadRequest,
				credential.ErrUnknownCredentialIdentifier,
			)
		} else {
			c.JSON(
				http.StatusBadRequest,
				credential.ErrUnknownCredentialConfiguration,
			)
		}

		return
	}

	credentialConfiguration, ok :=
		metadata.CredentialConfigurationsSupported[credentialConfigurationID]

	if !ok {
		err := errors.New(
			"credential configuration is not supported",
		)

		g.log.Error(
			err,
			"unknown credential configuration",
		)

		c.JSON(
			http.StatusBadRequest,
			credential.ErrUnknownCredentialConfiguration,
		)

		return
	}

	//
	// Validate request and proof(s).
	//
	// If nonceSecret is configured, the library requires a nonce
	// and validates:
	//
	//   - HMAC
	//   - expiration
	//   - tenant binding
	//

	valid, err := req.CheckRequestValid(
		audience,
		tenantID,
		g.nonceSecret,
		credentialConfiguration.ProofTypesSupported,
	)

	if err != nil || !valid {
		if err != nil {
			g.log.Error(
				err,
				"credential request validation failed",
			)
		}

		//
		// TODO:
		// Replace textual inspection with typed library errors.
		//
		if err != nil &&
			strings.Contains(
				strings.ToLower(err.Error()),
				"nonce",
			) {

			c.JSON(
				http.StatusBadRequest,
				credential.ErrInvalidNonce,
			)

			return
		}

		c.JSON(
			http.StatusBadRequest,
			credential.ErrInvalidProof,
		)

		return
	}

	//
	// Extract issuer-internal code from access token.
	//

	codeValue, ok := token.Get("code")

	if !ok {
		err := errors.New(
			"access token contains no code claim",
		)

		g.log.Error(
			err,
			"missing code claim",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	code, ok := codeValue.(string)

	if !ok || code == "" {
		err := errors.New(
			"access token code claim is invalid",
		)

		g.log.Error(
			err,
			"invalid code claim",
		)

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "invalid_token",
			},
		)

		return
	}

	//
	// Issue Credential.
	//

	cred, err := g.svc.GetCredential(
		c.Request.Context(),
		authRep,
		req,
		code,
		audience,
		signerKey,
		namespace,
		group,
	)

	if err != nil {
		g.log.Error(
			err,
			"error during credential issuance",
		)

		switch {
		case errors.Is(
			err,
			credential.ErrUnknownCredentialIdentifier,
		):
			c.JSON(
				http.StatusBadRequest,
				credential.ErrUnknownCredentialIdentifier,
			)

		case errors.Is(
			err,
			credential.ErrUnknownCredentialConfiguration,
		):
			c.JSON(
				http.StatusBadRequest,
				credential.ErrUnknownCredentialConfiguration,
			)

		default:
			c.JSON(
				http.StatusBadRequest,
				credential.ErrInvalidCredentialRequest,
			)
		}

		return
	}

	c.JSON(
		http.StatusOK,
		cred,
	)
}

type nonceResponse struct {
	CNonce string `json:"c_nonce"`
}

func (g RestGateway) RequestNonce(c *gin.Context) {
	tenantID := c.Param("tenantId")

	if tenantID == "" {
		g.log.Error(
			errors.New("tenant ID is empty"),
			"could not create nonce",
		)

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": "invalid_request",
			},
		)

		return
	}

	nonce, err := credential.CreateNonce(
		g.nonceSecret,
		tenantID,
		credential.DefaultNonceTTL,
	)
	if err != nil {
		g.log.Error(
			err,
			"could not create nonce",
		)

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "server_error",
			},
		)

		return
	}

	c.JSON(
		http.StatusOK,
		nonceResponse{
			CNonce: nonce,
		},
	)
}

func resolveCredentialConfigurationID(
	req credential.CredentialRequest,
	authorizedConfigurations []credential.CredentialConfigurationIdentifier,
) (string, error) {

	//
	// Flow 1:
	// credential_configuration_id was sent directly.
	//

	if req.CredentialConfigurationID != "" {
		for _, configuration := range authorizedConfigurations {
			if configuration.Id == req.CredentialConfigurationID {
				return configuration.Id, nil
			}
		}

		return "",
			credential.ErrUnknownCredentialConfiguration
	}

	//
	// Flow 2:
	// credential_identifier was returned during token issuance
	// and now has to be mapped back to its configuration.
	//

	if req.CredentialIdentifier != "" {
		for _, configuration := range authorizedConfigurations {
			for _, identifier := range configuration.CredentialIdentifiers {

				if identifier == req.CredentialIdentifier {
					return configuration.Id, nil
				}
			}
		}

		return "",
			credential.ErrUnknownCredentialIdentifier
	}

	return "",
		credential.ErrInvalidCredentialRequest
}

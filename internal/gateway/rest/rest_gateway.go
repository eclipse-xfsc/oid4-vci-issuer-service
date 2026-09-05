package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	crypto "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/gin-gonic/gin"
)

type RestGateway struct {
	svc         credentialService
	log         logr.Logger
	audience    string
	jwksURL     string
	nonceSecret string
}

func NewGateway(
	svc credentialService,
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
	// Normalize legacy / interoperability request variants.
	//
	// Example:
	//
	//   "proof": {
	//     "proof_type": "jwt",
	//     "jwt": "..."
	//   }
	//
	// becomes:
	//
	//   "proofs": {
	//     "jwt": ["..."]
	//   }
	//
	// The legacy "format" field is accepted by the request model but is
	// intentionally not used for credential selection.
	//

	req.Normalize()

	if req.Format != "" {
		g.log.Info(
			"legacy credential request format received",
			"format", req.Format,
		)
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
	// Validate interoperability vct hint.
	//
	// Some wallets send "vct" in the Credential Request even though
	// credential selection is done via credential_configuration_id or
	// credential_identifier.
	//
	// Therefore:
	//   - never use req.VCT for configuration selection
	//   - if present, validate it against the resolved configuration
	//

	if req.VCT != "" {
		if *credentialConfiguration.Vct == "" {
			g.log.Info(
				"credential request contains vct but resolved configuration has no vct",
				"request_vct", req.VCT,
				"credential_configuration_id", credentialConfigurationID,
			)
		} else if req.VCT != *credentialConfiguration.Vct {
			err := errors.New(
				"credential request vct does not match resolved credential configuration",
			)

			g.log.Error(
				err,
				"credential vct mismatch",
				"request_vct", req.VCT,
				"configuration_vct", credentialConfiguration.Vct,
				"credential_configuration_id", credentialConfigurationID,
			)

			c.JSON(
				http.StatusBadRequest,
				credential.ErrInvalidCredentialRequest,
			)

			return
		}
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

	nonce := ""

	if metadata.NonceEndpoint != nil {
		nonce = g.nonceSecret
	}

	//
	// Do not dereference req.Proofs.JWT[0] without checking it first.
	// A supported configuration may use a different proof type, or the
	// request may simply be malformed.
	//

	switch {
	case req.Proofs == nil:
		g.log.Info(
			"credential request contains no proofs",
		)

	case len(req.Proofs.JWT) > 0:
		g.log.Info(
			"credential JWT proof received",
			"proof", req.Proofs.JWT[0],
		)

	case len(req.Proofs.DIVP) > 0:
		g.log.Info(
			"credential di_vp proof received",
			"count", len(req.Proofs.DIVP),
		)

	case len(req.Proofs.Attestation) > 0:
		g.log.Info(
			"credential attestation proof received",
			"count", len(req.Proofs.Attestation),
		)
	}

	valid, err := req.CheckRequestValid(
		audience,
		tenantID,
		nonce,
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

	g.log.Info(
		"Credential issued",
		"credential", cred,
	)

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

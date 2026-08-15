package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/service"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	crypto "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type RestGateway struct {
	svc      service.CredentialService
	log      logr.Logger
	audience string
	jwksUrl  string
}

func NewGateway(svc service.CredentialService, log logr.Logger, jwksUrl string, audience string) RestGateway {
	return RestGateway{
		svc:      svc,
		log:      log,
		audience: audience,
		jwksUrl:  jwksUrl,
	}
}

func (g RestGateway) RequestCredential(c *gin.Context) {
	var token jwt.Token
	var err error

	jwksURL := g.jwksUrl // Default

	if header := c.GetHeader("x-jwks-url"); header != "" {

		jwksURL = header

	}

	audience := g.audience // Default

	if header := c.GetHeader("x-audience-url"); header != "" {

		audience = header

	}

	if token, err = crypto.ParseRequestWithJWKS(c.Request, jwksURL); err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	if err != nil {
		g.log.Error(err, "token error")
		c.JSON(401, map[string]string{"error": "unauthorized"})
		return
	}

	subject := token.Subject()

	if subject == "" {
		g.log.Error(err, "subject error")
		c.JSON(400, map[string]string{"error": "no subject present"})
		return
	}

	var req credential.CredentialRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		g.log.Error(errors.New("decoding error"), "decoding error")
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	if req.Format != "" && req.CredentialIdentifier != "" && req.CredentialConfigurationId != "" {
		g.log.Error(errors.New("unclear parameters"), "Either format or credential identifier or credential configuration id can be used")
		c.JSON(400, credential.ErrUnsupportedCredentialFormat)
		return
	}

	if req.CredentialConfigurationId == "" && req.Format == "" && req.CredentialIdentifier == "" {
		g.log.Error(errors.New("missing credential configuration or format"), "missing credential identifier, credentialconfiguration or format")
		c.JSON(400, credential.ErrUnsupportedCredentialFormat)
		return
	}

	tenantID := c.Param("tenantId")

	if tenantID == "" {
		g.log.Error(errors.ErrUnsupported, "Tenant ID Empty.", nil)
		c.JSON(400, map[string]string{"error": "Tenant ID Empty"})
		return
	}

	authRep, err := g.svc.VerifyAuthToken(c.Request.Context(), c.Request.Header.Get("Authorization"))

	if err != nil {
		g.log.Error(err, err.Error())
		c.JSON(401, map[string]string{"error": "unauthorized"})
		return
	}

	if authRep.TenantId != tenantID {
		g.log.Error(err, "mismatch in tenant id route and auth token usage")
		c.JSON(401, credential.ErrInvalidCredentialRequest)
		return
	}

	tmpReq := common.Request{
		TenantId:  authRep.TenantId,
		RequestId: authRep.RequestId,
		GroupId:   authRep.GroupId,
	}

	if tmpReq.BuildSubject() != subject {
		g.log.Error(err, "mismatch in subject")
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	metadata, err := g.svc.GetCompleteCredentialIssuer(c.Request.Context(), tenantID)

	if err != nil || metadata == nil {
		g.log.Error(err, err.Error())
		c.JSON(400, map[string]string{
			"error": "error during getting metadata",
		})
		return
	}

	if req.Format != "" {
		var credentialConfig credential.CredentialConfiguration
		var ok = false
		if metadata != nil {
			for i, c := range metadata.CredentialConfigurationsSupported {
				if c.Format == req.Format {
					credentialConfig = c
					req.CredentialConfigurationId = i
					ok = true
					break
				}
			}
		}

		err := req.Proof.CheckProof(audience, authRep.Nonce, credentialConfig.ProofTypesSupported)

		if err != nil {
			g.log.Error(err, "proof invalid")
			c.JSON(400, credential.ErrInvalidProof)
			return
		}

		if err != nil || metadata == nil || !ok {
			g.log.Error(errors.New("unsupported format or identifier"), "unsupported format or identifier")
			if err != nil {
				g.log.Error(err, err.Error())
			}
			c.JSON(400, credential.ErrUnsupportedCredentialFormat)
			return
		}
	} else {
		if req.CredentialIdentifier != "" {
			//when just credential identifier is sent, find out the config id (stupid spec)
			for _, c := range authRep.CredentialConfigurations {
				if slices.Contains(c.CredentialIdentifier, req.CredentialIdentifier) {
					req.CredentialConfigurationId = c.Id
					break
				}
			}
		}
	}

	code, ok := token.Get("code")

	if !ok {
		code = "no code provided in token"
	}

	cc, ok := code.(string)

	if !ok {
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	cred, err := g.svc.GetCredential(c, authRep, req, cc, audience)
	if err != nil {
		g.log.Error(err, "Error during Get Credential")
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	c.JSON(http.StatusOK, cred)
}

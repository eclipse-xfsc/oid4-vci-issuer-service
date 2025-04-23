package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/service"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	crypto "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/eclipse-xfsc/ssi-jwt/fetcher"
	"github.com/gin-gonic/gin"
)

type RestGateway struct {
	svc      service.CredentialService
	log      logr.Logger
	audience string
}

func NewGateway(svc service.CredentialService, log logr.Logger, jwksUrl string, audience string) RestGateway {
	jwksFetcher := new(fetcher.JwksFetcher)
	jwksFetcher.Initialize([]string{jwksUrl}, time.Minute*15)
	crypto.RegisterFetcher("JWKS1", jwksFetcher)

	return RestGateway{
		svc:      svc,
		log:      log,
		audience: audience,
	}
}

func (g RestGateway) RequestCredential(c *gin.Context) {
	if _, err := crypto.ParseRequest(c.Request); err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	var req credential.CredentialRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		g.log.Error(errors.New("decoding error"), "decoding error")
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	if req.Format != "" && req.CredentialIdentifier != "" {
		g.log.Error(errors.New("unclear parameters"), "Either format or credential identifier can be used")
		c.JSON(400, credential.ErrUnsupportedCredentialFormat)
		return
	}

	if req.CredentialIdentifier == "" && req.Format == "" {
		g.log.Error(errors.New("missing credential identifier or format"), "missing credential identifier or format")
		c.JSON(400, credential.ErrUnsupportedCredentialFormat)
		return
	}

	tenantID := c.Param("tenantId")

	if tenantID == "" {
		g.log.Error(errors.ErrUnsupported, "Tenant ID Empty.", nil)
		c.JSON(400, "Tenant ID Empty")
		return
	}

	nonce, config, err := g.svc.VerifyAuthToken(c.Request.Context(), c.Request.Header.Get("Authorization"))

	if err != nil {
		g.log.Error(err, err.Error())
		c.JSON(400, credential.ErrInvalidCredentialRequest)
		return
	}

	valid, err := g.svc.ValidateProof(*req.Proof, &g.audience, nonce)

	if !valid || err != nil {
		g.log.Error(err, "proof invalid")
		c.JSON(400, credential.ErrInvalidProof)
		return
	}
	var configId = ""
	if req.Format != "" {
		metadata, err := g.svc.GetCompleteCredentialIssuer(c.Request.Context(), tenantID)

		var ok = false
		if metadata != nil {
			for i, c := range metadata.CredentialConfigurationsSupported {
				if c.Format == req.Format {
					configId = i
					break
				}
			}
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
		configId = *config
	}

	credential, err := g.svc.GetCredential(c, tenantID, req, nonce, &configId)
	if err != nil {
		g.log.Error(err, "Error during Get Credential")
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, credential)
}

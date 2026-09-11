package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/nats-message-library/common"
	preAuth "github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const (
	testTenantID = "demo_tenant"
	testAudience = "https://issuer.example.com"
	testKeyID    = "access-token-key"
	testCode     = "issuer-code"
	testGroupID  = "group-id"
)

type fakeCredentialService struct {
	verifyAuthTokenFn func(
		ctx context.Context,
		tenantID string,
		groupID string,
		headerValue string,
	) (*preAuth.ValidateAuthenticationRep, error)

	getCompleteCredentialIssuerFn func(
		ctx context.Context,
		tenantID string,
	) (*credential.IssuerMetadata, error)

	getCredentialFn func(
		ctx context.Context,
		authRep *preAuth.ValidateAuthenticationRep,
		req credential.CredentialRequest,
		code string,
		audience string,
		signerKey string,
		namespace string,
		group string,
	) (*types.GetCredentialRespImmediate, error)
}

func (f *fakeCredentialService) VerifyAuthToken(
	ctx context.Context,
	tenantID string,
	groupID string,
	headerValue string,
) (*preAuth.ValidateAuthenticationRep, error) {
	if f.verifyAuthTokenFn == nil {
		panic("unexpected VerifyAuthToken call")
	}

	return f.verifyAuthTokenFn(
		ctx,
		tenantID,
		groupID,
		headerValue,
	)
}

func (f *fakeCredentialService) GetCompleteCredentialIssuer(
	ctx context.Context,
	tenantID string,
) (*credential.IssuerMetadata, error) {
	if f.getCompleteCredentialIssuerFn == nil {
		panic("unexpected GetCompleteCredentialIssuer call")
	}

	return f.getCompleteCredentialIssuerFn(
		ctx,
		tenantID,
	)
}

func (f *fakeCredentialService) GetCredential(
	ctx context.Context,
	authRep *preAuth.ValidateAuthenticationRep,
	req credential.CredentialRequest,
	code string,
	audience string,
	signerKey string,
	namespace string,
	group string,
) (*types.GetCredentialRespImmediate, error) {
	if f.getCredentialFn == nil {
		panic("unexpected GetCredential call")
	}

	return f.getCredentialFn(
		ctx,
		authRep,
		req,
		code,
		audience,
		signerKey,
		namespace,
		group,
	)
}

func TestResolveCredentialConfigurationID_ConfigurationID(t *testing.T) {
	req := credential.CredentialRequest{
		CredentialConfigurationID: "SDJWTCredential",
	}

	authorized := []credential.CredentialConfigurationIdentifier{
		{
			Id:                    "SDJWTCredential",
			CredentialIdentifiers: []string{"developer-credential"},
		},
	}

	got, err := resolveCredentialConfigurationID(
		req,
		authorized,
	)

	require.NoError(t, err)
	require.Equal(t, "SDJWTCredential", got)
}

func TestResolveCredentialConfigurationID_CredentialIdentifier(t *testing.T) {
	req := credential.CredentialRequest{
		CredentialIdentifier: "developer-credential",
	}

	authorized := []credential.CredentialConfigurationIdentifier{
		{
			Id:                    "SDJWTCredential",
			CredentialIdentifiers: []string{"developer-credential"},
		},
	}

	got, err := resolveCredentialConfigurationID(
		req,
		authorized,
	)

	require.NoError(t, err)
	require.Equal(t, "SDJWTCredential", got)
}

func TestResolveCredentialConfigurationID_UnknownConfiguration(t *testing.T) {
	req := credential.CredentialRequest{
		CredentialConfigurationID: "unknown",
	}

	got, err := resolveCredentialConfigurationID(
		req,
		[]credential.CredentialConfigurationIdentifier{
			{Id: "SDJWTCredential"},
		},
	)

	require.Empty(t, got)
	require.ErrorIs(
		t,
		err,
		credential.ErrUnknownCredentialConfiguration,
	)
}

func TestResolveCredentialConfigurationID_UnknownIdentifier(t *testing.T) {
	req := credential.CredentialRequest{
		CredentialIdentifier: "unknown",
	}

	got, err := resolveCredentialConfigurationID(
		req,
		[]credential.CredentialConfigurationIdentifier{
			{
				Id:                    "SDJWTCredential",
				CredentialIdentifiers: []string{"known"},
			},
		},
	)

	require.Empty(t, got)
	require.ErrorIs(
		t,
		err,
		credential.ErrUnknownCredentialIdentifier,
	)
}

func TestResolveCredentialConfigurationID_Empty(t *testing.T) {
	got, err := resolveCredentialConfigurationID(
		credential.CredentialRequest{},
		nil,
	)

	require.Empty(t, got)
	require.ErrorIs(
		t,
		err,
		credential.ErrInvalidCredentialRequest,
	)
}

func TestCredentialRequest_NormalizeLegacyJWTProof(t *testing.T) {
	req := credential.CredentialRequest{
		Format: "dc+sd-jwt",
		Proof: &credential.CredentialProof{
			ProofType: "jwt",
			JWT:       "legacy-proof",
		},
	}

	req.Normalize()

	require.NotNil(t, req.Proofs)
	require.Equal(
		t,
		[]string{"legacy-proof"},
		req.Proofs.JWT,
	)
}

func TestCredentialRequest_NormalizeDoesNotOverrideOID4VCI10Proofs(t *testing.T) {
	req := credential.CredentialRequest{
		Proofs: &credential.CredentialProofs{
			JWT: []string{"oid4vci-1.0-proof"},
		},
		Proof: &credential.CredentialProof{
			ProofType: "jwt",
			JWT:       "legacy-proof",
		},
	}

	req.Normalize()

	require.Equal(
		t,
		[]string{"oid4vci-1.0-proof"},
		req.Proofs.JWT,
	)
}

func TestRequestNonce_Success(t *testing.T) {
	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)

	ctx, recorder := newGinContext(
		http.MethodPost,
		"/v1/tenants/"+testTenantID+"/nonce",
		nil,
	)

	ctx.Params = gin.Params{
		{
			Key:   "tenantId",
			Value: testTenantID,
		},
	}

	gateway.RequestNonce(ctx)

	require.Equal(
		t,
		http.StatusOK,
		recorder.Code,
	)

	var response nonceResponse

	require.NoError(
		t,
		json.Unmarshal(
			recorder.Body.Bytes(),
			&response,
		),
	)

	require.NotEmpty(t, response.CNonce)
}

func TestRequestNonce_MissingTenant(t *testing.T) {
	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)

	ctx, recorder := newGinContext(
		http.MethodPost,
		"/v1/tenants//nonce",
		nil,
	)

	gateway.RequestNonce(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_request"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_MissingTenant(t *testing.T) {
	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)

	ctx, recorder := newGinContext(
		http.MethodPost,
		"/v1/tenants//credential",
		[]byte(`{}`),
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.InvalidCredentialRequest,
	)
}

func TestRequestCredential_InvalidAccessToken(t *testing.T) {
	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		"invalid-token",
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusUnauthorized,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_token"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_StrictDecoderRejectsUnknownField(t *testing.T) {
	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			"request-1",
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential",
			"unknown_field":"must-fail"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.InvalidCredentialRequest,
	)
}

func TestRequestCredential_AcceptsOID4VCI10ProofsWireFormat(t *testing.T) {
	var request credential.CredentialRequest

	decoder := json.NewDecoder(
		bytes.NewBufferString(`{
			"credential_configuration_id":"SDJWTCredential",
			"proofs":{
				"jwt":[
					"jwt-proof-1",
					"jwt-proof-2"
				]
			}
		}`),
	)
	decoder.DisallowUnknownFields()

	require.NoError(
		t,
		decoder.Decode(&request),
	)

	require.Equal(
		t,
		"SDJWTCredential",
		request.CredentialConfigurationID,
	)

	require.NotNil(t, request.Proofs)

	require.Equal(
		t,
		[]string{
			"jwt-proof-1",
			"jwt-proof-2",
		},
		request.Proofs.JWT,
	)
}

func TestRequestCredential_AcceptsLegacyProofAndFormatCompatibilityFields(t *testing.T) {
	var request credential.CredentialRequest

	decoder := json.NewDecoder(
		bytes.NewBufferString(`{
			"credential_configuration_id":"SDJWTCredential",
			"format":"dc+sd-jwt",
			"proof":{
				"proof_type":"jwt",
				"jwt":"legacy-proof"
			}
		}`),
	)
	decoder.DisallowUnknownFields()

	require.NoError(
		t,
		decoder.Decode(&request),
	)

	request.Normalize()

	require.Equal(
		t,
		"dc+sd-jwt",
		request.Format,
	)

	require.NotNil(t, request.Proofs)

	require.Equal(
		t,
		[]string{"legacy-proof"},
		request.Proofs.JWT,
	)
}

func TestRequestCredential_RejectsNoCredentialSelector(t *testing.T) {
	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			"request-1",
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.InvalidCredentialRequest,
	)
}

func TestRequestCredential_RejectsBothCredentialSelectors(t *testing.T) {
	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			"request-1",
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	gateway := newGatewayForTest(
		t,
		&fakeCredentialService{},
	)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_identifier":"developer",
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.InvalidCredentialRequest,
	)
}

func TestRequestCredential_VerifyAuthTokenError(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: func(
			ctx context.Context,
			tenantID string,
			groupID string,
			headerValue string,
		) (*preAuth.ValidateAuthenticationRep, error) {
			require.Equal(t, testTenantID, tenantID)
			require.Equal(t, "", groupID)
			require.Equal(
				t,
				"Bearer "+accessToken,
				headerValue,
			)

			return nil,
				errors.New("authorization bridge failed")
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusUnauthorized,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_token"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_NilAuthorizationReply(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: func(
			ctx context.Context,
			tenantID string,
			groupID string,
			headerValue string,
		) (*preAuth.ValidateAuthenticationRep, error) {
			return nil, nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusUnauthorized,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_token"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_TenantBinding(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: func(
			ctx context.Context,
			tenantID string,
			groupID string,
			headerValue string,
		) (*preAuth.ValidateAuthenticationRep, error) {
			return &preAuth.ValidateAuthenticationRep{
				Reply: common.Reply{
					TenantId:  "other-tenant",
					RequestId: requestID,
				},
			}, nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusUnauthorized,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_token"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_SubjectBinding(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		"wrong-subject",
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: func(
			ctx context.Context,
			tenantID string,
			groupID string,
			headerValue string,
		) (*preAuth.ValidateAuthenticationRep, error) {
			return &preAuth.ValidateAuthenticationRep{
				Reply: common.Reply{
					TenantId:  testTenantID,
					RequestId: requestID,
				},
			}, nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusUnauthorized,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"invalid_token"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_MetadataError(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			"",
			[]credential.CredentialConfigurationIdentifier{
				{Id: "SDJWTCredential"},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return nil,
				errors.New("metadata unavailable")
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusInternalServerError,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"server_error"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_NilMetadata(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			"",
			[]credential.CredentialConfigurationIdentifier{
				{Id: "SDJWTCredential"},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return nil, nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusInternalServerError,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{"error":"server_error"}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_UnknownCredentialConfiguration(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			"",
			[]credential.CredentialConfigurationIdentifier{
				{Id: "SDJWTCredential"},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return testIssuerMetadata(
				"DifferentCredential",
			), nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.UnknownCredentialConfiguration,
	)
}

func TestRequestCredential_UnknownCredentialIdentifier(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			"",
			[]credential.CredentialConfigurationIdentifier{
				{
					Id:                    "SDJWTCredential",
					CredentialIdentifiers: []string{"known"},
				},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return testIssuerMetadata(
				"SDJWTCredential",
			), nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_identifier":"unknown"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusBadRequest,
		recorder.Code,
	)

	assertCredentialError(
		t,
		recorder.Body.Bytes(),
		credential.UnknownCredentialIdentifier,
	)
}

func TestRequestCredential_HappyPathConfigurationIDWithoutAdvertisedProof(t *testing.T) {
	requestID := "request-1"
	groupID := "authorization-group"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			groupID,
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			groupID,
			[]credential.CredentialConfigurationIdentifier{
				{Id: "SDJWTCredential"},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			require.Equal(t, testTenantID, tenantID)

			return testIssuerMetadata(
				"SDJWTCredential",
			), nil
		},

		getCredentialFn: func(
			ctx context.Context,
			authRep *preAuth.ValidateAuthenticationRep,
			req credential.CredentialRequest,
			code string,
			audience string,
			signerKey string,
			namespace string,
			group string,
		) (*types.GetCredentialRespImmediate, error) {
			require.Equal(
				t,
				"SDJWTCredential",
				req.CredentialConfigurationID,
			)

			require.Equal(t, testCode, code)
			require.Equal(t, testAudience, audience)
			require.Equal(t, "signerKey", signerKey)
			require.Empty(t, namespace)
			require.Empty(t, group)

			return immediateCredentialResponse(
				t,
				"eyJhbGciOiJFUzI1NiJ9.payload.signature~",
			), nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	// VerifyAuthToken receives this group ID from the gateway header,
	// independently from the group embedded in the authorization reply.
	ctx.Request.Header.Set(
		"x-groupId",
		groupID,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusOK,
		recorder.Code,
	)

	require.JSONEq(
		t,
		`{
			"credentials":[
				{
					"credential":"eyJhbGciOiJFUzI1NiJ9.payload.signature~"
				}
			]
		}`,
		recorder.Body.String(),
	)
}

func TestRequestCredential_HappyPathCredentialIdentifier(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	svc := &fakeCredentialService{
		verifyAuthTokenFn: validAuthReply(
			testTenantID,
			requestID,
			"",
			[]credential.CredentialConfigurationIdentifier{
				{
					Id: "SDJWTCredential",
					CredentialIdentifiers: []string{
						"developer-credential",
					},
				},
			},
		),

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return testIssuerMetadata(
				"SDJWTCredential",
			), nil
		},

		getCredentialFn: func(
			ctx context.Context,
			authRep *preAuth.ValidateAuthenticationRep,
			req credential.CredentialRequest,
			code string,
			audience string,
			signerKey string,
			namespace string,
			group string,
		) (*types.GetCredentialRespImmediate, error) {
			require.Equal(
				t,
				"developer-credential",
				req.CredentialIdentifier,
			)

			return immediateCredentialResponse(
				t,
				"credential",
			), nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_identifier":"developer-credential"
		}`),
		accessToken,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusOK,
		recorder.Code,
	)
}

func TestRequestCredential_HeaderOverridesArePassedToService(t *testing.T) {
	requestID := "request-1"

	jwksServer, accessToken := newJWKSAndAccessToken(
		t,
		testSubject(
			testTenantID,
			requestID,
			"",
		),
		testCode,
	)
	defer jwksServer.Close()

	const (
		overrideAudience = "https://tenant.example.com"
		overrideSigner   = "tenant-signing-key"
		overrideNS       = "tenant-namespace"
		overrideGroup    = "tenant-group"
		overrideGroupID  = "tenant-group-id"
	)

	svc := &fakeCredentialService{
		verifyAuthTokenFn: func(
			ctx context.Context,
			tenantID string,
			groupID string,
			headerValue string,
		) (*preAuth.ValidateAuthenticationRep, error) {
			require.Equal(
				t,
				overrideGroupID,
				groupID,
			)

			return &preAuth.ValidateAuthenticationRep{
				Reply: common.Reply{

					TenantId:  testTenantID,
					RequestId: requestID,
					GroupId:   "",
				},
				Valid: true,
				CredentialConfigurations: []credential.CredentialConfigurationIdentifier{
					{
						Id: "SDJWTCredential",
					},
				},
			}, nil
		},

		getCompleteCredentialIssuerFn: func(
			ctx context.Context,
			tenantID string,
		) (*credential.IssuerMetadata, error) {
			return testIssuerMetadata(
				"SDJWTCredential",
			), nil
		},

		getCredentialFn: func(
			ctx context.Context,
			authRep *preAuth.ValidateAuthenticationRep,
			req credential.CredentialRequest,
			code string,
			audience string,
			signerKey string,
			namespace string,
			group string,
		) (*types.GetCredentialRespImmediate, error) {
			require.Equal(
				t,
				overrideAudience,
				audience,
			)
			require.Equal(
				t,
				overrideSigner,
				signerKey,
			)
			require.Equal(
				t,
				overrideNS,
				namespace,
			)
			require.Equal(
				t,
				overrideGroup,
				group,
			)

			return immediateCredentialResponse(
				t,
				"credential",
			), nil
		},
	}

	gateway := newGatewayForTest(t, svc)
	gateway.jwksURL = jwksServer.URL

	ctx, recorder := newCredentialContext(
		[]byte(`{
			"credential_configuration_id":"SDJWTCredential"
		}`),
		accessToken,
	)

	ctx.Request.Header.Set(
		"x-audience-url",
		overrideAudience,
	)
	ctx.Request.Header.Set(
		"x-signerkey",
		overrideSigner,
	)
	ctx.Request.Header.Set(
		"x-namespace",
		overrideNS,
	)
	ctx.Request.Header.Set(
		"x-group",
		overrideGroup,
	)
	ctx.Request.Header.Set(
		"x-groupId",
		overrideGroupID,
	)

	gateway.RequestCredential(ctx)

	require.Equal(
		t,
		http.StatusOK,
		recorder.Code,
	)
}

func TestRequestCredential_GetCredentialErrorMapping(t *testing.T) {
	tests := []struct {
		name          string
		serviceError  error
		expectedError string
	}{
		{
			name:          "unknown credential identifier",
			serviceError:  credential.ErrUnknownCredentialIdentifier,
			expectedError: credential.UnknownCredentialIdentifier,
		},
		{
			name:          "unknown credential configuration",
			serviceError:  credential.ErrUnknownCredentialConfiguration,
			expectedError: credential.UnknownCredentialConfiguration,
		},
		{
			name:          "generic issuance error",
			serviceError:  errors.New("issuer backend failed"),
			expectedError: credential.InvalidCredentialRequest,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				requestID := "request-1"

				jwksServer, accessToken :=
					newJWKSAndAccessToken(
						t,
						testSubject(
							testTenantID,
							requestID,
							"",
						),
						testCode,
					)
				defer jwksServer.Close()

				svc := &fakeCredentialService{
					verifyAuthTokenFn: validAuthReply(
						testTenantID,
						requestID,
						"",
						[]credential.CredentialConfigurationIdentifier{
							{
								Id: "SDJWTCredential",
							},
						},
					),

					getCompleteCredentialIssuerFn: func(
						ctx context.Context,
						tenantID string,
					) (*credential.IssuerMetadata, error) {
						return testIssuerMetadata(
							"SDJWTCredential",
						), nil
					},

					getCredentialFn: func(
						ctx context.Context,
						authRep *preAuth.ValidateAuthenticationRep,
						req credential.CredentialRequest,
						code string,
						audience string,
						signerKey string,
						namespace string,
						group string,
					) (*types.GetCredentialRespImmediate, error) {
						return nil, tt.serviceError
					},
				}

				gateway := newGatewayForTest(
					t,
					svc,
				)
				gateway.jwksURL =
					jwksServer.URL

				ctx, recorder :=
					newCredentialContext(
						[]byte(`{
							"credential_configuration_id":"SDJWTCredential"
						}`),
						accessToken,
					)

				gateway.RequestCredential(ctx)

				require.Equal(
					t,
					http.StatusBadRequest,
					recorder.Code,
				)

				assertCredentialError(
					t,
					recorder.Body.Bytes(),
					tt.expectedError,
				)
			},
		)
	}
}

func TestRequestCredential_LegacyFormatDoesNotControlCredentialSelection(t *testing.T) {
	var request credential.CredentialRequest

	require.NoError(
		t,
		json.Unmarshal(
			[]byte(`{
				"credential_configuration_id":"SDJWTCredential",
				"format":"some-wrong-format"
			}`),
			&request,
		),
	)

	require.Equal(
		t,
		"SDJWTCredential",
		request.CredentialConfigurationID,
	)

	require.Equal(
		t,
		"some-wrong-format",
		request.Format,
	)
}

func TestImmediateCredentialResponseJSONShape(t *testing.T) {
	response := immediateCredentialResponse(
		t,
		"eyJ...~",
	)

	data, err := json.Marshal(response)
	require.NoError(t, err)

	require.JSONEq(
		t,
		`{
			"credentials":[
				{
					"credential":"eyJ...~"
				}
			]
		}`,
		string(data),
	)
}

func validAuthReply(
	tenantID string,
	requestID string,
	groupID string,
	configurations []credential.CredentialConfigurationIdentifier,
) func(
	context.Context,
	string,
	string,
	string,
) (*preAuth.ValidateAuthenticationRep, error) {
	return func(
		ctx context.Context,
		actualTenantID string,
		actualGroupID string,
		headerValue string,
	) (*preAuth.ValidateAuthenticationRep, error) {
		return &preAuth.ValidateAuthenticationRep{
			Reply: common.Reply{
				TenantId:  tenantID,
				RequestId: requestID,
				GroupId:   groupID,
			},
			Valid: true,

			CredentialConfigurations: configurations,
		}, nil
	}
}

func testIssuerMetadata(
	configurationID string,
) *credential.IssuerMetadata {
	return &credential.IssuerMetadata{
		CredentialIssuer: testAudience,

		CredentialConfigurationsSupported: map[string]credential.CredentialConfiguration{
			configurationID: {
				// ProofTypesSupported deliberately remains empty.
				// Under OID4VCI 1.0 a proof is optional when the
				// selected configuration does not advertise
				// proof_types_supported. This allows the HTTP gateway
				// success path to be tested independently of the
				// cryptographic proof implementation in the library.
			},
		},
	}
}

func immediateCredentialResponse(
	t *testing.T,
	value string,
) *types.GetCredentialRespImmediate {
	t.Helper()

	credentialJSON, err := json.Marshal(value)
	require.NoError(t, err)

	return &types.GetCredentialRespImmediate{
		Credentials: []types.CredentialResponseItem{
			{
				Credential: credentialJSON,
			},
		},
	}
}

func testSubject(
	tenantID string,
	requestID string,
	groupID string,
) string {
	request := common.Request{
		TenantId:  tenantID,
		RequestId: requestID,
		GroupId:   groupID,
	}

	return request.BuildSubject()
}

func newGatewayForTest(
	t *testing.T,
	svc credentialService,
) RestGateway {
	t.Helper()

	logger, err := logr.New(
		"debug",
		true,
		io.Discard,
	)
	require.NoError(t, err)

	return NewGateway(
		svc,
		*logger,
		"http://127.0.0.1:1/jwks",
		testAudience,
		"test-nonce-secret",
	)
}

func newCredentialContext(
	body []byte,
	accessToken string,
) (*gin.Context, *httptest.ResponseRecorder) {
	ctx, recorder := newGinContext(
		http.MethodPost,
		"/v1/tenants/"+testTenantID+"/credential",
		body,
	)

	ctx.Params = gin.Params{
		{
			Key:   "tenantId",
			Value: testTenantID,
		},
	}

	ctx.Request.Header.Set(
		"Authorization",
		"Bearer "+accessToken,
	)

	return ctx, recorder
}

func newGinContext(
	method string,
	target string,
	body []byte,
) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()

	ctx, _ := gin.CreateTestContext(
		recorder,
	)

	request := httptest.NewRequest(
		method,
		target,
		bytes.NewReader(body),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	ctx.Request = request

	return ctx, recorder
}

func assertCredentialError(
	t *testing.T,
	body []byte,
	expected string,
) {
	t.Helper()

	var response credential.CredentialErrorResponse

	require.NoError(
		t,
		json.Unmarshal(
			body,
			&response,
		),
	)

	require.Equal(
		t,
		expected,
		response.ErrorMsg,
	)
}

func newJWKSAndAccessToken(
	t *testing.T,
	subject string,
	code string,
) (*httptest.Server, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(
		leftPad(
			privateKey.PublicKey.X.Bytes(),
			32,
		),
	)

	y := base64.RawURLEncoding.EncodeToString(
		leftPad(
			privateKey.PublicKey.Y.Bytes(),
			32,
		),
	)

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"use": "sig",
				"kid": testKeyID,
				"alg": "ES256",
				"crv": "P-256",
				"x":   x,
				"y":   y,
			},
		},
	}

	server := httptest.NewServer(
		http.HandlerFunc(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				w.Header().Set(
					"Content-Type",
					"application/json",
				)

				require.NoError(
					t,
					json.NewEncoder(w).Encode(
						jwks,
					),
				)
			},
		),
	)

	token := signES256JWT(
		t,
		privateKey,
		map[string]any{
			"sub":  subject,
			"code": code,
			"iat": time.Now().
				Add(-time.Minute).
				Unix(),
			"exp": time.Now().
				Add(time.Hour).
				Unix(),
		},
	)

	return server, token
}

func signES256JWT(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	claims map[string]any,
) string {
	t.Helper()

	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
		"kid": testKeyID,
	}

	headerJSON, err := json.Marshal(
		header,
	)
	require.NoError(t, err)

	claimsJSON, err := json.Marshal(
		claims,
	)
	require.NoError(t, err)

	encodedHeader :=
		base64.RawURLEncoding.EncodeToString(
			headerJSON,
		)

	encodedClaims :=
		base64.RawURLEncoding.EncodeToString(
			claimsJSON,
		)

	signingInput :=
		encodedHeader +
			"." +
			encodedClaims

	hash := sha256.Sum256(
		[]byte(signingInput),
	)

	r, s, err := ecdsa.Sign(
		rand.Reader,
		privateKey,
		hash[:],
	)
	require.NoError(t, err)

	signature := append(
		leftPad(
			r.Bytes(),
			32,
		),
		leftPad(
			s.Bytes(),
			32,
		)...,
	)

	return signingInput +
		"." +
		base64.RawURLEncoding.EncodeToString(
			signature,
		)
}

func leftPad(
	value []byte,
	size int,
) []byte {
	if len(value) >= size {
		return value
	}

	result := make(
		[]byte,
		size,
	)

	copy(
		result[size-len(value):],
		value,
	)

	return result
}

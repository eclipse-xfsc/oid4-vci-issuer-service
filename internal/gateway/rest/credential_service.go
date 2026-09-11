package rest

import (
	"context"

	preAuth "github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-issuer-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

// credentialService contains only the service methods required by the REST
// gateway. The concrete service.CredentialService satisfies this interface.
//
// Keeping the gateway dependent on this small interface makes the HTTP layer
// independently unit-testable without starting NATS / CloudEvent infrastructure.
type credentialService interface {
	VerifyAuthToken(
		ctx context.Context,
		tenantID string,
		groupID string,
		headerValue string,
	) (*preAuth.ValidateAuthenticationRep, error)

	GetCompleteCredentialIssuer(
		ctx context.Context,
		tenantID string,
	) (*credential.IssuerMetadata, error)

	GetCredential(
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

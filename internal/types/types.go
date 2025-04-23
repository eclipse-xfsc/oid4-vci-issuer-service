package types

import "github.com/eclipse-xfsc/nats-message-library/common"

const (
	ProofTypeJWT   = "jwt"
	ProofTypeCWT   = "cwt"
	ProofTypeLDPvP = "ldp_vp"
)

type GetCredentialResp interface {
	isGetCredentialResp()
}

type GetCredentialRespImmediate struct {
	common.Reply
	Format     string `json:"format"`
	Credential any    `json:"credential"`
	CNonce     string `json:"c_nonce"`

	// CNonceExpiresIn is the lifetime in seconds
	// of the c_nonce
	CNonceExpiresIn int `json:"c_nonce_expires_in"`
}

func (g GetCredentialRespImmediate) isGetCredentialResp() {}

type GetCredentialRespDeferred struct {
	TransactionID string `json:"transaction_id"`
	CNonce        string `json:"c_nonce"`

	// CNonceExpiresIn is the lifetime in seconds
	// of the c_nonce
	CNonceExpiresIn int `json:"c_nonce_expires_in"`
}

func (g GetCredentialRespDeferred) isGetCredentialResp() {}

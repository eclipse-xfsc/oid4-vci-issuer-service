package types

const (
	ProofTypeJWT   = "jwt"
	ProofTypeCWT   = "cwt"
	ProofTypeLDPvP = "ldp_vp"
)

type GetCredentialResp interface {
	isGetCredentialResp()
}

type CredentialResponseItem struct {
	Credential any `json:"credential"`
}

type GetCredentialRespImmediate struct {
	Credentials []CredentialResponseItem `json:"credentials"`

	NotificationID string `json:"notification_id,omitempty"`
}

type GetCredentialRespDeferred struct {
	TransactionID string `json:"transaction_id"`
	Interval      int    `json:"interval"`
}

func (g GetCredentialRespImmediate) isGetCredentialResp() {}

func (g GetCredentialRespDeferred) isGetCredentialResp() {}

package messaging

import (
	"fmt"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

const SourceIssuanceService = "issuance"

const (
	TopicOffering     = "credential.offer.url"
	EventTypeOffering = "credential.offer.url.v1"
)

type IssueCredentialReqParams struct {
	CredentialType string `json:"credential_type"`
	Proof          Proof  `json:"proof"`
	AccessToken    string `json:"access_token"`
}

// Proof is part of a GetCredentialReq. The ProofType is mandatory,
// as well as one (and only one) of JWT, CWT and LDPvP
type Proof struct {
	ProofType string  `json:"proof_type"`
	JWT       *string `json:"jwt,omitempty"`
	CWT       *string `json:"cwt,omitempty"`
	LDPvP     *string `json:"ldp_vp,omitempty"`
}

type OfferingURLResp struct {
	common.Reply
	CredentialOffer credential.CredentialOffer
}

type OfferingURLReq struct {
	common.Request
	Params AuthorizationReq
}

type AuthorizationReq struct {
	CredentialType       string    `json:"credentialType"`
	CredentialIdentifier []string  `json:"credentialIdentifier"`
	GrantType            string    `json:"grantType"`
	TwoFactor            TwoFactor `json:"twoFactor"`
	Nonce                string    `json:"nonce"`
}

type TwoFactor struct {
	Enabled          bool   `json:"enabled"`
	RecipientType    string `json:"recipientType"`
	RecipientAddress string `json:"recipientAddress"`
}

type IssuanceModuleReq struct {
	common.Request
	CredentialConfigId   string
	CredentialIdentifier string
	Format               string
	Code                 string
	Holder               string
	ProofType            string
}

type IssuanceModuleRep struct {
	common.Reply
	Credential any
	Format     string
}

func (u AuthorizationReq) Validate() error {
	if u.CredentialType == "" {
		return fmt.Errorf("credentialType not set")
	}

	if u.GrantType == "" {
		return fmt.Errorf("grantType not set")
	}

	return nil
}

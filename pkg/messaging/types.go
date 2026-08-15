package messaging

import (
	"fmt"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
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
	Code            string
	Subject         string
}

type OfferingURLReq struct {
	common.Request
	Params AuthorizationReq
}

type AuthorizationReq struct {
	Subject                  string                                         `json:"subject"`
	Claims                   []oauth.Claim                                  `json:"subject,omitempty"`
	CredentialConfigurations []credential.CredentialConfigurationIdentifier `json:"credentialConfiguration"`
	GrantType                string                                         `json:"grantType"`
	//Ignored when grant type authorization code
	TwoFactor TwoFactor `json:"twoFactor"`
	//Ignored when grant type authorization code
	Nonce string `json:"nonce"`
	//Ignored when granttype is preauth code
	IssuerState string `json:"issuerState"`
}

type TwoFactor struct {
	Enabled          bool   `json:"enabled"`
	RecipientType    string `json:"recipientType"`
	RecipientAddress string `json:"recipientAddress"`
}

type IssuanceModuleReq struct {
	common.Request
	CredentialConfiguration credential.CredentialConfigurationIdentifier
	Claims                  []oauth.Claim
	Code                    string
	Format                  string
	Subject                 string
	Nonce                   string
	Holder                  string
	ProofType               string
	Origin                  string
	SignerKey               string
}

type IssuanceModuleRep struct {
	common.Reply
	Credential any
	Format     string
}

func (u AuthorizationReq) Validate() error {

	if u.GrantType == "" {
		return fmt.Errorf("grantType not set")
	}

	if len(u.CredentialConfigurations) == 0 {
		return fmt.Errorf("no credential configuration set")
	}

	return nil
}

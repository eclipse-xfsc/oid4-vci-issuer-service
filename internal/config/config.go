package config

import (
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/config"
)

type IssuanceServiceConfig struct {
	JwksUrl  string `mapstructure:"jwksUrl" envconfig:"JWKSURL"`
	Audience string `mapstructure:"audience" envconfig:"AUDIENCE"`
	config.BaseConfig
	Nats        cloudeventprovider.NatsConfig `envconfig:"NATS"`
	Resolver    string                        `envconfig:"DID_RESOLVER"`
	NonceSecret string                        `envconfig:"NONCE_SECRET" required:"true"`
}

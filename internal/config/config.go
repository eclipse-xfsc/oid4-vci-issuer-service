package config

import (
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/config"
	redisPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/db/redis"
)

type IssuanceServiceConfig struct {
	JwksUrl  string `mapstructure:"jwksUrl" envconfig:"JWKSURL"`
	Audience string `mapstructure:"audience" envconfig:"AUDIENCE"`
	config.BaseConfig
	Redis redisPkg.Config               `mapstructure:"database"`
	Nats  cloudeventprovider.NatsConfig `envconfig:"NATS"`
}

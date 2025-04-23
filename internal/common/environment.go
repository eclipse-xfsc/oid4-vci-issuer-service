package common

import (
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/swaggo/swag/example/basic/docs"
)

type Environment struct {
	logger    *logPkg.Logger
	isHealthy bool
}

var env *Environment

func init() {
	env = new(Environment)
}

func GetEnvironment() *Environment {
	return env
}

func (e *Environment) IsHealthy() bool {
	return true
}

// SetSwaggerBasePath sets the base path that will be used by swagger ui for requests url generation
func (e *Environment) SetSwaggerBasePath(path string) {
	docs.SwaggerInfo.BasePath = path + BasePath
}

// SwaggerOptions swagger config options. See https://github.com/swaggo/gin-swagger?tab=readme-ov-file#configuration
func (e *Environment) SwaggerOptions() []func(config *ginSwagger.Config) {
	return []func(config *ginSwagger.Config){
		ginSwagger.DefaultModelsExpandDepth(10),
	}
}

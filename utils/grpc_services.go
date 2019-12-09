package utils

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// ConfigureProfileService creates required connection to the profile service
func ConfigureProfileServiceConn(log *logrus.Entry) (*grpc.ClientConn, error) {

	// Create a new interceptor
	jwt := &JWTInterceptor{
		// Set up all the members here
	}

	profileServiceUri := GetEnv(ConfigProfileServiceUri, "")
	return grpc.Dial(profileServiceUri, grpc.WithUnaryInterceptor(jwt.UnaryClientInterceptor))

}

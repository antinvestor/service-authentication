package handlers

import (
	"fmt"
	"net/http"

	"github.com/opentracing/opentracing-go"

	"antinvestor.com/service/auth/utils"
)

func HealthCheckEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, _ := opentracing.StartSpanFromContext(req.Context(), "HealthCheckEndpoint")
	defer span.Finish()

	statusCode, content := utils.HealthCheckProcessing(env.Logger, env.Health)

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	rw.WriteHeader(statusCode)
	rw.Write(content)
	return nil
}

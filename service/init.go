package service

import (
	"encoding/json"
	"fmt"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/handlers"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/pitabwire/frame"
	"net/http"
)

type holder struct {
	service      *frame.Service
	config       *config.AuthenticationConfig
	profileCli   *profilev1.ProfileClient
	partitionCli *partitionv1.PartitionClient
}
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *holder) writeError(w http.ResponseWriter, err error, code int, msg string) {

	w.Header().Set("Content-Type", "application/json")

	h.service.L().
		WithField("code", code).
		WithField("message", msg).WithError(err).Error("internal service error")
	w.WriteHeader(code)

	err = json.NewEncoder(w).Encode(&ErrorResponse{
		Code:    code,
		Message: fmt.Sprintf(" internal processing err message: %s %s", msg, err),
	})
	if err != nil {
		h.service.L().WithError(err).Error("could not write error to response")
	}
}

func (h *holder) addHandler(router *mux.Router,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(frame.ToContext(r.Context(), h.service))
		r = r.WithContext(profilev1.ToContext(r.Context(), h.profileCli))
		r = r.WithContext(partitionv1.ToContext(r.Context(), h.partitionCli))

		err := f(w, r)
		if err != nil {
			h.writeError(w, err, 500, "could not process request")
		}
	})

	router.Path(path).
		Name(name).
		Handler(handler).
		Methods(method)
}

// NewAuthRouterV1 NewRouterV1 -
func NewAuthRouterV1(service *frame.Service,
	authConfig *config.AuthenticationConfig,
	profileCli *profilev1.ProfileClient,
	partitionCli *partitionv1.PartitionClient) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	csrfMiddleware := csrf.Protect(
		[]byte(authConfig.CsrfSecret),
		csrf.Secure(false),
	)

	sRouter := router.PathPrefix("/s").Subrouter()
	sRouter.Use(csrfMiddleware)

	authRouter := router.PathPrefix("/api").Subrouter()

	webhookRouter := router.PathPrefix("/webhook").Subrouter()

	authRouter.Use(func(handler http.Handler) http.Handler {
		return service.AuthenticationMiddleware(handler, authConfig.Oauth2JwtVerifyAudience, authConfig.Oauth2JwtVerifyIssuer)
	})

	holder := &holder{
		service:      service,
		config:       authConfig,
		profileCli:   profileCli,
		partitionCli: partitionCli,
	}

	holder.addHandler(router, handlers.IndexEndpoint, "/", "IndexEndpoint", "GET")
	holder.addHandler(router, handlers.ErrorEndpoint, "/error", "ErrorEndpoint", "GET")

	holder.addHandler(sRouter, handlers.ShowLoginEndpoint, "/login", "ShowLoginEndpoint", "GET")
	holder.addHandler(sRouter, handlers.SubmitLoginEndpoint, "/login/post", "SubmitLoginEndpoint", "POST")
	holder.addHandler(sRouter, handlers.ShowLogoutEndpoint, "/logout", "ShowLogoutEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ShowConsentEndpoint, "/consent", "ShowConsentEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ShowRegisterEndpoint, "/register", "ShowRegisterEndpoint", "GET")
	holder.addHandler(sRouter, handlers.SubmitRegisterEndpoint, "/register/post", "SubmitRegisterEndpoint", "POST")
	holder.addHandler(sRouter, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint", "GET")

	holder.addHandler(webhookRouter, handlers.TokenEnrichmentEndpoint, "/enrich/{tokenType}", "WebhookTokenEnrichmentEndpoint", "POST")
	holder.addHandler(webhookRouter, handlers.CentrifugoProxyEndpoint, "/centrifugo/proxy/{ProxyAction}", "CentrifugoProxyEndpoint", "POST")

	holder.addHandler(authRouter, handlers.CreateAPIKeyEndpoint, "/key", "CreateAPIKeyEndpoint", "PUT")
	holder.addHandler(authRouter, handlers.ListAPIKeyEndpoint, "/key", "ListApiKeyEndpoint", "GET")
	holder.addHandler(authRouter, handlers.DeleteAPIKeyEndpoint, "/key/{ApiKeyId}", "DeleteApiKeyEndpoint", "DELETE")
	holder.addHandler(authRouter, handlers.GetAPIKeyEndpoint, "/key/{ApiKeyId}", "GetApiKeyEndpoint", "GET")

	return router
}

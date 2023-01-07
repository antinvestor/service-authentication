package service

import (
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/handlers"
	prtapi "github.com/antinvestor/service-partition-api"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type holder struct {
	service      *frame.Service
	config       *config.AuthenticationConfig
	profileCli   *papi.ProfileClient
	partitionCli *prtapi.PartitionClient
}

func (h *holder) addHandler(router *mux.Router,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(frame.ToContext(r.Context(), h.service))
		r = r.WithContext(papi.ToContext(r.Context(), h.profileCli))
		r = r.WithContext(prtapi.ToContext(r.Context(), h.partitionCli))

		err := f(w, r)
		if err != nil {
			log.Printf(" handler %s on %s has the error %v", name, path, err)
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
	profileCli *papi.ProfileClient,
	partitionCli *prtapi.PartitionClient) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	csrfMiddleware := csrf.Protect(
		[]byte(authConfig.CsrfSecret),
		csrf.Secure(false),
	)

	sRouter := router.PathPrefix("/s").Subrouter()
	sRouter.Use(csrfMiddleware)

	authRouter := router.PathPrefix("/api").Subrouter()

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
	holder.addHandler(sRouter, handlers.ShowLoginEndpoint, "/login", "ShowLoginEndpoint", "GET")
	holder.addHandler(sRouter, handlers.SubmitLoginEndpoint, "/login/post", "SubmitLoginEndpoint", "POST")
	holder.addHandler(sRouter, handlers.ShowLogoutEndpoint, "/logout", "ShowLogoutEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ShowConsentEndpoint, "/consent", "ShowConsentEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ShowRegisterEndpoint, "/register", "ShowRegisterEndpoint", "GET")
	holder.addHandler(sRouter, handlers.SubmitRegisterEndpoint, "/register/post", "SubmitRegisterEndpoint", "POST")
	holder.addHandler(sRouter, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint", "GET")
	holder.addHandler(sRouter, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint", "GET")

	holder.addHandler(authRouter, handlers.CreateAPIKeyEndpoint, "/key", "CreateAPIKeyEndpoint", "PUT")
	holder.addHandler(authRouter, handlers.ListAPIKeyEndpoint, "/key", "ListApiKeyEndpoint", "GET")
	holder.addHandler(authRouter, handlers.DeleteAPIKeyEndpoint, "/key/{ApiKeyId}", "DeleteApiKeyEndpoint", "DELETE")
	holder.addHandler(authRouter, handlers.GetAPIKeyEndpoint, "/key/{ApiKeyId}", "GetApiKeyEndpoint", "GET")

	return router
}

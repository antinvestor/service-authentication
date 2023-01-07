package service

import (
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/handlers"
	prtapi "github.com/antinvestor/service-partition-api"
	papi "github.com/antinvestor/service-profile-api"

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

func addHandler(holder *holder, router *mux.Router,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		r = r.WithContext(frame.ToContext(r.Context(), holder.service))
		r = r.WithContext(papi.ToContext(r.Context(), holder.profileCli))
		r = r.WithContext(prtapi.ToContext(r.Context(), holder.partitionCli))

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
func NewAuthRouterV1(service *frame.Service, authConfig *config.AuthenticationConfig, profileCli *papi.ProfileClient, partitionCli *prtapi.PartitionClient) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	authenticatedRouter := mux.NewRouter().StrictSlash(true)

	holder := &holder{
		service:      service,
		config:       authConfig,
		profileCli:   profileCli,
		partitionCli: partitionCli,
	}

	addHandler(holder, router, handlers.IndexEndpoint, "/", "IndexEndpoint", "GET")
	addHandler(holder, router, handlers.ShowLoginEndpoint, "/login", "ShowLoginEndpoint", "GET")
	addHandler(holder, router, handlers.SubmitLoginEndpoint, "/login/post", "SubmitLoginEndpoint", "POST")
	addHandler(holder, router, handlers.ShowLogoutEndpoint, "/logout", "ShowLogoutEndpoint", "GET")
	addHandler(holder, router, handlers.ShowConsentEndpoint, "/consent", "ShowConsentEndpoint", "GET")
	addHandler(holder, router, handlers.ShowRegisterEndpoint, "/register", "ShowRegisterEndpoint", "GET")
	addHandler(holder, router, handlers.SubmitRegisterEndpoint, "/register/post", "SubmitRegisterEndpoint", "POST")
	addHandler(holder, router, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint", "GET")
	addHandler(holder, router, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint", "GET")

	addHandler(holder, authenticatedRouter, handlers.CreateAPIKeyEndpoint, "/key", "CreateAPIKeyEndpoint", "PUT")
	addHandler(holder, authenticatedRouter, handlers.DeleteAPIKeyEndpoint, "/key", "DeleteApiKeyEndpoint", "DELETE")
	addHandler(holder, authenticatedRouter, handlers.ListAPIKeyEndpoint, "/key", "ListApiKeyEndpoint", "GET")

	authenticatedHandler := holder.service.AuthenticationMiddleware(authenticatedRouter,
		holder.config.Oauth2JwtVerifyAudience, holder.config.Oauth2JwtVerifyIssuer)

	router.Handle("/api", authenticatedHandler)

	return router
}

package service

import (
	"github.com/antinvestor/service-authentication/service/handlers"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/pitabwire/frame"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func addHandler(service *frame.Service, profileCli *papi.ProfileClient, router *mux.Router,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		r.WithContext(frame.ToContext(r.Context(), service))

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

// NewRouterV1 -
func NewAuthRouterV1(service *frame.Service, profileCli *papi.ProfileClient) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	addHandler(service, profileCli, router, handlers.IndexEndpoint, "/", "IndexEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.ShowLoginEndpoint, "/login", "ShowLoginEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.SubmitLoginEndpoint, "/login/post", "SubmitLoginEndpoint", "POST")
	addHandler(service, profileCli, router, handlers.ShowLogoutEndpoint, "/logout", "ShowLogoutEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.ShowConsentEndpoint, "/consent", "ShowConsentEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.ShowRegisterEndpoint, "/register", "ShowRegisterEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.SubmitRegisterEndpoint, "/register/post", "SubmitRegisterEndpoint", "POST")
	addHandler(service, profileCli, router, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint", "GET")
	addHandler(service, profileCli, router, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint", "GET")

	return router
}

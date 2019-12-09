package service

import (
	"antinvestor.com/service/auth/service/handlers"
	"antinvestor.com/service/auth/utils"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)


// Logger -
func Logger(inner http.Handler, name string, logger *logrus.Entry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		logger.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}

func addHandler(env *utils.Env, router *mux.Router,
	f func(env *utils.Env, w http.ResponseWriter, r *http.Request) error, path string, name string) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := f(env, w, r)
		if err != nil {
			switch e := err.(type) {
			case Error:
				// We can retrieve the status here and write out a specific
				// HTTP status code.
				env.Logger.Warnf("request failed with  %d - %s", e.Status(), e)
			default:

				env.Logger.Error(e)
			}
		}

	})
	loggedHandler := Logger(handler, name, env.Logger)

	router.Path(path).
		Name(name).
		Handler(loggedHandler)

}

// NewRouterV1 -
func NewAuthRouterV1(env *utils.Env) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	addHandler(env, router, handlers.IndexEndpoint, "/", "IndexEndpoint")
	addHandler(env, router, handlers.HealthCheckEndpoint, "/healthz", "HealthCheckEndpoint")
	addHandler(env, router, handlers.LoginEndpoint, "/login", "LoginEndpoint")
	addHandler(env, router, handlers.LogoutEndpoint, "/logout", "LogoutEndpoint")
	addHandler(env, router, handlers.ConsentEndpoint, "/consent", "ConsentEndpoint")
	addHandler(env, router, handlers.RegisterEndpoint, "/register", "RegisterEndpoint")
	addHandler(env, router, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint")
	addHandler(env, router, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint")

	return router
}

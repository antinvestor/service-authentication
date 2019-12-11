package handlers

import (
	"antinvestor.com/service/auth/service/profile"
	"antinvestor.com/service/auth/utils"
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/opentracing/opentracing-go"
)

var registerTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/registration.html"))

func ShowRegisterEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, _ := opentracing.StartSpanFromContext(req.Context(), "ShowRegisterEndpoint")
	defer span.Finish()

	err := registerTmpl.Execute(rw, map[string]interface{}{
		"error":          "",
		csrf.TemplateTag: csrf.TemplateField(req),
	})
	return err
	return nil

}


func SubmitRegisterEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {
	span, ctx := opentracing.StartSpanFromContext(req.Context(), "SubmitRegisterEndpoint")
	defer span.Finish()

	contact := req.PostForm.Get("contact")
	existingProfile, err := getProfileByContact(env, ctx, contact)
	if err != nil {
		return err
	}

	if existingProfile != nil {
		// don't have this profile in existence so we create it

		name := req.PostForm.Get("name")
		existingProfile, err = createProfileByContactAndName(env, ctx, contact, name)
		if err != nil {
			return err
		}
	}

	profileId := existingProfile.GetID()
	password := req.PostForm.Get("password")
	redirectUri, err := createAuthEntry(env, ctx, profileId, password)
	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUri, http.StatusSeeOther)

	return nil
}

func getProfileByContact(env *utils.Env, ctx context.Context, contact string) (*profile.ProfileObject, error) {

	profileCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	profileService := profile.NewProfileServiceClient(env.GetProfileServiceConn())

	contactRequest := profile.ProfileContactRequest{
		Contact: contact,
	}

	return profileService.GetByContact(profileCtx, &contactRequest)
}

func createProfileByContactAndName(env *utils.Env, ctx context.Context, contact string, name string) (*profile.ProfileObject, error) {

	profileCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	profileService := profile.NewProfileServiceClient(env.GetProfileServiceConn())

	createProfileRequest := profile.ProfileCreateRequest{
		Contact: contact,
	}
	createProfileRequest.GetProperties()["name"] = name

	return profileService.Create(profileCtx, &createProfileRequest)
}

func createAuthEntry(env *utils.Env, ctx context.Context, profileId string, password string) (string, error) {
	return "", nil
}

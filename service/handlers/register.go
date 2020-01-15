package handlers

import (
	"antinvestor.com/service/auth/grpc/profile"
	"antinvestor.com/service/auth/models"
	"antinvestor.com/service/auth/utils"
	"context"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	loginChallenge := req.FormValue("login_challenge")

	err := registerTmpl.Execute(rw, map[string]interface{}{
		"error":           "",
		"loginChallenge": loginChallenge,
		csrf.TemplateTag:  csrf.TemplateField(req),
	})
	return err
}


func SubmitRegisterEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {
	span, ctx := opentracing.StartSpanFromContext(req.Context(), "SubmitRegisterEndpoint")
	defer span.Finish()

	contact := req.PostForm.Get("contact")
	loginChallenge := req.PostForm.Get("login_challenge")
	existingProfile, err := getProfileByContact(env, ctx, contact)

	if err != nil{
		env.Logger.WithError(err).WithField("contact", contact).Info("couldn't get by profile")
		st, ok := status.FromError(err)
		if !ok ||  st.Code() != codes.NotFound{
			return err
		}
	}

	if existingProfile == nil {
		// don't have this profile in existence so we create it

		name := req.PostForm.Get("name")
		existingProfile, err = createProfileByContactAndName(env, ctx, contact, name)
		if err != nil {
			env.Logger.WithError(err).WithField("contact", contact).Info("couldn't create profile")
			return err
		}
	}

	profileId := existingProfile.GetID()
	password := req.PostForm.Get("password")
	redirectUri, err := createAuthEntry(env, ctx, profileId, password, loginChallenge)
	if err != nil {
		env.Logger.WithError(err).WithField("contact", contact).Info("couldn't create auth entry")
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

	properties := make(map[string]string)
	properties["name"] = name


	profileService := profile.NewProfileServiceClient(env.GetProfileServiceConn())

	createProfileRequest := profile.ProfileCreateRequest{
		Contact: contact,
		Properties: properties,
	}

	return profileService.Create(profileCtx, &createProfileRequest)
}

func createAuthEntry(env *utils.Env, ctx context.Context, profileId string, password string, loginChallenge string) (string, error) {

	profileHash := utils.HashStringSecret(profileId)

	crypt := utils.NewBCrypt()
	passwordHash, err := crypt.Hash(ctx, []byte(password))
	if err != nil {
		return "/register", err
	}

	login := models.Login{
		ProfileHash: profileHash,
		PasswordHash: passwordHash,
	}
	if err := env.GetRDb(ctx).Create(&login).Error; err != nil {
		return "/register", err
	}

	return fmt.Sprintf("/login?login_challenge=%s", loginChallenge), nil
}

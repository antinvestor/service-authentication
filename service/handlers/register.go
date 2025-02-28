package handlers

import (
	"context"
	"fmt"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"html/template"
	"log"
	"net/http"
)

var registerTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/registration.html"))

func ShowRegisterEndpoint(rw http.ResponseWriter, req *http.Request) error {

	loginChallenge := req.FormValue("login_challenge")

	payload := initTemplatePayload(req.Context())
	payload["error"] = ""
	payload["loginChallenge"] = loginChallenge
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := registerTmpl.Execute(rw, payload)
	return err
}

func SubmitRegisterEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	profileCli := profilev1.FromContext(ctx)
	service := frame.FromContext(ctx)

	contact := req.PostForm.Get("contact")
	name := req.PostForm.Get("name")
	loginChallenge := req.PostForm.Get("login_challenge")

	existingProfile, err := profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		log.Printf(" SubmitRegisterEndpoint -- could not get profile by contact %s : %v", contact, err)
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.NotFound {

			payload := initTemplatePayload(req.Context())
			payload["error"] = service.Translate(ctx, req, "CouldNotCheckContactExists")
			payload["contact"] = contact
			payload["name"] = name
			payload["loginChallenge"] = loginChallenge
			payload[csrf.TemplateTag] = csrf.TemplateField(req)

			err2 := registerTmpl.Execute(rw, payload)
			if err2 != nil {
				return err2
			}

			return err
		}
	}

	if existingProfile == nil {
		// don't have this profile in existence so we create it

		existingProfile, err = profileCli.CreateProfileByContactAndName(ctx, contact, name)
		if err != nil {
			log.Printf(" SubmitRegisterEndpoint -- could not create profile by contact %s : %v", contact, err)

			payload := initTemplatePayload(req.Context())
			payload["error"] = service.Translate(ctx, req, "CouldNotCreateProfileByContact")
			payload["contact"] = contact
			payload["name"] = name
			payload["loginChallenge"] = loginChallenge
			payload[csrf.TemplateTag] = csrf.TemplateField(req)

			err2 := registerTmpl.Execute(rw, payload)
			if err2 != nil {
				return err2
			}

			return err
		}
	}

	profileId := existingProfile.GetId()
	password := req.PostForm.Get("password")
	redirectUri, err := createAuthEntry(ctx, profileId, password, loginChallenge)
	if err != nil {
		log.Printf(" SubmitRegisterEndpoint -- could not create auth entry for profile %s : %+v", profileId, err)

		payload := initTemplatePayload(req.Context())
		payload["error"] = service.Translate(ctx, req, "CouldNotCreateLoginDetails")
		payload["contact"] = contact
		payload["name"] = name
		payload["loginChallenge"] = loginChallenge
		payload[csrf.TemplateTag] = csrf.TemplateField(req)

		err2 := registerTmpl.Execute(rw, payload)
		if err2 != nil {
			return err2
		}

		return err
	}

	http.Redirect(rw, req, redirectUri, http.StatusSeeOther)

	return nil
}

func createAuthEntry(ctx context.Context, profileId string, password string, loginChallenge string) (string, error) {

	service := frame.FromContext(ctx)

	profileHash := utils.HashStringSecret(profileId)

	crypt := utils.NewBCrypt()
	passwordHash, err := crypt.Hash(ctx, []byte(password))
	if err != nil {
		return "/s/register", err
	}

	login := &models.Login{
		ProfileHash:  profileHash,
		PasswordHash: passwordHash,
	}
	if err = service.DB(ctx, false).Create(login).Error; err != nil {
		return "/s/register", err
	}

	return fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge), nil
}

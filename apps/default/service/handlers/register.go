package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (h *AuthServer) ShowRegisterEndpoint(rw http.ResponseWriter, req *http.Request) error {

	loginChallenge := req.FormValue("login_challenge")

	payload := initTemplatePayload(req.Context())
	payload["error"] = ""
	payload["loginChallenge"] = loginChallenge
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := registerTmpl.Execute(rw, payload)
	return err
}

func (h *AuthServer) SubmitRegisterEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	contact := req.PostForm.Get("contact")
	name := req.PostForm.Get("name")
	loginChallenge := req.PostForm.Get("login_challenge")

	existingProfile, err := h.profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		log.Printf(" SubmitRegisterEndpoint -- could not get profile by contact %s : %v", contact, err)
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.NotFound {

			payload := initTemplatePayload(req.Context())
			payload["error"] = h.service.Translate(ctx, req, "CouldNotCheckContactExists")
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

		existingProfile, err = h.profileCli.CreateProfileByContactAndName(ctx, contact, name)
		if err != nil {
			log.Printf(" SubmitRegisterEndpoint -- could not create profile by contact %s : %v", contact, err)

			payload := initTemplatePayload(req.Context())
			payload["error"] = h.service.Translate(ctx, req, "CouldNotCreateProfileByContact")
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

	password := req.PostForm.Get("password")
	confirmPassword := req.PostForm.Get("confirmPassword")

	if password != confirmPassword {

		payload := initTemplatePayload(req.Context())
		payload["error"] = h.service.Translate(ctx, req, "PasswordsDoNotMatch")
		payload["contact"] = contact
		payload["name"] = name
		payload["loginChallenge"] = loginChallenge
		payload[csrf.TemplateTag] = csrf.TemplateField(req)

		err = registerTmpl.Execute(rw, payload)
		if err != nil {
			return err
		}

		return nil
	}

	profileId := existingProfile.GetId()

	redirectUri, err := h.createAuthEntry(ctx, profileId, password, loginChallenge)

	if err != nil {
		log.Printf(" SubmitRegisterEndpoint -- could not create auth entry for profile %s : %+v", profileId, err)

		payload := initTemplatePayload(req.Context())
		payload["error"] = h.service.Translate(ctx, req, "CouldNotCreateLoginDetails")
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

func (h *AuthServer) createAuthEntry(ctx context.Context, profileId string, password string, loginChallenge string) (string, error) {

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
	err = h.loginRepo.Save(ctx, login)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could not save login")
		return "/s/register", err
	}

	return fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge), nil
}

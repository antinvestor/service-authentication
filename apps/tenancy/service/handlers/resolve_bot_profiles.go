package handlers

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const botEmailDomain = "stawi.org"

type botProfileResolution struct {
	Scanned    int
	Resolved   int
	Unresolved int
	Skipped    int
}

// resolveBotProfiles ensures every service account has a real profile_id
// from the profile service. Migration-seeded SAs use placeholder profile_ids
// (e.g. "service_authentication") — this step replaces them with actual
// ProfileType_BOT profile IDs before Hydra sync so tokens carry valid subjects.
//
// The bot email is derived from the SA's ClientID field:
//
//	"service-authentication" → authentication.bot@stawi.org
//	"foundry"                → foundry.bot@stawi.org
func (prtSrv *PartitionServer) resolveBotProfiles(ctx context.Context) botProfileResolution {
	result := botProfileResolution{}

	if prtSrv.ProfileCli == nil {
		util.Log(ctx).Warn("profile client not configured, skipping bot profile resolution")
		return result
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)
	log := util.Log(ctx)

	allSAs, err := prtSrv.ServiceAccountRepo.GetAllBy(ctx, nil, 0, math.MaxInt32)
	if err != nil {
		log.WithError(err).Error("failed to list service accounts for bot profile resolution")
		return result
	}

	result.Scanned = len(allSAs)

	for _, sa := range allSAs {
		if !isPlaceholderProfileID(sa.ProfileID) {
			result.Skipped++
			continue
		}

		email := botEmailFromClientID(sa.ClientID)
		if email == "" {
			log.WithField("client_id", sa.ClientID).
				Debug("cannot derive bot email from service account client_id, skipping")
			result.Skipped++
			continue
		}

		profileID, profileErr := prtSrv.ensureBotProfile(ctx, email)
		if profileErr != nil {
			log.WithError(profileErr).
				WithField("sa_id", sa.GetID()).
				WithField("email", email).
				Error("failed to create bot profile for service account")
			result.Unresolved++
			continue
		}

		sa.ProfileID = profileID
		if _, updateErr := prtSrv.ServiceAccountRepo.Update(ctx, sa, "profile_id"); updateErr != nil {
			log.WithError(updateErr).
				WithField("sa_id", sa.GetID()).
				WithField("profile_id", profileID).
				Error("failed to update service account profile_id")
			result.Unresolved++
			continue
		}

		log.WithField("sa_id", sa.GetID()).
			WithField("client_id", sa.ClientID).
			WithField("email", email).
			WithField("profile_id", profileID).
			Info("resolved bot profile for service account")
		result.Resolved++
	}

	log.WithFields(map[string]any{
		"scanned":    result.Scanned,
		"resolved":   result.Resolved,
		"unresolved": result.Unresolved,
		"skipped":    result.Skipped,
	}).Info("bot profile resolution completed")

	return result
}

// ensureBotProfile looks up or creates a ProfileType_BOT profile for the given email.
func (prtSrv *PartitionServer) ensureBotProfile(ctx context.Context, email string) (string, error) {
	resp, err := prtSrv.ProfileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{
		Contact: email,
	}))
	if err == nil && resp.Msg.GetData() != nil && resp.Msg.GetData().GetId() != "" {
		return resp.Msg.GetData().GetId(), nil
	}

	if err != nil && !frame.ErrorIsNotFound(err) && connect.CodeOf(err) != connect.CodeNotFound {
		return "", err
	}

	req := &profilev1.CreateRequest{}
	req.SetType(profilev1.ProfileType_BOT)
	req.SetContact(email)

	createResp, createErr := prtSrv.ProfileCli.Create(ctx, connect.NewRequest(req))
	if createErr != nil {
		return "", createErr
	}
	if createResp.Msg.GetData() == nil {
		return "", errors.New("profile service returned empty bot profile")
	}

	return createResp.Msg.GetData().GetId(), nil
}

// botEmailFromClientID derives a bot email from a service account's client_id.
// The client_id from migrations follows patterns like "service-authentication",
// "service-notification-integration-africastalking", or bare names like "foundry".
func botEmailFromClientID(clientID string) string {
	if clientID == "" {
		return ""
	}
	name := strings.TrimPrefix(clientID, "service-")
	return fmt.Sprintf("%s.bot@%s", name, botEmailDomain)
}

// isPlaceholderProfileID returns true if the profile_id looks like a
// human-readable placeholder rather than a real profile service ID.
// Placeholder values from migrations contain underscores (e.g.
// "service_authentication") or are short alphabetic names (e.g. "foundry").
// Real profile IDs are exactly 20 characters long with no underscores.
func isPlaceholderProfileID(profileID string) bool {
	if profileID == "" {
		return true
	}
	if strings.Contains(profileID, "_") {
		return true
	}
	return len(profileID) != 20
}

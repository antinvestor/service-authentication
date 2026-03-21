package handlers

import (
	"context"
	"errors"
	"math"
	"strings"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/pkg/botdefs"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// resolveBotProfiles ensures every service account has a real profile_id
// from the profile service. Migration-seeded SAs use placeholder profile_ids
// (e.g. "service_authentication") — this step replaces them with actual
// ProfileType_BOT profile IDs before Hydra sync so tokens carry valid subjects.
func (prtSrv *PartitionServer) resolveBotProfiles(ctx context.Context) {
	if prtSrv.ProfileCli == nil {
		util.Log(ctx).Warn("profile client not configured, skipping bot profile resolution")
		return
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)
	log := util.Log(ctx)

	allSAs, err := prtSrv.ServiceAccountRepo.GetAllBy(ctx, nil, 0, math.MaxInt32)
	if err != nil {
		log.WithError(err).Error("failed to list service accounts for bot profile resolution")
		return
	}

	placeholderToEmail := buildPlaceholderEmailMap()

	resolved := 0
	for _, sa := range allSAs {
		if !isPlaceholderProfileID(sa.ProfileID) {
			continue
		}

		email, ok := placeholderToEmail[sa.ProfileID]
		if !ok {
			log.WithField("profile_id", sa.ProfileID).
				Debug("service account profile_id is not a known bot placeholder, skipping")
			continue
		}

		profileID, profileErr := prtSrv.ensureBotProfile(ctx, email)
		if profileErr != nil {
			log.WithError(profileErr).
				WithField("sa_id", sa.GetID()).
				WithField("email", email).
				Error("failed to create bot profile for service account")
			continue
		}

		sa.ProfileID = profileID
		if _, updateErr := prtSrv.ServiceAccountRepo.Update(ctx, sa, "profile_id"); updateErr != nil {
			log.WithError(updateErr).
				WithField("sa_id", sa.GetID()).
				WithField("profile_id", profileID).
				Error("failed to update service account profile_id")
			continue
		}

		log.WithField("sa_id", sa.GetID()).
			WithField("email", email).
			WithField("profile_id", profileID).
			Info("resolved bot profile for service account")
		resolved++
	}

	if resolved > 0 {
		log.WithField("resolved", resolved).Info("bot profile resolution completed")
	}
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

// buildPlaceholderEmailMap creates a mapping from the migration placeholder
// profile_id values to bot email addresses.
//
// Migration SQL uses values like:
//
//	"service_authentication" → authentication.bot@stawi.org
//	"service_notifications" → notification.bot@stawi.org
//	"foundry"               → foundry.bot@stawi.org
func buildPlaceholderEmailMap() map[string]string {
	m := make(map[string]string)
	for _, d := range botdefs.All() {
		placeholder := migrationProfileID(d.Function)
		m[placeholder] = botdefs.Email(d.Function)
	}
	return m
}

// migrationProfileID converts a bot function name to the placeholder value
// used as profile_id in the seed migration SQL.
func migrationProfileID(function string) string {
	name := strings.ReplaceAll(function, "-", "_")
	switch name {
	case "foundry", "gitvault", "trustage":
		return name
	case "sync":
		return "synchronise_partitions"
	case "notification":
		return "service_notifications"
	case "device":
		return "service_devices"
	case "notification_africastalking":
		return "service_notification_africastalking"
	case "notification_emailsmtp":
		return "service_notification_emailsmtp"
	default:
		return "service_" + name
	}
}

// isPlaceholderProfileID returns true if the profile_id looks like a
// human-readable placeholder rather than a real profile service ID.
// Real profile IDs are xid-format strings (20 chars, [0-9a-v]).
func isPlaceholderProfileID(profileID string) bool {
	if profileID == "" {
		return true
	}
	if len(profileID) != 20 {
		return true
	}
	for _, c := range profileID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'v')) {
			return true
		}
	}
	return false
}

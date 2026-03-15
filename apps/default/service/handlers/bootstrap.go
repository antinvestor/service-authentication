package handlers

import (
	"context"
	"fmt"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/util"
)

// DefaultBotContact is the contact detail for the platform's default bot profile.
// All internal service accounts should be attached to this profile.
const DefaultBotContact = "system.bot@stawi.org"

// EnsureDefaultBotProfile creates the default bot profile if it doesn't already exist.
// This should be called during service startup to ensure core internal services
// have a profile to attach their service accounts to.
func (h *AuthServer) EnsureDefaultBotProfile(ctx context.Context) error {
	log := util.Log(ctx)

	// Check if the bot profile already exists
	resp, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{
		Contact: DefaultBotContact,
	}))
	if err == nil && resp.Msg.GetData() != nil {
		profile := resp.Msg.GetData()
		if profile.GetType() != profilev1.ProfileType_BOT {
			log.WithField("profile_id", profile.GetId()).
				WithField("current_type", profile.GetType().String()).
				Warn("default bot profile exists but has wrong type")
		}
		log.WithField("profile_id", profile.GetId()).Info("default bot profile exists")
		return nil
	}

	// Create the bot profile
	createResp, err := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:    profilev1.ProfileType_BOT,
		Contact: DefaultBotContact,
	}))
	if err != nil {
		return fmt.Errorf("failed to create default bot profile: %w", err)
	}

	log.WithField("profile_id", createResp.Msg.GetData().GetId()).
		Info("created default bot profile")
	return nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/pkg/tenantenv"
	"github.com/pitabwire/util"
)

const (
	seedBotUsersCommandName = "seed-bot-users"
	botEmailDomain          = "stawi.org"
)

// botDefinition describes a service bot profile to seed.
type botDefinition struct {
	Function    string
	Description string
}

// defaultBotDefinitions returns the list of bot profiles to seed for service accounts.
func defaultBotDefinitions() []botDefinition {
	return []botDefinition{
		{Function: "authentication", Description: "Authentication service bot"},
		{Function: "profile", Description: "Profile service bot"},
		{Function: "tenancy", Description: "Tenancy service bot"},
		{Function: "notification", Description: "Notification service bot"},
		{Function: "device", Description: "Device service bot"},
		{Function: "settings", Description: "Settings service bot"},
		{Function: "payment", Description: "Payment service bot"},
		{Function: "payment-jenga", Description: "Jenga payment integration bot"},
		{Function: "ledger", Description: "Ledger service bot"},
		{Function: "billing", Description: "Billing service bot"},
		{Function: "files", Description: "Files service bot"},
		{Function: "chat-drone", Description: "Chat drone service bot"},
		{Function: "chat-gateway", Description: "Chat gateway service bot"},
		{Function: "foundry", Description: "Foundry service bot"},
		{Function: "gitvault", Description: "Gitvault service bot"},
		{Function: "trustage", Description: "Trustage service bot"},
		{Function: "notification-africastalking", Description: "Africa's Talking notification integration bot"},
		{Function: "notification-emailsmtp", Description: "SMTP email notification integration bot"},
		{Function: "sync", Description: "Partition synchronisation bot"},
	}
}

func botEmail(function string) string {
	return fmt.Sprintf("%s.bot@%s", function, botEmailDomain)
}

type seedBotUsersResult struct {
	Created  int
	Existing int
	Errors   int
	Details  []seedBotUserDetail
}

type seedBotUserDetail struct {
	Function  string
	Email     string
	ProfileID string
	Created   bool
	Error     string
}

type botUserProfileService interface {
	GetByContact(ctx context.Context, contact string) (*profilev1.ProfileObject, error)
	CreateBotProfile(ctx context.Context, email, description string) (*profilev1.ProfileObject, error)
}

type botUserSeeder struct {
	profiles botUserProfileService
}

func runSeedBotUsersCommand(ctx context.Context, cfg aconfig.AuthenticationConfig, args []string) error {
	flagSet := flag.NewFlagSet(seedBotUsersCommandName, flag.ContinueOnError)
	environment := flagSet.String("environment", "", "target root environment: production or staging")

	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*environment) == "" {
		return fmt.Errorf("%s requires --environment", seedBotUsersCommandName)
	}

	if _, err := tenantenv.ParseToProto(*environment); err != nil {
		return err
	}

	profileCli, err := setupProfileClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup profile client: %w", err)
	}

	seeder := &botUserSeeder{
		profiles: connectBotUserProfileService{client: profileCli},
	}

	result := seeder.SeedBotUsers(ctx)

	util.Log(ctx).WithFields(map[string]any{
		"environment": tenantenv.Normalise(*environment),
		"created":     result.Created,
		"existing":    result.Existing,
		"errors":      result.Errors,
	}).Info("seeded bot users completed")

	for _, detail := range result.Details {
		fields := map[string]any{
			"function":   detail.Function,
			"email":      detail.Email,
			"profile_id": detail.ProfileID,
			"created":    detail.Created,
		}
		if detail.Error != "" {
			fields["error"] = detail.Error
			util.Log(ctx).WithFields(fields).Warn("bot user seed failed")
		} else {
			util.Log(ctx).WithFields(fields).Info("bot user seeded")
		}
	}

	return nil
}

func (s *botUserSeeder) SeedBotUsers(ctx context.Context) *seedBotUsersResult {
	bots := defaultBotDefinitions()
	result := &seedBotUsersResult{
		Details: make([]seedBotUserDetail, 0, len(bots)),
	}

	for _, bot := range bots {
		detail := s.seedOneBot(ctx, bot)
		result.Details = append(result.Details, detail)

		switch {
		case detail.Error != "":
			result.Errors++
		case detail.Created:
			result.Created++
		default:
			result.Existing++
		}
	}

	return result
}

func (s *botUserSeeder) seedOneBot(ctx context.Context, bot botDefinition) seedBotUserDetail {
	email := botEmail(bot.Function)
	detail := seedBotUserDetail{
		Function: bot.Function,
		Email:    email,
	}

	profile, err := s.profiles.GetByContact(ctx, email)
	if err == nil && profile != nil && profile.GetId() != "" {
		detail.ProfileID = profile.GetId()
		detail.Created = false
		return detail
	}

	if err != nil && !isNotFoundError(err) {
		detail.Error = fmt.Sprintf("lookup failed: %v", err)
		return detail
	}

	profile, err = s.profiles.CreateBotProfile(ctx, email, bot.Description)
	if err != nil {
		detail.Error = fmt.Sprintf("create failed: %v", err)
		return detail
	}

	detail.ProfileID = profile.GetId()
	detail.Created = true
	return detail
}

// connectBotUserProfileService adapts the profile Connect client for bot seeding.
type connectBotUserProfileService struct {
	client profilev1connect.ProfileServiceClient
}

func (c connectBotUserProfileService) GetByContact(ctx context.Context, contact string) (*profilev1.ProfileObject, error) {
	resp, err := c.client.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{
		Contact: contact,
	}))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("profile service returned empty profile")
	}
	return resp.Msg.GetData(), nil
}

func (c connectBotUserProfileService) CreateBotProfile(ctx context.Context, email, description string) (*profilev1.ProfileObject, error) {
	req := &profilev1.CreateRequest{}
	req.SetType(profilev1.ProfileType_BOT)
	req.SetContact(email)

	resp, err := c.client.Create(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("profile service returned empty created bot profile")
	}
	return resp.Msg.GetData(), nil
}

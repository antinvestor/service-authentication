package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/pkg/botdefs"
	"github.com/antinvestor/service-authentication/pkg/tenantenv"
	"github.com/pitabwire/util"
)

const seedBotUsersCommandName = "seed-bot-users"

// botServiceAccountName returns the SA display name matching the migration convention.
func botServiceAccountName(function string) string {
	return strings.ReplaceAll(function, "-", "_")
}

type seedBotUsersResult struct {
	Created  int
	Existing int
	Errors   int
	Details  []seedBotUserDetail
}

type seedBotUserDetail struct {
	Function         string
	Email            string
	ProfileID        string
	ServiceAccountID string
	CreatedProfile   bool
	CreatedSA        bool
	Error            string
}

type botUserProfileService interface {
	GetByContact(ctx context.Context, contact string) (*profilev1.ProfileObject, error)
	CreateBotProfile(ctx context.Context, email string) (*profilev1.ProfileObject, error)
}

type botUserPartitionService interface {
	ListServiceAccounts(ctx context.Context, partitionID string) ([]*partitionv1.ServiceAccountObject, error)
	CreateServiceAccount(ctx context.Context, partitionID, profileID, name, saType string, audiences []string) (*partitionv1.CreateServiceAccountResponse, error)
}

type botUserSeeder struct {
	profiles    botUserProfileService
	partitions  botUserPartitionService
	partitionID string
	existingSAs map[string]*partitionv1.ServiceAccountObject // keyed by profile_id
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

	environmentEnum, err := tenantenv.ParseToProto(*environment)
	if err != nil {
		return err
	}

	partitionID, err := rootPartitionIDForEnvironment(environmentEnum)
	if err != nil {
		return err
	}

	profileCli, err := setupProfileClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup profile client: %w", err)
	}

	partitionCli, err := setupPartitionClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup partition client: %w", err)
	}

	seeder := &botUserSeeder{
		profiles:   connectBotUserProfileService{client: profileCli},
		partitions: connectBotUserPartitionService{client: partitionCli},
	}

	result, err := seeder.SeedBotUsers(ctx, partitionID)
	if err != nil {
		return err
	}

	util.Log(ctx).WithFields(map[string]any{
		"environment":  tenantenv.Normalise(*environment),
		"partition_id": partitionID,
		"created":      result.Created,
		"existing":     result.Existing,
		"errors":       result.Errors,
	}).Info("seeded bot users completed")

	for _, detail := range result.Details {
		fields := map[string]any{
			"function":           detail.Function,
			"email":              detail.Email,
			"profile_id":         detail.ProfileID,
			"service_account_id": detail.ServiceAccountID,
			"created_profile":    detail.CreatedProfile,
			"created_sa":         detail.CreatedSA,
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

func (s *botUserSeeder) SeedBotUsers(ctx context.Context, partitionID string) (*seedBotUsersResult, error) {
	s.partitionID = partitionID

	existingSAs, err := s.partitions.ListServiceAccounts(ctx, partitionID)
	if err != nil {
		return nil, fmt.Errorf("list existing service accounts for partition %s: %w", partitionID, err)
	}

	s.existingSAs = make(map[string]*partitionv1.ServiceAccountObject, len(existingSAs))
	for _, sa := range existingSAs {
		s.existingSAs[sa.GetProfileId()] = sa
	}

	allBots := botdefs.All()
	result := &seedBotUsersResult{
		Details: make([]seedBotUserDetail, 0, len(allBots)),
	}

	for _, bot := range allBots {
		detail := s.seedOneBot(ctx, bot)
		result.Details = append(result.Details, detail)

		switch {
		case detail.Error != "":
			result.Errors++
		case detail.CreatedProfile || detail.CreatedSA:
			result.Created++
		default:
			result.Existing++
		}
	}

	return result, nil
}

func (s *botUserSeeder) seedOneBot(ctx context.Context, bot botdefs.Definition) seedBotUserDetail {
	email := botdefs.Email(bot.Function)
	detail := seedBotUserDetail{
		Function: bot.Function,
		Email:    email,
	}

	profileID, createdProfile, err := s.ensureBotProfile(ctx, email)
	if err != nil {
		detail.Error = fmt.Sprintf("profile: %v", err)
		return detail
	}
	detail.ProfileID = profileID
	detail.CreatedProfile = createdProfile

	saID, createdSA, err := s.ensureServiceAccount(ctx, profileID, bot)
	if err != nil {
		detail.Error = fmt.Sprintf("service account: %v", err)
		return detail
	}
	detail.ServiceAccountID = saID
	detail.CreatedSA = createdSA

	return detail
}

func (s *botUserSeeder) ensureBotProfile(ctx context.Context, email string) (string, bool, error) {
	profile, err := s.profiles.GetByContact(ctx, email)
	if err == nil && profile != nil && profile.GetId() != "" {
		return profile.GetId(), false, nil
	}

	if err != nil && !isNotFoundError(err) {
		return "", false, fmt.Errorf("lookup failed: %w", err)
	}

	profile, err = s.profiles.CreateBotProfile(ctx, email)
	if err != nil {
		return "", false, fmt.Errorf("create failed: %w", err)
	}

	return profile.GetId(), true, nil
}

func (s *botUserSeeder) ensureServiceAccount(ctx context.Context, profileID string, bot botdefs.Definition) (string, bool, error) {
	if existing, ok := s.existingSAs[profileID]; ok {
		return existing.GetId(), false, nil
	}

	name := botServiceAccountName(bot.Function)
	resp, err := s.partitions.CreateServiceAccount(ctx, s.partitionID, profileID, name, botdefs.ServiceAccountType, bot.Audiences)
	if err != nil {
		return "", false, fmt.Errorf("create failed: %w", err)
	}

	sa := resp.GetData()
	if sa == nil {
		return "", false, errors.New("partition service returned empty service account")
	}

	return sa.GetId(), true, nil
}

// --- Connect client adapters ---

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

func (c connectBotUserProfileService) CreateBotProfile(ctx context.Context, email string) (*profilev1.ProfileObject, error) {
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

type connectBotUserPartitionService struct {
	client partitionv1connect.PartitionServiceClient
}

func (c connectBotUserPartitionService) ListServiceAccounts(ctx context.Context, partitionID string) ([]*partitionv1.ServiceAccountObject, error) {
	req := &partitionv1.ListServiceAccountRequest{}
	req.SetPartitionId(partitionID)

	stream, err := c.client.ListServiceAccount(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}

	var accounts []*partitionv1.ServiceAccountObject
	for stream.Receive() {
		accounts = append(accounts, stream.Msg().GetData()...)
	}

	return accounts, stream.Err()
}

func (c connectBotUserPartitionService) CreateServiceAccount(
	ctx context.Context,
	partitionID, profileID, name, saType string,
	audiences []string,
) (*partitionv1.CreateServiceAccountResponse, error) {
	req := &partitionv1.CreateServiceAccountRequest{}
	req.SetPartitionId(partitionID)
	req.SetProfileId(profileID)
	req.SetName(name)
	req.SetType(saType)
	req.SetAudiences(audiences)

	resp, err := c.client.CreateServiceAccount(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}

	return resp.Msg, nil
}

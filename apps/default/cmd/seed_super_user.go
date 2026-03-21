package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/pkg/tenantenv"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

const (
	seedSuperUserCommandName  = "seed-super-user"
	rootEnvironmentProduction = tenantenv.Production
	rootEnvironmentStaging    = tenantenv.Staging
	rootPartitionProductionID = "c2f4j7au6s7f91uqnokg"
	rootPartitionStagingID    = "9bsv0s3pbdv002o80qhg"
)

type seedSuperUserResult struct {
	ProfileID       string
	PartitionID     string
	AccessID        string
	PartitionRoleID string
	CreatedProfile  bool
	CreatedRole     bool
	AssignedRole    bool
}

type superUserProfileService interface {
	GetByContact(ctx context.Context, contact string) (*profilev1.ProfileObject, error)
	CreateProfile(ctx context.Context, email string) (*profilev1.ProfileObject, error)
}

type superUserPartitionService interface {
	CreateAccess(ctx context.Context, partitionID, profileID string) (*partitionv1.AccessObject, error)
	ListAccesses(ctx context.Context, partitionID string) ([]*partitionv1.AccessObject, error)
	ListPartitionRoles(ctx context.Context, partitionID string) ([]*partitionv1.PartitionRoleObject, error)
	CreatePartitionRole(ctx context.Context, partitionID, name string) (*partitionv1.PartitionRoleObject, error)
	ListAccessRoles(ctx context.Context, accessID string) ([]*partitionv1.AccessRoleObject, error)
	CreateAccessRole(ctx context.Context, accessID, partitionRoleID string) (*partitionv1.AccessRoleObject, error)
}

type superUserSeeder struct {
	profiles   superUserProfileService
	partitions superUserPartitionService
}

type existingSuperUser struct {
	ProfileID       string
	AccessID        string
	PartitionRoleID string
}

func handleOneShotCommands(ctx context.Context, cfg aconfig.AuthenticationConfig) (bool, error) {
	if len(os.Args) < 2 {
		return false, nil
	}

	switch os.Args[1] {
	case seedSuperUserCommandName:
		return true, runSeedSuperUserCommand(ctx, cfg, os.Args[2:])
	case seedBotUsersCommandName:
		return true, runSeedBotUsersCommand(ctx, cfg, os.Args[2:])
	default:
		return false, nil
	}
}

func runSeedSuperUserCommand(ctx context.Context, cfg aconfig.AuthenticationConfig, args []string) error {
	flagSet := flag.NewFlagSet(seedSuperUserCommandName, flag.ContinueOnError)
	email := flagSet.String("email", "", "email address of the super user to create or elevate")
	environment := flagSet.String("environment", "", "target root environment: production or staging")

	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*email) == "" && len(flagSet.Args()) > 0 {
		*email = flagSet.Args()[0]
	}

	if strings.TrimSpace(*email) == "" {
		return fmt.Errorf("%s requires --email", seedSuperUserCommandName)
	}
	if strings.TrimSpace(*environment) == "" {
		return fmt.Errorf("%s requires --environment", seedSuperUserCommandName)
	}

	profileCli, err := setupProfileClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup profile client: %w", err)
	}

	partitionCli, err := setupPartitionClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup partition client: %w", err)
	}

	seeder := &superUserSeeder{
		profiles:   connectSuperUserProfileService{client: profileCli},
		partitions: connectSuperUserPartitionService{client: partitionCli},
	}

	result, err := seeder.SeedSuperUser(ctx, *email, *environment)
	if err != nil {
		return err
	}

	util.Log(ctx).WithFields(map[string]any{
		"email":             strings.ToLower(strings.TrimSpace(*email)),
		"environment":       normalizeRootEnvironment(*environment),
		"profile_id":        result.ProfileID,
		"partition_id":      result.PartitionID,
		"access_id":         result.AccessID,
		"partition_role_id": result.PartitionRoleID,
		"created_profile":   result.CreatedProfile,
		"created_role":      result.CreatedRole,
		"assigned_role":     result.AssignedRole,
	}).Info("seeded super user successfully")

	return nil
}

func (s *superUserSeeder) SeedSuperUser(ctx context.Context, email string, environment string) (*seedSuperUserResult, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if !utils.IsEmail(normalizedEmail) {
		return nil, fmt.Errorf("invalid email address %q", email)
	}

	environmentEnum, err := tenantenv.ParseToProto(environment)
	if err != nil {
		return nil, err
	}

	profile, profileExists, err := s.findProfileByEmail(ctx, normalizedEmail)
	if err != nil {
		return nil, err
	}

	partitionID, err := rootPartitionIDForEnvironment(environmentEnum)
	if err != nil {
		return nil, err
	}

	existingOwner, err := s.findExistingSuperUser(ctx, partitionID)
	if err != nil {
		return nil, err
	}
	if existingOwner != nil && (!profileExists || profile.GetId() != existingOwner.ProfileID) {
		return nil, fmt.Errorf("a super user already exists for partition %s", partitionID)
	}

	createdProfile := false
	if !profileExists {
		profile, err = s.profiles.CreateProfile(ctx, normalizedEmail)
		if err != nil {
			return nil, fmt.Errorf("create profile for %s: %w", normalizedEmail, err)
		}
		createdProfile = true
	}

	access, err := s.partitions.CreateAccess(ctx, partitionID, profile.GetId())
	if err != nil {
		return nil, fmt.Errorf("create root partition access for profile %s: %w", profile.GetId(), err)
	}

	ownerRole, createdRole, err := s.getOrCreatePartitionRole(ctx, partitionID, authz.RoleOwner)
	if err != nil {
		return nil, err
	}

	assignedRole, err := s.ensureAccessRole(ctx, access.GetId(), ownerRole)
	if err != nil {
		return nil, err
	}

	return &seedSuperUserResult{
		ProfileID:       profile.GetId(),
		PartitionID:     partitionID,
		AccessID:        access.GetId(),
		PartitionRoleID: ownerRole.GetId(),
		CreatedProfile:  createdProfile,
		CreatedRole:     createdRole,
		AssignedRole:    assignedRole,
	}, nil
}

func (s *superUserSeeder) findProfileByEmail(ctx context.Context, email string) (*profilev1.ProfileObject, bool, error) {
	profile, err := s.profiles.GetByContact(ctx, email)
	if err == nil {
		if profile == nil || profile.GetId() == "" {
			return nil, false, fmt.Errorf("get profile by email %s: empty profile returned", email)
		}
		return profile, true, nil
	}
	if !isNotFoundError(err) {
		return nil, false, fmt.Errorf("get profile by email %s: %w", email, err)
	}

	return nil, false, nil
}

func (s *superUserSeeder) getOrCreatePartitionRole(
	ctx context.Context,
	partitionID string,
	roleName string,
) (*partitionv1.PartitionRoleObject, bool, error) {
	roles, err := s.partitions.ListPartitionRoles(ctx, partitionID)
	if err != nil {
		return nil, false, fmt.Errorf("list partition roles for %s: %w", partitionID, err)
	}

	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role.GetName()), roleName) {
			return role, false, nil
		}
	}

	role, err := s.partitions.CreatePartitionRole(ctx, partitionID, roleName)
	if err != nil {
		return nil, false, fmt.Errorf("create partition role %s for %s: %w", roleName, partitionID, err)
	}

	return role, true, nil
}

func (s *superUserSeeder) ensureAccessRole(
	ctx context.Context,
	accessID string,
	role *partitionv1.PartitionRoleObject,
) (bool, error) {
	roles, err := s.partitions.ListAccessRoles(ctx, accessID)
	if err != nil {
		return false, fmt.Errorf("list access roles for %s: %w", accessID, err)
	}

	for _, accessRole := range roles {
		if accessRole.GetRole().GetId() == role.GetId() {
			return false, nil
		}
		if strings.EqualFold(strings.TrimSpace(accessRole.GetRole().GetName()), role.GetName()) {
			return false, nil
		}
	}

	if _, err := s.partitions.CreateAccessRole(ctx, accessID, role.GetId()); err != nil {
		return false, fmt.Errorf("assign role %s to access %s: %w", role.GetName(), accessID, err)
	}

	return true, nil
}

func (s *superUserSeeder) findExistingSuperUser(ctx context.Context, partitionID string) (*existingSuperUser, error) {
	accesses, err := s.partitions.ListAccesses(ctx, partitionID)
	if err != nil {
		return nil, fmt.Errorf("list accesses for partition %s: %w", partitionID, err)
	}

	for _, access := range accesses {
		roles, roleErr := s.partitions.ListAccessRoles(ctx, access.GetId())
		if roleErr != nil {
			return nil, fmt.Errorf("list access roles for %s: %w", access.GetId(), roleErr)
		}

		for _, accessRole := range roles {
			if !strings.EqualFold(strings.TrimSpace(accessRole.GetRole().GetName()), authz.RoleOwner) {
				continue
			}

			return &existingSuperUser{
				ProfileID:       access.GetProfileId(),
				AccessID:        access.GetId(),
				PartitionRoleID: accessRole.GetRole().GetId(),
			}, nil
		}
	}

	return nil, nil
}

func normalizeRootEnvironment(environment string) string {
	return tenantenv.Normalise(environment)
}

func rootPartitionIDForEnvironment(environment partitionv1.TenantEnvironment) (string, error) {
	switch environment {
	case partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION:
		return rootPartitionProductionID, nil
	case partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING:
		return rootPartitionStagingID, nil
	default:
		return "", fmt.Errorf("unsupported environment %s", environment.String())
	}
}

func isNotFoundError(err error) bool {
	return frame.ErrorIsNotFound(err) || connect.CodeOf(err) == connect.CodeNotFound
}

type connectSuperUserProfileService struct {
	client profilev1connect.ProfileServiceClient
}

func (c connectSuperUserProfileService) GetByContact(ctx context.Context, contact string) (*profilev1.ProfileObject, error) {
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

func (c connectSuperUserProfileService) CreateProfile(ctx context.Context, email string) (*profilev1.ProfileObject, error) {
	resp, err := c.client.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:    profilev1.ProfileType_PERSON,
		Contact: email,
	}))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("profile service returned empty created profile")
	}

	return resp.Msg.GetData(), nil
}

type connectSuperUserPartitionService struct {
	client partitionv1connect.PartitionServiceClient
}

func (c connectSuperUserPartitionService) CreateAccess(
	ctx context.Context,
	partitionID, profileID string,
) (*partitionv1.AccessObject, error) {
	resp, err := c.client.CreateAccess(ctx, connect.NewRequest(&partitionv1.CreateAccessRequest{
		Partition: &partitionv1.CreateAccessRequest_PartitionId{PartitionId: partitionID},
		ProfileId: profileID,
	}))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("partition service returned empty access")
	}

	return resp.Msg.GetData(), nil
}

func (c connectSuperUserPartitionService) ListAccesses(
	ctx context.Context,
	partitionID string,
) ([]*partitionv1.AccessObject, error) {
	req := &partitionv1.ListAccessRequest{}
	req.SetPartitionId(partitionID)

	stream, err := c.client.ListAccess(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}

	var accesses []*partitionv1.AccessObject
	for stream.Receive() {
		accesses = append(accesses, stream.Msg().GetData()...)
	}

	return accesses, stream.Err()
}

func (c connectSuperUserPartitionService) ListPartitionRoles(
	ctx context.Context,
	partitionID string,
) ([]*partitionv1.PartitionRoleObject, error) {
	stream, err := c.client.ListPartitionRole(ctx, connect.NewRequest(&partitionv1.ListPartitionRoleRequest{
		PartitionId: partitionID,
	}))
	if err != nil {
		return nil, err
	}

	var roles []*partitionv1.PartitionRoleObject
	for stream.Receive() {
		roles = append(roles, stream.Msg().GetData()...)
	}

	return roles, stream.Err()
}

func (c connectSuperUserPartitionService) CreatePartitionRole(
	ctx context.Context,
	partitionID, name string,
) (*partitionv1.PartitionRoleObject, error) {
	resp, err := c.client.CreatePartitionRole(ctx, connect.NewRequest(&partitionv1.CreatePartitionRoleRequest{
		PartitionId: partitionID,
		Name:        name,
	}))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("partition service returned empty partition role")
	}

	return resp.Msg.GetData(), nil
}

func (c connectSuperUserPartitionService) ListAccessRoles(
	ctx context.Context,
	accessID string,
) ([]*partitionv1.AccessRoleObject, error) {
	stream, err := c.client.ListAccessRole(ctx, connect.NewRequest(&partitionv1.ListAccessRoleRequest{
		AccessId: accessID,
	}))
	if err != nil {
		return nil, err
	}

	var roles []*partitionv1.AccessRoleObject
	for stream.Receive() {
		roles = append(roles, stream.Msg().GetData()...)
	}

	return roles, stream.Err()
}

func (c connectSuperUserPartitionService) CreateAccessRole(
	ctx context.Context,
	accessID, partitionRoleID string,
) (*partitionv1.AccessRoleObject, error) {
	resp, err := c.client.CreateAccessRole(ctx, connect.NewRequest(&partitionv1.CreateAccessRoleRequest{
		AccessId:        accessID,
		PartitionRoleId: partitionRoleID,
	}))
	if err != nil {
		return nil, err
	}
	if resp.Msg.GetData() == nil {
		return nil, errors.New("partition service returned empty access role")
	}

	return resp.Msg.GetData(), nil
}

package tests

import (
	"fmt"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PartitionRepositoryTestSuite struct {
	BaseTestSuite
}

func TestPartitionRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(PartitionRepositoryTestSuite))
}

func (suite *PartitionRepositoryTestSuite) TestGetParents() {
	t := suite.T()
	svc, ctx := suite.CreateService(t, definition.NewDependancyOption("test_get_parents", "test_get_parents", nil))

	partitionRepo := repository.NewPartitionRepository(svc)

	// Create a hierarchy: Root -> Company -> Department -> Team
	// Root partition (no parent)
	rootPartition := &models.Partition{
		Name:        "Root Organisation",
		Description: "Top level organisation",
		ParentID:    "", // No parent
		State:       1,
	}
	rootPartition.GenID(ctx)
	err := partitionRepo.Save(ctx, rootPartition)
	require.NoError(t, err)

	// Company partition (parent: root)
	companyPartition := &models.Partition{
		Name:        "Acme Corporation",
		Description: "Main company",
		ParentID:    rootPartition.ID,
		State:       1,
	}
	companyPartition.GenID(ctx)
	err = partitionRepo.Save(ctx, companyPartition)
	require.NoError(t, err)

	// Department partition (parent: company)
	departmentPartition := &models.Partition{
		Name:        "Engineering Department",
		Description: "Software engineering team",
		ParentID:    companyPartition.ID,
		State:       1,
	}
	departmentPartition.GenID(ctx)
	err = partitionRepo.Save(ctx, departmentPartition)
	require.NoError(t, err)

	// Team partition (parent: department)
	teamPartition := &models.Partition{
		Name:        "Backend Team",
		Description: "Backend development team",
		ParentID:    departmentPartition.ID,
		State:       1,
	}
	teamPartition.GenID(ctx)
	err = partitionRepo.Save(ctx, teamPartition)
	require.NoError(t, err)

	// Test 1: Get parents of team partition (should return department, company, root)
	parents, err := partitionRepo.GetParents(ctx, teamPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 3, "Team should have 3 parents: department, company, root")

	// Verify the hierarchy order (should be ordered by creation time - oldest first)
	assert.Equal(t, rootPartition.ID, parents[0].ID, "First parent should be root (oldest)")
	assert.Equal(t, companyPartition.ID, parents[1].ID, "Second parent should be company")
	assert.Equal(t, departmentPartition.ID, parents[2].ID, "Third parent should be department (immediate parent)")

	// Test 2: Get parents of department partition (should return company, root)
	parents, err = partitionRepo.GetParents(ctx, departmentPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 2, "Department should have 2 parents: company, root")

	assert.Equal(t, rootPartition.ID, parents[0].ID, "First parent should be root")
	assert.Equal(t, companyPartition.ID, parents[1].ID, "Second parent should be company")

	// Test 3: Get parents of company partition (should return root only)
	parents, err = partitionRepo.GetParents(ctx, companyPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 1, "Company should have 1 parent: root")

	assert.Equal(t, rootPartition.ID, parents[0].ID, "Only parent should be root")

	// Test 4: Get parents of root partition (should return empty)
	parents, err = partitionRepo.GetParents(ctx, rootPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 0, "Root partition should have no parents")

	// Test 5: Get parents of non-existent partition (should return empty)
	parents, err = partitionRepo.GetParents(ctx, "non-existent-id")
	require.NoError(t, err)
	require.Len(t, parents, 0, "Non-existent partition should have no parents")
}

func (suite *PartitionRepositoryTestSuite) TestGetParentsWithOrphanedPartition() {
	t := suite.T()
	svc, ctx := suite.CreateService(t, definition.NewDependancyOption("test_orphaned", "test_orphaned", nil))

	partitionRepo := repository.NewPartitionRepository(svc)

	// Create a partition with a non-existent parent ID
	orphanedPartition := &models.Partition{
		Name:        "Orphaned Partition",
		Description: "Partition with missing parent",
		ParentID:    "non-existent-parent-id",
		State:       1,
	}
	orphanedPartition.GenID(ctx)
	err := partitionRepo.Save(ctx, orphanedPartition)
	require.NoError(t, err)

	// Test: Get parents of orphaned partition (should handle gracefully)
	parents, err := partitionRepo.GetParents(ctx, orphanedPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 0, "Orphaned partition should return no parents when parent doesn't exist")
}

func (suite *PartitionRepositoryTestSuite) TestGetParentsWithCircularReference() {
	t := suite.T()
	svc, ctx := suite.CreateService(t, definition.NewDependancyOption("test_circular", "test_circular", nil))

	partitionRepo := repository.NewPartitionRepository(svc)

	// Create two partitions that reference each other (circular reference)
	partition1 := &models.Partition{
		Name:        "Partition 1",
		Description: "First partition",
		ParentID:    "", // Will be set to partition2.ID later
		State:       1,
	}
	partition1.GenID(ctx)

	partition2 := &models.Partition{
		Name:        "Partition 2",
		Description: "Second partition",
		ParentID:    partition1.ID, // References partition1
		State:       1,
	}
	partition2.GenID(ctx)

	// Save partition1 first
	err := partitionRepo.Save(ctx, partition1)
	require.NoError(t, err)

	// Save partition2
	err = partitionRepo.Save(ctx, partition2)
	require.NoError(t, err)

	// Update partition1 to reference partition2 (creating circular reference)
	partition1.ParentID = partition2.ID
	err = partitionRepo.Save(ctx, partition1)
	require.NoError(t, err)

	// Test: Get parents should handle circular reference gracefully
	// Note: The CTE query should naturally handle this by the WHERE conditions and depth limit
	parents, err := partitionRepo.GetParents(ctx, partition1.ID)
	require.NoError(t, err)
	// Should return up to 5 parents due to depth limit, preventing infinite loop
	require.LessOrEqual(t, len(parents), 5, "Circular reference should not cause infinite results and be limited by depth")
}

func (suite *PartitionRepositoryTestSuite) TestGetParentsDeepHierarchy() {
	t := suite.T()
	svc, ctx := suite.CreateService(t, definition.NewDependancyOption("test_deep", "test_deep", nil))

	partitionRepo := repository.NewPartitionRepository(svc)

	// Create a deep hierarchy (10 levels)
	var partitions []*models.Partition
	var parentID string

	for i := 0; i < 10; i++ {
		partition := &models.Partition{
			Name:        fmt.Sprintf("Level %d", i),
			Description: fmt.Sprintf("Partition at level %d", i),
			ParentID:    parentID,
			State:       1,
		}
		partition.GenID(ctx)
		err := partitionRepo.Save(ctx, partition)
		require.NoError(t, err)

		partitions = append(partitions, partition)
		parentID = partition.ID // Next partition will have this as parent
	}

	// Test: Get parents of the deepest partition (should return 5 parents due to depth limit)
	deepestPartition := partitions[len(partitions)-1]
	parents, err := partitionRepo.GetParents(ctx, deepestPartition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 5, "Deepest partition should have 5 parents (limited by depth)")

	// Verify that we got the correct parents (the 5 immediate ancestors due to depth limit)
	// For the deepest partition (level 9), the 5 parents should be levels 8, 7, 6, 5, 4
	expectedParentIDs := make(map[string]bool)
	for i := 4; i < 9; i++ { // Levels 4, 5, 6, 7, 8
		expectedParentIDs[partitions[i].ID] = true
	}

	// Verify that all returned parents are in the expected set
	for i, parent := range parents {
		assert.True(t, expectedParentIDs[parent.ID],
			fmt.Sprintf("Parent at index %d (ID: %s) should be one of the first 5 levels", i, parent.ID))
	}

	// Verify that we have exactly the expected parents (no duplicates)
	returnedIDs := make(map[string]bool)
	for _, parent := range parents {
		assert.False(t, returnedIDs[parent.ID],
			fmt.Sprintf("Parent ID %s should not be duplicated", parent.ID))
		returnedIDs[parent.ID] = true
	}
}

func (suite *PartitionRepositoryTestSuite) TestGetParentsWithEmptyParentID() {
	t := suite.T()
	svc, ctx := suite.CreateService(t, definition.NewDependancyOption("test_empty_parent", "test_empty_parent", nil))

	partitionRepo := repository.NewPartitionRepository(svc)

	// Create partition with explicitly empty parent ID
	partition := &models.Partition{
		Name:        "Root Level Partition",
		Description: "Partition with empty parent ID",
		ParentID:    "",
		State:       1,
	}
	partition.GenID(ctx)
	err := partitionRepo.Save(ctx, partition)
	require.NoError(t, err)

	// Test: Should return no parents
	parents, err := partitionRepo.GetParents(ctx, partition.ID)
	require.NoError(t, err)
	require.Len(t, parents, 0, "Partition with empty parent ID should have no parents")
}

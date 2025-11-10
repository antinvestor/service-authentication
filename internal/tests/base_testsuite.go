package tests

import (
	"context"

	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
)

const (
	DefaultRandomStringLength = 8
)

type BaseTestSuite struct {
	frametests.FrameBaseTestSuite
}

func initResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"))
	resources := []definition.TestResource{pg}
	return resources
}

func (bs *BaseTestSuite) SetupSuite() {
	if bs.InitResourceFunc == nil {
		bs.InitResourceFunc = initResources
	}
	bs.FrameBaseTestSuite.SetupSuite()
}

func (bs *BaseTestSuite) TearDownSuite() {
	bs.FrameBaseTestSuite.TearDownSuite()
}

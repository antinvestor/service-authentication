package handlers

import (
	"testing"
	"time"

	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type ResendHelpersTestSuite struct {
	suite.Suite
}

func (s *ResendHelpersTestSuite) TestGetResendCount_Nil() {
	s.Equal(0, getResendCount(nil))
}

func (s *ResendHelpersTestSuite) TestGetResendCount_Empty() {
	s.Equal(0, getResendCount(data.JSONMap{}))
}

func (s *ResendHelpersTestSuite) TestGetResendCount_Int() {
	props := data.JSONMap{propKeyResendCount: 3}
	s.Equal(3, getResendCount(props))
}

func (s *ResendHelpersTestSuite) TestGetResendCount_Float64() {
	props := data.JSONMap{propKeyResendCount: float64(2)}
	s.Equal(2, getResendCount(props))
}

func (s *ResendHelpersTestSuite) TestGetResendCount_Int64() {
	props := data.JSONMap{propKeyResendCount: int64(5)}
	s.Equal(5, getResendCount(props))
}

func (s *ResendHelpersTestSuite) TestGetResendCount_UnknownType() {
	props := data.JSONMap{propKeyResendCount: "not-a-number"}
	s.Equal(0, getResendCount(props))
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_Nil() {
	s.True(getLastResendAt(nil).IsZero())
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_Empty() {
	s.True(getLastResendAt(data.JSONMap{}).IsZero())
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_RFC3339String() {
	now := time.Now().Truncate(time.Second)
	props := data.JSONMap{propKeyLastResendAt: now.Format(time.RFC3339)}
	result := getLastResendAt(props)
	s.Equal(now.UTC(), result.UTC())
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_Float64Unix() {
	now := time.Now().Truncate(time.Second)
	props := data.JSONMap{propKeyLastResendAt: float64(now.Unix())}
	result := getLastResendAt(props)
	s.Equal(now.Unix(), result.Unix())
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_Int64Unix() {
	now := time.Now().Truncate(time.Second)
	props := data.JSONMap{propKeyLastResendAt: now.Unix()}
	result := getLastResendAt(props)
	s.Equal(now.Unix(), result.Unix())
}

func (s *ResendHelpersTestSuite) TestGetLastResendAt_UnknownType() {
	props := data.JSONMap{propKeyLastResendAt: true}
	s.True(getLastResendAt(props).IsZero())
}

func (s *ResendHelpersTestSuite) TestUpdateResendTracking_NilProps() {
	result := updateResendTracking(nil, 1)
	s.NotNil(result)
	s.Equal(1, result[propKeyResendCount])
	s.NotEmpty(result[propKeyLastResendAt])
}

func (s *ResendHelpersTestSuite) TestUpdateResendTracking_ExistingProps() {
	props := data.JSONMap{"existing_key": "existing_value"}
	result := updateResendTracking(props, 2)
	s.Equal(2, result[propKeyResendCount])
	s.Equal("existing_value", result["existing_key"])
}

func (s *ResendHelpersTestSuite) TestUpdateResendTracking_TimestampIsRFC3339() {
	result := updateResendTracking(nil, 1)
	ts, ok := result[propKeyLastResendAt].(string)
	s.True(ok)
	_, err := time.Parse(time.RFC3339, ts)
	s.NoError(err)
}

func (s *ResendHelpersTestSuite) TestResendWaitDurations() {
	s.Len(resendWaitDurations, 3)
	s.Equal(30*time.Second, resendWaitDurations[0])
	s.Equal(60*time.Second, resendWaitDurations[1])
	s.Equal(120*time.Second, resendWaitDurations[2])
}

func (s *ResendHelpersTestSuite) TestMaxResendAttempts() {
	s.Equal(3, maxResendAttempts)
}

func TestResendHelpers(t *testing.T) {
	suite.Run(t, new(ResendHelpersTestSuite))
}

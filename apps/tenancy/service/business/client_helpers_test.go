// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ClientHelpersTestSuite struct {
	suite.Suite
}

// --- toJSONMapSlice ---

func (s *ClientHelpersTestSuite) TestToJSONMapSlice_Values() {
	result := toJSONMapSlice("types", []string{"a", "b"})
	s.NotNil(result)
	types, ok := result["types"].([]any)
	s.True(ok)
	s.Len(types, 2)
	s.Equal("a", types[0])
	s.Equal("b", types[1])
}

func (s *ClientHelpersTestSuite) TestToJSONMapSlice_Empty() {
	s.Nil(toJSONMapSlice("types", nil))
	s.Nil(toJSONMapSlice("types", []string{}))
}

func TestClientHelpers(t *testing.T) {
	suite.Run(t, new(ClientHelpersTestSuite))
}

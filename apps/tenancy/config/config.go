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

package config

import "github.com/pitabwire/frame/config"

type TenancyConfig struct {
	config.ConfigurationDefault

	AuthContractExpectedClients         int64 `envDefault:"-1" env:"AUTH_CONTRACT_EXPECTED_CLIENTS"`
	AuthContractExpectedServiceAccounts int64 `envDefault:"-1" env:"AUTH_CONTRACT_EXPECTED_SERVICE_ACCOUNTS"`
	AuthContractExpectedRecipients      int64 `envDefault:"-1" env:"AUTH_CONTRACT_EXPECTED_RECIPIENTS"`
	AuthContractExpectedGrants          int64 `envDefault:"-1" env:"AUTH_CONTRACT_EXPECTED_GRANTS"`

	NotificationServiceURI                   string `envDefault:"127.0.0.1:7020" env:"NOTIFICATION_SERVICE_URI"`
	NotificationServiceWorkloadAPITargetPath string `envDefault:"/ns/notifications/sa/service-notification" env:"NOTIFICATION_SERVICE_WORKLOAD_API_TARGET_PATH"`

	ProfileServiceURI                   string `envDefault:"127.0.0.1:7010" env:"PROFILE_SERVICE_URI"`
	ProfileServiceWorkloadAPITargetPath string `envDefault:"/ns/profile/sa/service-profile" env:"PROFILE_SERVICE_WORKLOAD_API_TARGET_PATH"`
}

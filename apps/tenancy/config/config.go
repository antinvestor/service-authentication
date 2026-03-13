package config

import "github.com/pitabwire/frame/config"

type PartitionConfig struct {
	config.ConfigurationDefault

	NotificationServiceURI                   string `envDefault:"127.0.0.1:7020" env:"NOTIFICATION_SERVICE_URI"`
	NotificationServiceWorkloadAPITargetPath string `envDefault:"/ns/notifications/sa/service-notification" env:"NOTIFICATION_SERVICE_WORKLOAD_API_TARGET_PATH"`
}

package config

import "github.com/pitabwire/frame/config"

type PartitionConfig struct {
	config.ConfigurationDefault

	NotificationServiceURI       string `envDefault:"127.0.0.1:7020"             env:"NOTIFICATION_SERVICE_URI"`
	SynchronizePrimaryPartitions bool   `envDefault:"False"                      env:"SYNCHRONISE_PRIMARY_PARTITIONS"`
}

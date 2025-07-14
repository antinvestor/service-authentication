package config

import "github.com/pitabwire/frame"

type PartitionConfig struct {
	frame.ConfigurationDefault

	NotificationServiceURI       string `envDefault:"127.0.0.1:7020"             env:"NOTIFICATION_SERVICE_URI"`
	QueuePartitionSyncURL        string `envDefault:"mem://partition_sync_hydra" env:"QUEUE_PARTITION_SYNC"`
	PartitionSyncName            string `envDefault:"partition_sync_hydra"       env:"QUEUE_PARTITION_SYNC_NAME"`
	SynchronizePrimaryPartitions bool   `envDefault:"False"                      env:"SYNCHRONIZE_PRIMARY_PARTITIONS"`
}

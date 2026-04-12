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

package opl

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ConfigMapUpdater writes OPL content to a Kubernetes ConfigMap.
// Stakater Reloader on the Keto deployment watches the ConfigMap and
// restarts pods when the content changes.
type ConfigMapUpdater struct {
	clientset          kubernetes.Interface
	configMapName      string
	configMapNamespace string
	configMapKey       string
}

// NewConfigMapUpdater creates an updater using in-cluster credentials.
// Returns an error if the Kubernetes API is unreachable (e.g. running
// outside a cluster without KUBECONFIG).
func NewConfigMapUpdater(configMapName, configMapNamespace, configMapKey string) (*ConfigMapUpdater, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}

	return &ConfigMapUpdater{
		clientset:          clientset,
		configMapName:      configMapName,
		configMapNamespace: configMapNamespace,
		configMapKey:       configMapKey,
	}, nil
}

// NewConfigMapUpdaterWithClient creates an updater with an injected clientset.
// Use this in tests with fake.NewSimpleClientset().
func NewConfigMapUpdaterWithClient(clientset kubernetes.Interface, configMapName, configMapNamespace, configMapKey string) *ConfigMapUpdater {
	return &ConfigMapUpdater{
		clientset:          clientset,
		configMapName:      configMapName,
		configMapNamespace: configMapNamespace,
		configMapKey:       configMapKey,
	}
}

// Update writes the OPL content to the ConfigMap. It creates the ConfigMap
// if it doesn't exist, and skips the update if the content is unchanged.
// Returns true if the ConfigMap was actually modified.
func (u *ConfigMapUpdater) Update(ctx context.Context, oplContent string) (bool, error) {
	cmClient := u.clientset.CoreV1().ConfigMaps(u.configMapNamespace)

	existing, err := cmClient.Get(ctx, u.configMapName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      u.configMapName,
				Namespace: u.configMapNamespace,
			},
			Data: map[string]string{
				u.configMapKey: oplContent,
			},
		}
		_, createErr := cmClient.Create(ctx, cm, metav1.CreateOptions{})
		if createErr != nil {
			return false, fmt.Errorf("create configmap %s/%s: %w", u.configMapNamespace, u.configMapName, createErr)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("get configmap %s/%s: %w", u.configMapNamespace, u.configMapName, err)
	}

	// Skip update if content is unchanged — avoids unnecessary Keto restarts.
	if existing.Data[u.configMapKey] == oplContent {
		return false, nil
	}

	if existing.Data == nil {
		existing.Data = make(map[string]string)
	}
	existing.Data[u.configMapKey] = oplContent

	_, err = cmClient.Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("update configmap %s/%s: %w", u.configMapNamespace, u.configMapName, err)
	}
	return true, nil
}

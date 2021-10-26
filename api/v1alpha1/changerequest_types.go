/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ChangeRequestType defines types of ChangeRequest
type ChangeRequestType string

const (
	// Type defines type name of GitHub repository
	ChangeRequestGitHub = "github"

	// More types will be added here
)

// ChangeRequestSpec defines the desired state of ChangeRequest
type ChangeRequestSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// A string representation of the ChangeRequesr type. Valid values include:
	// `GitHub`,`github`
	// +kubebuilder:validation:Enum={GitHub,github}
	Type ChangeRequestType `json:"type"`

	// Pathname is the remote URL which is the source of truth.
	// The CR controller will decipher the details from the path.
	// eg. https://github.com/turbonomic/kubeturbo/blob/master/deploy/kubeturbo_yamls/step5_turbo_kubeturboDeploy.yaml
	// TODO: Figure out if this is sufficient to pinpoint a given configuration
	// If not, then a separate field specifying the repo specific configuration file path can be added.
	Pathname string `json:"pathname"`

	// Payload is the yaml structured resource data that needs to be updated
	// at the path in the source of truth repo.
	// The reconciler will expect that the git repo stores yamls and will
	// diff the spec of the retrieved yaml with the source of truth path to determine
	// if an update is needed.
	Payload string `json:"payload"`

	// For a `github` as the source of truth, this
	// can be used to reference a Secret which contains the credentials for
	// authentication, i.e. `user` and `accessToken`.
	// +optional
	SecretRef *corev1.ObjectReference `json:"secretRef,omitempty"`
}

// ChangeRequestStatus defines the observed state of ChangeRequest
type ChangeRequestStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ChangeRequest is the Schema for the changerequests API
type ChangeRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ChangeRequestSpec   `json:"spec,omitempty"`
	Status ChangeRequestStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ChangeRequestList contains a list of ChangeRequest
type ChangeRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ChangeRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ChangeRequest{}, &ChangeRequestList{})
}

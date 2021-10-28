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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ChangeRequestType defines types of ChangeRequest
type ChangeRequestType string

const (
	// GitHub repository
	ChangeRequestGitHub ChangeRequestType = "github"

	// More types will be added here
)

type ChangeRequestState string

const (
	StateInitial   ChangeRequestState = ""
	StateUpdating  ChangeRequestState = "Updating"
	StateCompleted ChangeRequestState = "Complete"
	StateFailed    ChangeRequestState = "Failed"
)

type ChangeRequestPushMode string

const (
	// Reconciler with try to raise a PR with this mode
	PushModeRequestApproval ChangeRequestPushMode = "requestapproval"

	// Reconciler with try to update the file in place in this mode
	PushModeDirect ChangeRequestPushMode = "direct"
)

type PatchItem struct {
	Op   string `json:"op,omitempty"`
	Path string `json:"path"`
	// We needed an Interface{} typed here, but controller-gen doesn't support that.
	// We use a solution listed at https://github.com/kubernetes-sigs/controller-tools/pull/126#issuecomment-707233008.
	// For more reference:
	// https://github.com/kubernetes-sigs/controller-tools/pull/126#issuecomment-630764976
	// https://github.com/kubernetes-sigs/controller-tools/issues/294#issuecomment-518379253
	Value apiextensionsv1.JSON `json:"value,omitempty"`
}

// ChangeRequestSpec defines the desired state of ChangeRequest
type ChangeRequestSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// A string representation of the ChangeRequest type. Valid values include:
	// `GitHub`,`github`
	// +kubebuilder:validation:Enum={GitHub,github}
	Type ChangeRequestType `json:"type"`

	// A string representation of the ChangeRequesr type. Valid values include:
	// `requestapproval`,`github`
	// +kubebuilder:validation:Enum={requestapproval,direct}
	// +optional
	Mode ChangeRequestPushMode `json:"mode"`

	// Source is the remote URL which is the source of truth.
	// eg. https://github.com/turbonomic/kubeturbo
	Source string `json:"source"`

	// FilePath is the path of file to be updated in the repo.
	// eg. deploy/kubeturbo_yamls/step5_turbo_kubeturboDeploy.yaml
	FilePath string `json:"filePath"`

	// Branch optionally specifies the branch to which the file will be updated.
	// If omitted the update will be pushed to the main branch.
	// +optional
	Branch string `json:"branch"`

	// PatchItems are a list of jsonpatch style patches that will be applied
	// to the spec from the file at the source of truth, eg. a git repo.
	// After the patch is applied the the file will be pushed back to the repo
	// using the policy specified in "Mode".
	PatchItems []PatchItem `json:"patchItems"`

	// For a `github` as the source of truth, this
	// can be used to reference a Secret which contains the credentials for
	// authentication, i.e. `user` and `accessToken`.
	// +optional
	SecretRef *corev1.ObjectReference `json:"secretRef,omitempty"`
}

// ChangeRequestStatus defines the observed state of ChangeRequest
type ChangeRequestStatus struct {
	State ChangeRequestState `json:"state"`
	// TODO: A field which can identify the created or to be created PR uniquely
	// can help in possible multiple reconciles for the same ChangeRequest
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

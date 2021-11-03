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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	//"github.com/google/go-github/github"
	"github.com/google/go-github/v39/github"
	"golang.org/x/oauth2"

	"github.com/golang/glog"

	"github.com/ghodss/yaml"

	jsonpatch "github.com/evanphx/json-patch"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	crv1alpha1 "github.com/irfanurrehman/change-reconciler/api/v1alpha1"
)

// ChangeRequestReconciler reconciles a ChangeRequest object
type ChangeRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=turbonomic.io,resources=changerequests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=turbonomic.io,resources=changerequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=turbonomic.io,resources=changerequests/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ChangeRequest object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ChangeRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	cr := &crv1alpha1.ChangeRequest{}
	err := r.Get(context.TODO(), req.NamespacedName, cr)
	if err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		// Other errors reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if cr.GetDeletionTimestamp() != nil || cr.Status.State == crv1alpha1.StateCompleted {
		// Nothing to do as of now.
		// We ignore reconciles of CRs whose status is completed.
		return reconcile.Result{}, nil
	}

	// Check the status to see if this is a new CR or an existing one
	// If the status is empty (""), then this should be a new one, just created
	// so we go ahead with the PR creation (or push commit) of the update
	// TODO: find a strategy in the PR naming or the hash of some kind
	// which can be matched across reconciles to ensure multiple reconciles
	// don't create multiple PRs for the same change.

	if cr.Status.State == crv1alpha1.StateUpdating {
		// We already must have a reconcile that is trying to create a PR
		// which would either succeed or fail the PR update
		// TODO: figure out a locking strategy if need be
		return reconcile.Result{}, nil
	}

	if cr.Status.State == crv1alpha1.StateInitial {
		result, err := r.updateStatus(cr, crv1alpha1.StateUpdating)
		if err != nil {
			// Requeue to try again.
			return result, err
		}
	}

	// If we reached here this should ideally be the fist reconcile called after
	// the create op.
	// Parse the URL and ensure there are no errors.
	// TODO: Add basic parsing and validation to API validation logic.
	// Validations errors should ideally be be caught in API validation logic
	// we don't have that yet.
	source := cr.Spec.Source
	url, err := url.Parse(source)
	if err != nil {
		// This is a non recoverable error (which should be caught in
		// API validation ideally but we don't have that yet)
		glog.Errorf("Source url: %s in the CR: %s is not valid: %v.", source, cr.Name, err)
		return r.updateStatus(cr, crv1alpha1.StateFailed)
	}

	// host := u.Host
	// TODO: should we validate the host also someway
	// eg host == github.com or name containes git, eg. for gitlab?
	pathParts := strings.Split(url.Path, "/")
	// We get three parts for a git repo like below:
	// For github.com/irfanurrehman/kubeturbo
	// Path == /irfanurrehman/kubeturbo
	// pathParts[0] = ""
	// pathParts[1] = "irfanurrehman"
	// pathParts[2] = "kubeturbo"
	if len(pathParts) != 3 {
		glog.Errorf("Source url: %s in the CR: %s should have 2 sections in path.", source, cr.Name)
		return r.updateStatus(cr, crv1alpha1.StateFailed)
	}

	handler := &GitHandler{
		ctx:        context.Background(),
		client:     getClient(ctx),
		user:       pathParts[1],
		repo:       pathParts[2],
		baseBranch: cr.Spec.Branch,
		filePath:   cr.Spec.FilePath,
	}

	newBranch := handler.baseBranch + strconv.FormatInt(time.Now().UnixNano(), 32)
	_, err = handler.createPR(newBranch, cr.Spec.PatchItems)
	if err != nil {
		glog.Errorf("Error creating new PR: %s/%s: %v", source, handler.filePath, err)
		return r.updateStatus(cr, crv1alpha1.StateFailed)
	}

	glog.Errorf("New PR created updating %s/%s from new branch %s.", source, handler.filePath, newBranch)
	return r.updateStatus(cr, crv1alpha1.StateCompleted)
}

func (r *ChangeRequestReconciler) updateStatus(cr *crv1alpha1.ChangeRequest, state crv1alpha1.ChangeRequestState) (ctrl.Result, error) {
	cr.Status.State = state
	err := r.Status().Update(context.TODO(), cr)
	if err != nil {
		glog.Errorf("Error updating CR: %s to state %s: %v", cr.Name, state, err)
		// Requeue with a small delay on update failures
		return reconcile.Result{
			RequeueAfter: time.Second * 10,
		}, err
	}
	return reconcile.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ChangeRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&crv1alpha1.ChangeRequest{}).
		Complete(r)
}

func getClient(ctx context.Context) *github.Client {
	// TODO: get the Auth info from the secret
	ts := oauth2.StaticTokenSource(
		// This is a dummy revoked token
		&oauth2.Token{AccessToken: "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"},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

type GitHandler struct {
	ctx        context.Context
	client     *github.Client
	user       string
	repo       string
	baseBranch string
	filePath   string
}

func (g *GitHandler) createNewBranch(newBranch string) (ref *github.Reference, err error) {
	var baseRef *github.Reference
	if baseRef, _, err = g.client.Git.GetRef(g.ctx, g.user, g.repo, "refs/heads/"+g.baseBranch); err != nil {
		return nil, err
	}
	newRef := &github.Reference{Ref: github.String("refs/heads/" + newBranch), Object: &github.GitObject{SHA: baseRef.Object.SHA}}
	ref, _, err = g.client.Git.CreateRef(g.ctx, g.user, g.repo, newRef)
	return ref, err
}

func (g *GitHandler) getRemoteFileContent() (string, error) {
	opts := github.RepositoryContentGetOptions{
		Ref: g.baseBranch,
	}
	fileContent, _, _, err := g.client.Repositories.GetContents(g.ctx, g.user, g.repo, g.filePath, &opts)
	if err != nil {
		return "", err
	}
	return fileContent.GetContent()
}

func (g *GitHandler) getTree(ref *github.Reference, fileContent []byte) (tree *github.Tree, err error) {
	// Create a tree with what to commit.
	entries := []*github.TreeEntry{
		{
			Path:    github.String(g.filePath),
			Type:    github.String("blob"),
			Content: github.String(string(fileContent)),
			Mode:    github.String("100644"),
		},
	}

	tree, _, err = g.client.Git.CreateTree(g.ctx, g.user, g.repo, *ref.Object.SHA, entries)
	return tree, err
}

func (g *GitHandler) pushCommit(ref *github.Reference, tree *github.Tree) error {
	// Get the parent commit to attach the commit to.
	parent, _, err := g.client.Repositories.GetCommit(g.ctx, g.user, g.repo, *ref.Object.SHA, nil)
	if err != nil {
		return err
	}
	// This is not always populated, but is needed.
	parent.Commit.SHA = parent.SHA

	// Create the commit using the tree.
	// TODO: stuff like author, email, etc. should come from reconciler controller config
	date := time.Now()
	authorName := "irfanurrehman"
	authorEmail := "irfan.rehman@turbonomic.com"
	commitMsg := "Action executed from turbo" // TODO: add more details
	author := &github.CommitAuthor{Date: &date, Name: &authorName, Email: &authorEmail}
	commit := &github.Commit{Author: author, Message: &commitMsg, Tree: tree, Parents: []*github.Commit{parent.Commit}}
	newCommit, _, err := g.client.Git.CreateCommit(g.ctx, g.user, g.repo, commit)
	if err != nil {
		return err
	}

	ref.Object.SHA = newCommit.SHA
	_, _, err = g.client.Git.UpdateRef(g.ctx, g.user, g.repo, ref, false)
	return err
}

func (g *GitHandler) newPR(newBranch string) (*github.PullRequest, error) {
	prTitle := "Update based on TODO"
	prDescription := "Empty for now TODO"
	baseBranch := g.baseBranch

	newPR := &github.NewPullRequest{
		Title:               &prTitle,
		Head:                &newBranch, // Head may need user:ref_name
		Base:                &baseBranch,
		Body:                &prDescription,
		MaintainerCanModify: github.Bool(true),
	}

	pr, _, err := g.client.PullRequests.Create(g.ctx, g.user, g.repo, newPR)
	if err != nil {
		return nil, err
	}
	return pr, nil
}

func (g *GitHandler) createPR(newBranch string, patches []crv1alpha1.PatchItem) (*github.PullRequest, error) {
	yamlContent, err := g.getRemoteFileContent()
	if err != nil {
		// TODO: At some point we would need to have a retry strategy for
		// transient errors.
		glog.Errorf("error retrieving remote file %s", g.filePath)
		return nil, fmt.Errorf("error retrieving remote file %s", g.filePath)
	}

	patchedYamlContent, err := ApplyPatch([]byte(yamlContent), patches)
	if err != nil {
		glog.Errorf("error applying patches to file %s: %v", g.filePath, patches)
		return nil, fmt.Errorf("error applying patches to file %s: %v", g.filePath, patches)
	}

	ref, err := g.createNewBranch(newBranch)
	if err != nil {
		glog.Errorf("error creating new branch %s, %v", newBranch, err)
		return nil, fmt.Errorf("error creating new branch %s, %v", newBranch, err)
	}

	tree, err := g.getTree(ref, patchedYamlContent)
	if err != nil {
		glog.Errorf("error getting new branch ref: %s, %v", newBranch, err)
		return nil, fmt.Errorf("error getting new branch ref: %s, %v", newBranch, err)
	}

	err = g.pushCommit(ref, tree)
	if err != nil {
		glog.Errorf("error committing new content to branch %s, %v", newBranch, err)
		return nil, fmt.Errorf("error committing new content to branch %s, %v", newBranch, err)
	}

	return g.newPR(newBranch)
}

// TODO: Enhance the support to identify json or yaml content on the fly
func ApplyPatch(yamlBytes []byte, patches []crv1alpha1.PatchItem) ([]byte, error) {
	// TODO: defaulting of "op" field to "replace" in API defaulting, when we have defaulting
	for i, patchItem := range patches {
		if patchItem.Op == "" {
			patches[i].Op = "replace"
		}
	}
	jsonPatchBytes, err := json.Marshal(patches)
	if err != nil {
		return nil, err
	}

	patch, err := jsonpatch.DecodePatch(jsonPatchBytes)
	if err != nil {
		return nil, err
	}

	jsonBytes, err := yaml.YAMLToJSON(yamlBytes)
	if err != nil {
		return nil, err
	}

	patchedJsonBytes, err := patch.Apply(jsonBytes)
	if err != nil {
		return nil, err
	}

	return yaml.JSONToYAML(patchedJsonBytes)
}

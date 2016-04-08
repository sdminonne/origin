package podspecselfsubjectreview

import (
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	kapierrors "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/runtime"

	"github.com/openshift/origin/pkg/authorization/authorizer"
	securityapi "github.com/openshift/origin/pkg/security/api"
	securityvalidation "github.com/openshift/origin/pkg/security/api/validation"
)

// REST implements the RESTStorage interface in terms of an Registry.
type REST struct {
	authorizer authorizer.Authorizer
}

// NewREST creates a new REST for policies.
func NewREST(authorizer authorizer.Authorizer) *REST {
	return &REST{authorizer}
}

// New creates a new PodSpecSelfSubjectReview object
func (r *REST) New() runtime.Object {
	return &securityapi.PodSpecSelfSubjectReview{}
}

// Create registers a given new PodSpecSelfSubjectReview instance to r.registry.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	podSpecSelfSubjectReview, ok := obj.(*securityapi.PodSpecSelfSubjectReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a podspecselfsubjectreview: %#v", obj))
	}
	if errs := securityvalidation.ValidatePodSpecSelfSubjectReview(podSpecSelfSubjectReview); len(errs) > 0 {
		return nil, kapierrors.NewInvalid(securityapi.Kind(podSpecSelfSubjectReview.Kind), "", errs)
	}
	newPodSpecSelfSubjectReview := &securityapi.PodSpecSelfSubjectReview{}
	newPodSpecSelfSubjectReview.Spec = podSpecSelfSubjectReview.Spec
	// TODO: add logic to fill response
	return newPodSpecSelfSubjectReview, nil
}

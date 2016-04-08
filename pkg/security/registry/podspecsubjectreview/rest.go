package podspecsubjectreview

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

// New creates a new PodSpecSubjectReview object
func (r *REST) New() runtime.Object {
	return &securityapi.PodSpecSubjectReview{}
}

// Create registers a given new PodSpecSubjectReview instance to r.registry.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	podSpecSubjectReview, ok := obj.(*securityapi.PodSpecSubjectReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a podspecselfsubjectreview: %#v", obj))
	}
	if errs := securityvalidation.ValidatePodSpecSubjectReview(podSpecSubjectReview); len(errs) > 0 {
		return nil, kapierrors.NewInvalid(securityapi.Kind(podSpecSubjectReview.Kind), "", errs)
	}
	newPodSpecSubjectReview := &securityapi.PodSpecSubjectReview{}
	newPodSpecSubjectReview.Spec = podSpecSubjectReview.Spec
	// TODO: add logic to fill response
	return newPodSpecSubjectReview, nil
}

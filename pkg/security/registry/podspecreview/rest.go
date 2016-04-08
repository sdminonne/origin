package podspecreview

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

// NewREST creates a new REST for policies..
func NewREST(authorizer authorizer.Authorizer) *REST {
	return &REST{authorizer}
}

// New creates a new PodSpecReview object
func (r *REST) New() runtime.Object {
	return &securityapi.PodSpecReview{}
}

// Create registers a given new PodSpecReview instance to r.registry.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	podSpecReview, ok := obj.(*securityapi.PodSpecReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a podspecreview: %#v", obj))
	}
	if errs := securityvalidation.ValidatePodSpecReview(podSpecReview); len(errs) > 0 {
		return nil, kapierrors.NewInvalid(securityapi.Kind(podSpecReview.Kind), "", errs)
	}
	newPodSpecReview := &securityapi.PodSpecReview{}
	newPodSpecReview.Spec = podSpecReview.Spec

	// TODO: add logic to fill response
	return newPodSpecReview, nil
}

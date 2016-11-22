package podsecuritypolicyselfsubjectreview

import (
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	kapierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/runtime"
	kscc "k8s.io/kubernetes/pkg/securitycontextconstraints"
	"k8s.io/kubernetes/pkg/serviceaccount"

	"github.com/golang/glog"
	securityapi "github.com/openshift/origin/pkg/security/api"
	securityvalidation "github.com/openshift/origin/pkg/security/api/validation"
	podsecuritypolicysubjectreview "github.com/openshift/origin/pkg/security/registry/podsecuritypolicysubjectreview"
	oscc "github.com/openshift/origin/pkg/security/scc"
)

// REST implements the RESTStorage interface in terms of an Registry.
type REST struct {
	sccMatcher oscc.SCCMatcher
	client     clientset.Interface
}

// NewREST creates a new REST for policies..
func NewREST(m oscc.SCCMatcher, c clientset.Interface) *REST {
	return &REST{sccMatcher: m, client: c}
}

// New creates a new PodSecurityPolicySelfSubjectReview object
func (r *REST) New() runtime.Object {
	return &securityapi.PodSecurityPolicySelfSubjectReview{}
}

// Create registers a given new pspssr instance to r.registry.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	pspssr, ok := obj.(*securityapi.PodSecurityPolicySelfSubjectReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a PodSecurityPolicySelfSubjectReview: %#v", obj))
	}
	if errs := securityvalidation.ValidatePodSecurityPolicySelfSubjectReview(pspssr); len(errs) > 0 {
		return nil, kapierrors.NewInvalid(kapi.Kind("PodSecurityPolicySelfSubjectReview"), "", errs)
	}
	userInfo, ok := kapi.UserFrom(ctx)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("no user data associated with context"))
	}
	ns, ok := kapi.NamespaceFrom(ctx)
	if !ok {
		return nil, kapierrors.NewBadRequest("namespace parameter required.")
	}
	matchedConstraints, err := r.sccMatcher.FindApplicableSCCs(userInfo)
	if err != nil {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("unable to find SecurityContextConstraints: %v", err))
	}
	saName := pspssr.Spec.Template.Spec.ServiceAccountName
	if len(saName) > 0 {
		saUserInfo := serviceaccount.UserInfo(ns, saName, "")
		saConstraints, err := r.sccMatcher.FindApplicableSCCs(saUserInfo)
		if err != nil {
			return nil, kapierrors.NewBadRequest(fmt.Sprintf("unable to find SecurityContextConstraints: %v", err))
		}
		matchedConstraints = append(matchedConstraints, saConstraints...)
	}
	assigner := newSCCAssigner(&pspssr.Status, pspssr.Spec.Template.Spec)
	if err = oscc.AssignConstraints(r.sccMatcher, matchedConstraints, ns, r.client, assigner); err != nil {
		glog.V(4).Infof("PodSecurityPolicySelfSubjectReview error: %v", err)
	}
	return pspssr, nil
}

type sCCAssigner struct {
	status *securityapi.PodSecurityPolicySubjectReviewStatus
	spec   kapi.PodSpec
}

var _ oscc.SCCAssigner = &sCCAssigner{}

func newSCCAssigner(status *securityapi.PodSecurityPolicySubjectReviewStatus, spec kapi.PodSpec) oscc.SCCAssigner {
	return &sCCAssigner{
		status: status,
		spec:   spec,
	}
}

func (a *sCCAssigner) Assign(provider kscc.SecurityContextConstraintsProvider, constraint *kapi.SecurityContextConstraints) error {
	filled, err := podsecuritypolicysubjectreview.FillPodSecurityPolicySubjectReviewStatus(a.status, provider, a.spec, constraint)
	if !filled || err != nil {
		if err == nil {
			err = fmt.Errorf("unknown reason")
		}
		return fmt.Errorf("unable to fill PodSecurityPolicySubjectReviewStatus from constraint: %v", err)
	}
	return nil
}

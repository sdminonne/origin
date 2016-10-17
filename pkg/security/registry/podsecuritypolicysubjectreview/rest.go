package podsecuritypolicysubjectreview

import (
	"fmt"
	"sort"

	"github.com/golang/glog"

	kapi "k8s.io/kubernetes/pkg/api"
	kapierrors "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/auth/user"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/runtime"
	kscc "k8s.io/kubernetes/pkg/securitycontextconstraints"
	"k8s.io/kubernetes/pkg/serviceaccount"
	"k8s.io/kubernetes/pkg/util/validation/field"

	authorizationapi "github.com/openshift/origin/pkg/authorization/api"
	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
	securityapi "github.com/openshift/origin/pkg/security/api"
	securityvalidation "github.com/openshift/origin/pkg/security/api/validation"
	oscc "github.com/openshift/origin/pkg/security/scc"
	userapi "github.com/openshift/origin/pkg/user/api"
	uservalidation "github.com/openshift/origin/pkg/user/api/validation"
	usercache "github.com/openshift/origin/pkg/user/cache"
)

// REST implements the RESTStorage interface in terms of an Registry.
type REST struct {
	sccMatcher oscc.SCCMatcher
	groupCache *usercache.GroupCache
	client     clientset.Interface
}

// NewREST creates a new REST for policies..
func NewREST(m oscc.SCCMatcher, g *usercache.GroupCache, c clientset.Interface) *REST {
	return &REST{sccMatcher: m, groupCache: g, client: c}
}

// New creates a new PodSecurityPolicySubjectReview object
func (r *REST) New() runtime.Object {
	return &securityapi.PodSecurityPolicySubjectReview{}
}

// Create registers a given new PodSecurityPolicySubjectReview instance to r.registry.
func (r *REST) Create(ctx kapi.Context, obj runtime.Object) (runtime.Object, error) {
	pspsr, ok := obj.(*securityapi.PodSecurityPolicySubjectReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a PodSecurityPolicySubjectReview: %#v", obj))
	}
	ns, ok := kapi.NamespaceFrom(ctx)
	if !ok {
		return nil, kapierrors.NewBadRequest("namespace parameter required.")
	}
	if errs := securityvalidation.ValidatePodSecurityPolicySubjectReview(pspsr); len(errs) > 0 {
		return nil, kapierrors.NewInvalid(kapi.Kind("PodSecurityPolicySubjectReview"), "", errs)
	}
	//username := serviceaccount.MakeUsername(ns, pspsr.Spec.User)
	subjects := authorizationapi.BuildSubjects([]string{pspsr.Spec.User}, pspsr.Spec.Groups,
		// validates whether the usernames are regular users or system users
		uservalidation.ValidateUserName,
		// validates group names are regular groups or system groups
		uservalidation.ValidateGroupName)

	groupsSpecified := pspsr.Spec.Groups != nil
	groups := pspsr.Spec.Groups
	username := pspsr.Spec.User
	for _, subject := range subjects {
		switch subject.GetObjectKind().GroupVersionKind().GroupKind() {
		case userapi.Kind(authorizationapi.GroupKind):
			groups = append(groups, subject.Name)

		case userapi.Kind(authorizationapi.SystemGroupKind):
			groups = append(groups, subject.Name)

		case userapi.Kind(authorizationapi.UserKind):
			username = subject.Name
			if !groupsSpecified {
				if actualGroups, err := r.groupCache.GroupsFor(subject.Name); err == nil {
					for _, group := range actualGroups {
						groups = append(groups, group.Name)
					}
				}
				groups = append(groups, bootstrappolicy.AuthenticatedGroup, bootstrappolicy.AuthenticatedOAuthGroup)
			}

		case userapi.Kind(authorizationapi.SystemUserKind):
			username = subject.Name
			if !groupsSpecified {
				if subject.Name == bootstrappolicy.UnauthenticatedUsername {
					groups = append(groups, bootstrappolicy.UnauthenticatedGroup)
				} else {
					groups = append(groups, bootstrappolicy.AuthenticatedGroup)
				}
			}

		case kapi.Kind(authorizationapi.ServiceAccountKind):
			username = serviceaccount.MakeUsername(subject.Namespace, subject.Name)
			if !groupsSpecified {
				groups = append(serviceaccount.MakeGroupNames(subject.Namespace, subject.Name), bootstrappolicy.AuthenticatedGroup)
			}

		default:
			return nil, kapierrors.NewBadRequest(fmt.Sprintf("unknown subject type: %v", subject))
		}
		groups = append(groups, bootstrappolicy.AuthenticatedGroup, bootstrappolicy.AuthenticatedOAuthGroup)
	}

	userInfo := &user.DefaultInfo{Name: username, Groups: groups}
	matchedConstraints, err := r.sccMatcher.FindApplicableSCCs(userInfo)
	if err != nil {

		return nil, kapierrors.NewBadRequest(fmt.Sprintf("unable to find SecurityContextConstraints: %v", err))
	}
	saName := pspsr.Spec.Template.Spec.ServiceAccountName
	if len(saName) > 0 {
		saUserInfo := serviceaccount.UserInfo(ns, saName, "")
		saConstraints, err := r.sccMatcher.FindApplicableSCCs(saUserInfo)
		if err != nil {
			return nil, kapierrors.NewBadRequest(fmt.Sprintf("unable to find SecurityContextConstraints: %v", err))
		}
		matchedConstraints = append(matchedConstraints, saConstraints...)
	}
	oscc.DeduplicateSecurityContextConstraints(matchedConstraints)
	sort.Sort(oscc.ByPriority(matchedConstraints))
	var namespace *kapi.Namespace
	for _, constraint := range matchedConstraints {
		var (
			provider kscc.SecurityContextConstraintsProvider
			err      error
		)
		if provider, namespace, err = oscc.CreateProviderFromConstraint(ns, namespace, constraint, r.client); err != nil {
			glog.Errorf("Unable to create provider for constraint: %v", err)
			continue
		}
		filled, err := FillPodSecurityPolicySubjectReviewStatus(&pspsr.Status, provider, pspsr.Spec.Template.Spec, constraint)
		if err != nil {
			glog.Errorf("unable to fill PodSecurityPolicySubjectReviewStatus from constraint %v", err)
			continue
		}
		if filled {
			return pspsr, nil
		}
	}
	return pspsr, nil
}

// FillPodSecurityPolicySubjectReviewStatus fills PodSecurityPolicySubjectReviewStatus assigning SecurityContectConstraint to the PodSpec
func FillPodSecurityPolicySubjectReviewStatus(s *securityapi.PodSecurityPolicySubjectReviewStatus, provider kscc.SecurityContextConstraintsProvider, spec kapi.PodSpec, constraint *kapi.SecurityContextConstraints) (bool, error) {
	pod := &kapi.Pod{
		Spec: spec,
	}
	if errs := oscc.AssignSecurityContext(provider, pod, field.NewPath(fmt.Sprintf("provider %s: ", provider.GetSCCName()))); len(errs) > 0 {
		glog.Errorf("unable to assign SecurityContextConstraints provider: %v", errs)
		s.Reason = "CantAssignSecurityContextConstraintProvider"
		return false, fmt.Errorf("unable to assign SecurityContextConstraints provider: %v", errs.ToAggregate())
	}
	ref, err := kapi.GetReference(constraint)
	if err != nil {
		s.Reason = "CantObtainReference"
		return false, fmt.Errorf("unable to get SecurityContextConstraints reference: %v", err)
	}
	s.AllowedBy = ref

	if len(spec.ServiceAccountName) > 0 {
		s.Template.Spec = pod.Spec
	}
	return true, nil
}

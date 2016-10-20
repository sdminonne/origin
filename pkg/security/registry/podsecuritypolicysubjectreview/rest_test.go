package podsecuritypolicysubjectreview

import (
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/auth/user"
	"k8s.io/kubernetes/pkg/client/cache"
	clientsetfake "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	"k8s.io/kubernetes/pkg/util/sets"
	"k8s.io/kubernetes/pkg/watch"

	"github.com/openshift/origin/pkg/authorization/authorizer"
	oscache "github.com/openshift/origin/pkg/client/cache"
	admissionttesting "github.com/openshift/origin/pkg/security/admission/testing"
	securityapi "github.com/openshift/origin/pkg/security/api"
	oscc "github.com/openshift/origin/pkg/security/scc"
	userapi "github.com/openshift/origin/pkg/user/api"
	usercache "github.com/openshift/origin/pkg/user/cache"
)

type groupCache struct {
}

func (*groupCache) ListGroups(ctx kapi.Context, options *kapi.ListOptions) (*userapi.GroupList, error) {
	return &userapi.GroupList{}, nil
}
func (*groupCache) GetGroup(ctx kapi.Context, name string) (*userapi.Group, error) {
	return nil, nil
}
func (*groupCache) CreateGroup(ctx kapi.Context, group *userapi.Group) (*userapi.Group, error) {
	return nil, nil
}
func (*groupCache) UpdateGroup(ctx kapi.Context, group *userapi.Group) (*userapi.Group, error) {
	return nil, nil
}
func (*groupCache) DeleteGroup(ctx kapi.Context, name string) error {
	return nil
}
func (*groupCache) WatchGroups(ctx kapi.Context, options *kapi.ListOptions) (watch.Interface, error) {
	return watch.NewFake(), nil
}

type testAuthorizer struct {
	allowed bool
	reason  string
	err     string

	actualAttributes authorizer.DefaultAuthorizationAttributes
	actualUserInfo   user.Info
}

func (a *testAuthorizer) Authorize(ctx kapi.Context, passedAttributes authorizer.Action) (allowed bool, reason string, err error) {
	a.actualUserInfo, _ = kapi.UserFrom(ctx)
	return true, "", nil
}
func (a *testAuthorizer) GetAllowedSubjects(ctx kapi.Context, passedAttributes authorizer.Action) (sets.String, sets.String, error) {
	return sets.String{}, sets.String{}, nil
}
func saSCC() *kapi.SecurityContextConstraints {
	return &kapi.SecurityContextConstraints{
		ObjectMeta: kapi.ObjectMeta{
			SelfLink: "/api/version/securitycontextconstraints/scc-sa",
			Name:     "scc-sa",
		},
		RunAsUser: kapi.RunAsUserStrategyOptions{
			Type: kapi.RunAsUserStrategyMustRunAsRange,
		},
		SELinuxContext: kapi.SELinuxContextStrategyOptions{
			Type: kapi.SELinuxStrategyMustRunAs,
		},
		FSGroup: kapi.FSGroupStrategyOptions{
			Type: kapi.FSGroupStrategyMustRunAs,
		},
		SupplementalGroups: kapi.SupplementalGroupsStrategyOptions{
			Type: kapi.SupplementalGroupsStrategyMustRunAs,
		},
		Groups: []string{"system:serviceaccounts"},
	}
}

func TestAllowed(t *testing.T) {
	testcases := map[string]struct {
		sccs []*kapi.SecurityContextConstraints
		// patch function modify nominal PodSecurityPolicySubjectReview request
		patch func(p *securityapi.PodSecurityPolicySubjectReview)
		check func(p *securityapi.PodSecurityPolicySubjectReview) (bool, string)
	}{
		"nominal case": {
			sccs: []*kapi.SecurityContextConstraints{
				admissionttesting.UserScc("bar"),
				admissionttesting.UserScc("foo"),
			},
			check: func(p *securityapi.PodSecurityPolicySubjectReview) (bool, string) {
				// must be different due defaulting
				return p.Status.Template.Spec.SecurityContext != nil, "Status.Template should be defaulted"
			},
		},
		// if PodTemplateSpec.Spec.ServiceAccountName is empty it will not be defaulted
		"empty service account name": {
			sccs: []*kapi.SecurityContextConstraints{
				admissionttesting.UserScc("bar"),
				admissionttesting.UserScc("foo"),
			},
			patch: func(p *securityapi.PodSecurityPolicySubjectReview) {
				p.Spec.Template.Spec.ServiceAccountName = "" // empty SA in podSpec
			},

			check: func(p *securityapi.PodSecurityPolicySubjectReview) (bool, string) {
				return p.Status.Template.Spec.SecurityContext == nil, "Status.PodTemplateSpec should not be defaulted"
			},
		},
		// If you specify "User" but not "Group", then is it interpreted as "What if User were not a member of any groups.
		"user - no group": {
			sccs: []*kapi.SecurityContextConstraints{
				admissionttesting.UserScc("bar"),
				admissionttesting.UserScc("foo"),
			},
			patch: func(p *securityapi.PodSecurityPolicySubjectReview) {
				p.Spec.Groups = nil
			},
		},
		// If User and Groups are empty, then the check is performed using *only* the ServiceAccountName in the PodTemplateSpec.
		"no user - no group": {
			sccs: []*kapi.SecurityContextConstraints{
				admissionttesting.UserScc("bar"),
				admissionttesting.UserScc("foo"),
				saSCC(),
			},
			patch: func(p *securityapi.PodSecurityPolicySubjectReview) {
				p.Spec.Groups = nil
				p.Spec.User = ""
			},
		},
	}

	namespace := admissionttesting.CreateNamespaceForTest()
	for testName, testcase := range testcases {
		serviceAccount := admissionttesting.CreateSAForTest()
		reviewRequest := &securityapi.PodSecurityPolicySubjectReview{
			Spec: securityapi.PodSecurityPolicySubjectReviewSpec{
				Template: kapi.PodTemplateSpec{
					Spec: kapi.PodSpec{
						Containers:         []kapi.Container{{Name: "ctr", Image: "image", ImagePullPolicy: "IfNotPresent"}},
						RestartPolicy:      kapi.RestartPolicyAlways,
						SecurityContext:    &kapi.PodSecurityContext{},
						DNSPolicy:          kapi.DNSClusterFirst,
						ServiceAccountName: "default",
					},
				},
				User:   "foo",
				Groups: []string{"bar", "baz"},
			},
		}
		if testcase.patch != nil {
			testcase.patch(reviewRequest) // local modification of the nominal case
		}

		cache := &oscache.IndexerToSecurityContextConstraintsLister{
			Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
		}
		for _, scc := range testcase.sccs {
			if err := cache.Add(scc); err != nil {
				t.Fatalf("error adding sccs to store: %v", err)
			}
		}

		groupCache := usercache.NewGroupCache(&groupCache{})
		authorizer := &testAuthorizer{
			allowed: true,
		}
		csf := clientsetfake.NewSimpleClientset(namespace, serviceAccount)
		storage := REST{oscc.NewDefaultSCCMatcher(cache), groupCache, authorizer, csf}
		ctx := kapi.WithNamespace(kapi.NewContext(), "default")
		obj, err := storage.Create(ctx, reviewRequest)
		if err != nil {
			t.Errorf("%s - Unexpected error: %v", testName, err)
			continue
		}
		pspsr, ok := obj.(*securityapi.PodSecurityPolicySubjectReview)
		if !ok {
			t.Errorf("%s - Unable to convert created runtime.Object to PodSecurityPolicySubjectReview", testName)
			continue
		}

		if testcase.check != nil {
			if ok, message := testcase.check(pspsr); !ok {
				t.Errorf("testcase '%s' is failing: %s", testName, message)
			}
		}
		if pspsr.Status.AllowedBy == nil {
			t.Errorf("testcase '%s' is failing AllowedBy shoult be not nil\n", testName)
		}
	}
}

func TestRequests(t *testing.T) {
	testcases := map[string]struct {
		request        *securityapi.PodSecurityPolicySubjectReview
		sccs           []*kapi.SecurityContextConstraints
		serviceAccount *kapi.ServiceAccount
		errorMessage   string
	}{
		"invalid request": {
			request: &securityapi.PodSecurityPolicySubjectReview{
				Spec: securityapi.PodSecurityPolicySubjectReviewSpec{
					Template: kapi.PodTemplateSpec{
						Spec: kapi.PodSpec{
							Containers:         []kapi.Container{{Name: "ctr", Image: "image", ImagePullPolicy: "IfNotPresent"}},
							RestartPolicy:      kapi.RestartPolicyAlways,
							SecurityContext:    &kapi.PodSecurityContext{},
							DNSPolicy:          kapi.DNSClusterFirst,
							ServiceAccountName: "A.B.C.D",
						},
					},
					User:   "foo",
					Groups: []string{"bar", "baz"},
				},
			},
			errorMessage: `PodSecurityPolicySubjectReview "" is invalid: spec.template.spec.serviceAccountName: Invalid value: "A.B.C.D": must match the regex [a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)* (e.g. 'example.com')`,
		},
		"no provider": {
			request: &securityapi.PodSecurityPolicySubjectReview{
				Spec: securityapi.PodSecurityPolicySubjectReviewSpec{
					Template: kapi.PodTemplateSpec{
						Spec: kapi.PodSpec{
							Containers:         []kapi.Container{{Name: "ctr", Image: "image", ImagePullPolicy: "IfNotPresent"}},
							RestartPolicy:      kapi.RestartPolicyAlways,
							SecurityContext:    &kapi.PodSecurityContext{},
							DNSPolicy:          kapi.DNSClusterFirst,
							ServiceAccountName: "default",
						},
					},
				},
			},
			// no errorMessage only pspr empty
		},
		"container capability": {
			request: &securityapi.PodSecurityPolicySubjectReview{
				Spec: securityapi.PodSecurityPolicySubjectReviewSpec{
					Template: kapi.PodTemplateSpec{
						Spec: kapi.PodSpec{
							Containers: []kapi.Container{
								{
									Name:            "ctr",
									Image:           "image",
									ImagePullPolicy: "IfNotPresent",
									SecurityContext: &kapi.SecurityContext{
										Capabilities: &kapi.Capabilities{
											Add: []kapi.Capability{"foo"},
										},
									},
								},
							},
							RestartPolicy:      kapi.RestartPolicyAlways,
							SecurityContext:    &kapi.PodSecurityContext{},
							DNSPolicy:          kapi.DNSClusterFirst,
							ServiceAccountName: "default",
						},
					},
					User: "foo",
				},
			},
			sccs: []*kapi.SecurityContextConstraints{
				admissionttesting.UserScc("bar"),
				admissionttesting.UserScc("foo"),
			},
			// no errorMessage
		},
	}
	namespace := admissionttesting.CreateNamespaceForTest()
	serviceAccount := admissionttesting.CreateSAForTest()
	for testName, testcase := range testcases {
		sccCache := &oscache.IndexerToSecurityContextConstraintsLister{
			Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
		}
		for _, scc := range testcase.sccs {
			if err := sccCache.Add(scc); err != nil {
				t.Fatalf("error adding sccs to store: %v", err)
			}
		}
		csf := clientsetfake.NewSimpleClientset(namespace, serviceAccount)
		groupCache := usercache.NewGroupCache(&groupCache{})
		authorizer := &testAuthorizer{
			allowed: false,
		}
		storage := REST{oscc.NewDefaultSCCMatcher(sccCache), groupCache, authorizer, csf}
		ctx := kapi.WithNamespace(kapi.NewContext(), "default")
		_, err := storage.Create(ctx, testcase.request)
		switch {
		case err == nil && len(testcase.errorMessage) == 0:
			continue
		case err == nil && len(testcase.errorMessage) > 0:
			t.Errorf("%s - Expected error %q. No error found", testName, testcase.errorMessage)
			continue
		case err.Error() != testcase.errorMessage:
			t.Errorf("%s - Expected error %q. But got %q", testName, testcase.errorMessage, err.Error())
		}
	}

}

package v20191231preview

import (
	"github.com/jim-minter/rp/pkg/api"
	"github.com/jim-minter/rp/pkg/env"
)

const (
	resourceProviderNamespace = "Microsoft.RedHatOpenShift"
	resourceType              = "openShiftClusters"
)

type openShiftCluster struct {
	*DynamicValidator
}

func (*openShiftCluster) OpenShiftClusterToExternal(oc *api.OpenShiftCluster) interface{} {
	return openShiftClusterToExternal(oc)
}

func (*openShiftCluster) OpenShiftClustersToExternal(ocs []*api.OpenShiftCluster) interface{} {
	return openShiftClustersToExternal(ocs)
}

func (*openShiftCluster) OpenShiftClusterToInternal(oc interface{}, out *api.OpenShiftCluster) {
	openShiftClusterToInternal(oc.(*OpenShiftCluster), out)
}

func (*openShiftCluster) ValidateOpenShiftCluster(location, resourceID string, oc interface{}, curr *api.OpenShiftCluster) error {
	var current *OpenShiftCluster
	if curr != nil {
		current = openShiftClusterToExternal(curr)
	}
	return validateOpenShiftCluster(location, resourceID, oc.(*OpenShiftCluster), current)
}

type openShiftClusterCredentials struct{}

func (*openShiftClusterCredentials) OpenShiftClusterToExternal(oc *api.OpenShiftCluster) interface{} {
	return openShiftClusterCredentialsToExternal(oc)
}

type version struct {
	oc  *openShiftCluster
	occ *openShiftClusterCredentials
}

func (v *version) OpenShiftCluster() interface {
	api.OpenShiftClusterToExternal
	api.OpenShiftClustersToExternal
	api.OpenShiftClusterToInternal
} {
	return v.oc
}
func (v *version) OpenShiftClusterCredentials() api.OpenShiftClusterToExternal {
	return v.occ
}

// TODO: Clean up the mess
func NewAPI(env env.Interface) api.Version {
	return &version{
		oc: &openShiftCluster{
			DynamicValidator: NewDynamicValidator(env.FPAuthorizer),
		},
		occ: &openShiftClusterCredentials{},
	}
}

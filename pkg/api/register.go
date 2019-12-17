package api

import (
	"context"
)

// OpenShiftClusterToExternal is implemented by all APIs - it enables conversion
// of the internal OpenShiftCluster representation to the API-specific versioned
// external representation
type OpenShiftClusterToExternal interface {
	OpenShiftClusterToExternal(*OpenShiftCluster) interface{}
}

// OpenShiftClustersToExternal is implemented by APIs that can convert multiple
// internal OpenShiftCluster representations to the API-specific versioned
// external representation
type OpenShiftClustersToExternal interface {
	OpenShiftClustersToExternal([]*OpenShiftCluster) interface{}
}

// OpenShiftClusterToInternal is implemented by APIs that can convert their
// API-specific versioned external representation to the internal
// OpenShiftCluster representation.  It also includes validators
type OpenShiftClusterToInternal interface {
	OpenShiftClusterToInternal(interface{}, *OpenShiftCluster)
	ValidateOpenShiftCluster(string, string, interface{}, *OpenShiftCluster) error
	ValidateOpenShiftClusterDynamic(context.Context, *OpenShiftCluster) error
}

// TODO: Replace this name
type OpenShiftClusterInterface interface {
	OpenShiftClusterToExternal
	OpenShiftClustersToExternal
	OpenShiftClusterToInternal
}

// Version represents an API version
type Version interface {
	OpenShiftCluster() OpenShiftClusterInterface
	OpenShiftClusterCredentials() OpenShiftClusterToExternal
}

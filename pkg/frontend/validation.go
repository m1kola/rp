package frontend

import (
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"

	"github.com/jim-minter/rp/pkg/api"
)

var rxResourceGroupName = regexp.MustCompile(`(?i)^[-a-z0-9_().]{0,89}[-a-z0-9_()]$`)

func (f *frontend) isValidRequestPath(w http.ResponseWriter, r *http.Request) bool {
	vars := mux.Vars(r)

	_, err := uuid.FromString(vars["subscriptionId"])
	if err != nil {
		f.error(w, http.StatusNotFound, api.CloudErrorCodeInvalidSubscriptionID, "", "The provided subscription identifier '%s' is malformed or invalid.", vars["subscriptionId"])
		return false
	}

	if _, found := vars["resourceGroupName"]; found {
		if !rxResourceGroupName.MatchString(vars["resourceGroupName"]) {
			f.error(w, http.StatusNotFound, api.CloudErrorCodeResourceGroupNotFound, "", "Resource group '%s' could not be found.", vars["resourceGroupName"])
			return false
		}
	}

	if vars["resourceProviderNamespace"] != resourceProviderNamespace {
		f.error(w, http.StatusNotFound, api.CloudErrorCodeInvalidResourceNamespace, "", "The resource namespace '%s' is invalid.", vars["resourceProviderNamespace"])
		return false
	}

	if vars["resourceType"] != resourceType {
		f.error(w, http.StatusNotFound, api.CloudErrorCodeInvalidResourceType, "", "The resource type '%s' could not be found in the namespace '%s' for api version '%s'.", vars["resourceType"], vars["resourceProviderNamespace"], r.URL.Query().Get("api-version"))
		return false
	}

	if _, found := vars["resourceName"]; found {
		if !rxResourceGroupName.MatchString(vars["resourceName"]) {
			f.error(w, http.StatusNotFound, api.CloudErrorCodeResourceNotFound, "", "The Resource '%s/%s/%s' under resource group '%s' was not found.", vars["resourceProviderNamespace"], vars["resourceType"], vars["resourceName"], vars["resourceGroupName"])
			return false
		}
	}

	return true
}

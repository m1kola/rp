package frontend

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/jim-minter/rp/pkg/api"
	"github.com/jim-minter/rp/pkg/database/cosmosdb"
	"github.com/jim-minter/rp/pkg/frontend/middleware"
)

func (f *frontend) getOpenShiftCluster(w http.ResponseWriter, r *http.Request) {
	log := r.Context().Value(middleware.ContextKeyLog).(*logrus.Entry)
	vars := mux.Vars(r)

	b, err := f._getOpenShiftCluster(r, f.apis[vars["api-version"]].OpenShiftCluster())

	reply(log, w, b, err)
}

func (f *frontend) _getOpenShiftCluster(r *http.Request, external api.OpenShiftClusterToExternal) ([]byte, error) {
	vars := mux.Vars(r)

	doc, err := f.db.OpenShiftClusters.Get(api.Key(r.URL.Path))
	switch {
	case cosmosdb.IsErrorStatusCode(err, http.StatusNotFound):
		return nil, api.NewCloudError(http.StatusNotFound, api.CloudErrorCodeResourceNotFound, "", "The Resource '%s/%s' under resource group '%s' was not found.", vars["resourceType"], vars["resourceName"], vars["resourceGroupName"])
	case err != nil:
		return nil, err
	}

	doc.OpenShiftCluster.Properties.ServicePrincipalProfile.ClientSecret = ""

	return json.MarshalIndent(external.OpenShiftClusterToExternal(doc.OpenShiftCluster), "", "    ")
}

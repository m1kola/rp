package frontend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/jim-minter/rp/pkg/api"
	"github.com/jim-minter/rp/pkg/database/cosmosdb"

	"github.com/jim-minter/rp/pkg/database"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"

	"github.com/jim-minter/rp/pkg/env"
	"github.com/jim-minter/rp/pkg/util/mocks/mock_database"
	utiltls "github.com/jim-minter/rp/pkg/util/tls"
	"github.com/jim-minter/rp/test/util/listener"
)

func TestGetOpenShiftCluster(t *testing.T) {
	ctx := context.Background()

	validclientkey, validclientcerts, err := utiltls.GenerateKeyAndCertificate("validclient", true)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name           string
		clusterKey     string
		dbMock         func(mockCtrl *gomock.Controller) *database.Database
		wantStatusCode int
		wantJSON       string
	}{
		{
			name:       "cluster exists in db",
			clusterKey: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.RedHatOpenShift/openShiftClusters/cluster-exists",
			dbMock: func(mockCtrl *gomock.Controller) *database.Database {
				doc := &api.OpenShiftClusterDocument{
					OpenShiftCluster: &api.OpenShiftCluster{
						Name: "cluster-exists",
						Properties: api.Properties{
							ServicePrincipalProfile: api.ServicePrincipalProfile{
								ClientSecret: "fake-secret",
							},
						},
					},
				}

				ocDbMock := mock_database.NewMockOpenShiftClusters(mockCtrl)
				c := ocDbMock.EXPECT().Get(api.Key("/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/test-rg/providers/microsoft.redhatopenshift/openshiftclusters/cluster-exists"))
				c.Return(doc, nil)

				return &database.Database{
					OpenShiftClusters: ocDbMock,
				}
			},
			wantStatusCode: http.StatusOK,
			wantJSON: `{
    "name": "cluster-exists",
    "properties": {
        "servicePrincipalProfile": {},
        "networkProfile": {},
        "masterProfile": {}
    }
}
`,
		},
		{
			name:       "cluster not found in db",
			clusterKey: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.RedHatOpenShift/openShiftClusters/cluster-not-found",
			dbMock: func(mockCtrl *gomock.Controller) *database.Database {
				ocDbMock := mock_database.NewMockOpenShiftClusters(mockCtrl)
				c := ocDbMock.EXPECT().Get(api.Key("/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/test-rg/providers/microsoft.redhatopenshift/openshiftclusters/cluster-not-found"))
				c.Return(nil, &cosmosdb.Error{StatusCode: http.StatusNotFound})

				return &database.Database{
					OpenShiftClusters: ocDbMock,
				}
			},
			wantStatusCode: http.StatusNotFound,
			wantJSON: `{
    "error": {
        "code": "ResourceNotFound",
        "message": "The Resource 'openshiftclusters/cluster-not-found' under resource group 'test-rg' was not found."
    }
}
`,
		},
		{
			name:       "internal error",
			clusterKey: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.RedHatOpenShift/openShiftClusters/test-cluster",
			dbMock: func(mockCtrl *gomock.Controller) *database.Database {
				ocDbMock := mock_database.NewMockOpenShiftClusters(mockCtrl)
				c := ocDbMock.EXPECT().Get(api.Key("/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/test-rg/providers/microsoft.redhatopenshift/openshiftclusters/test-cluster"))
				c.Return(nil, errors.New("random error"))

				return &database.Database{
					OpenShiftClusters: ocDbMock,
				}
			},
			wantStatusCode: http.StatusInternalServerError,
			wantJSON: `{
    "error": {
        "code": "InternalServerError",
        "message": "Internal server error."
    }
}
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Note: we need to create and close a listener for every test run,
			// otherwise we will be running multiple versions of frontend with different mocks
			l := listener.NewListener()
			defer l.Close()

			env := env.NewTest(l, validclientcerts[0].Raw)

			env.TLSKey, env.TLSCerts, err = utiltls.GenerateKeyAndCertificate("server", false)
			if err != nil {
				t.Fatal(err)
			}

			pool := x509.NewCertPool()
			pool.AddCert(env.TLSCerts[0])

			c := &http.Client{
				Transport: &http.Transport{
					Dial: l.Dial,
					TLSClientConfig: &tls.Config{
						RootCAs: pool,
						Certificates: []tls.Certificate{
							{
								Certificate: [][]byte{validclientcerts[0].Raw},
								PrivateKey:  validclientkey,
							},
						},
					},
				},
			}

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			f, err := NewFrontend(ctx, logrus.NewEntry(logrus.StandardLogger()), env, tt.dbMock(mockCtrl))
			if err != nil {
				t.Fatal(err)
			}

			go f.Run(nil, nil)

			resp, err := c.Get(fmt.Sprintf("https://server%s?api-version=2019-12-31-preview", tt.clusterKey))
			if err != nil {
				t.Fatalf("unexpected err: %s", err.Error())
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("unexpected status code. Got: %d, expected: %d", resp.StatusCode, tt.wantStatusCode)
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error while reading body: %s", err.Error())
			}
			if string(body) != tt.wantJSON {
				t.Errorf("unexpected body. Got: %s, expected: %s", string(body), tt.wantJSON)
			}
		})
	}
}

package v20191231preview

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/dgrijalva/jwt-go"

	"github.com/jim-minter/rp/pkg/api"
	"github.com/jim-minter/rp/pkg/util/azureclient/authorization"
	utilpermissions "github.com/jim-minter/rp/pkg/util/permissions"
	"github.com/jim-minter/rp/pkg/util/subnet"
)

type azureClaim struct {
	Roles []string `json:"roles,omitempty"`
}

func (*azureClaim) Valid() error {
	return fmt.Errorf("unimplemented")
}

func NewDynamicValidator(getFPAuthorizer func(string, string) (autorest.Authorizer, error)) *DynamicValidator {
	return &DynamicValidator{
		FPAuthorizer:  getFPAuthorizer,
		SPAuthorizer:  validateServicePrincipalProfile,
		SubnetManager: subnet.NewManager,
		FpPermissions: authorization.NewPermissionsClient,
		SpPermissions: authorization.NewPermissionsClient,
	}
}

type DynamicValidator struct {
	FPAuthorizer  func(tenantID, resource string) (autorest.Authorizer, error)
	SPAuthorizer  func(oc *api.OpenShiftCluster) (autorest.Authorizer, error)
	FpPermissions func(subscriptionID string, authorizer autorest.Authorizer) authorization.PermissionsClient
	SpPermissions func(subscriptionID string, authorizer autorest.Authorizer) authorization.PermissionsClient
	SubnetManager func(subscriptionID string, spAuthorizer autorest.Authorizer) subnet.Manager
}

// ValidateOpenShiftClusterDynamic validates an OpenShift cluster
func (dv *DynamicValidator) ValidateOpenShiftClusterDynamic(ctx context.Context, oc *api.OpenShiftCluster) error {
	r, err := azure.ParseResourceID(oc.ID)
	if err != nil {
		return err
	}

	spAuthorizer, err := dv.SPAuthorizer(oc)
	if err != nil {
		return err
	}

	err = validateServicePrincipalRole(oc)
	if err != nil {
		return err
	}

	spPermissions := dv.SpPermissions(r.SubscriptionID, spAuthorizer)
	err = validateVnetPermissions(ctx, oc, spPermissions, api.CloudErrorCodeInvalidServicePrincipalPermissions, "provided service principal")
	if err != nil {
		return err
	}

	fpAuthorizer, err := dv.FPAuthorizer(oc.Properties.ServicePrincipalProfile.TenantID, azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return err
	}

	fpPermissions := dv.FpPermissions(r.SubscriptionID, fpAuthorizer)
	err = validateVnetPermissions(ctx, oc, fpPermissions, api.CloudErrorCodeInvalidResourceProviderPermissions, "resource provider")
	if err != nil {
		return err
	}

	return validateSubnets(
		ctx,
		dv.SubnetManager(r.SubscriptionID, spAuthorizer),
		oc,
	)
}

func validateServicePrincipalProfile(oc *api.OpenShiftCluster) (autorest.Authorizer, error) {
	spp := &oc.Properties.ServicePrincipalProfile
	conf := auth.NewClientCredentialsConfig(spp.ClientID, spp.ClientSecret, spp.TenantID)

	token, err := conf.ServicePrincipalToken()
	if err != nil {
		return nil, err
	}

	err = token.EnsureFresh()
	if err != nil {
		return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidServicePrincipalCredentials, "properties.servicePrincipalProfile", "The provided service principal credentials are invalid.")
	}

	return conf.Authorizer()
}

func validateServicePrincipalRole(oc *api.OpenShiftCluster) error {
	spp := &oc.Properties.ServicePrincipalProfile
	conf := auth.NewClientCredentialsConfig(spp.ClientID, spp.ClientSecret, spp.TenantID)
	conf.Resource = azure.PublicCloud.GraphEndpoint

	token, err := conf.ServicePrincipalToken()
	if err != nil {
		return err
	}

	err = token.EnsureFresh()
	if err != nil {
		return err
	}

	p := &jwt.Parser{}
	c := &azureClaim{}
	_, _, err = p.ParseUnverified(token.OAuthToken(), c)
	if err != nil {
		return err
	}

	for _, role := range c.Roles {
		if role == "Application.ReadWrite.OwnedBy" {
			return api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidServicePrincipalCredentials, "properties.servicePrincipalProfile", "The provided service principal must not have the Application.ReadWrite.OwnedBy permission.")
		}
	}

	return nil
}

func validateVnetPermissions(ctx context.Context, oc *api.OpenShiftCluster, client authorization.PermissionsClient, code, typ string) error {
	vnetID, _, err := subnet.Split(oc.Properties.MasterProfile.SubnetID)
	if err != nil {
		return err
	}

	permissions, err := client.ListForResource(ctx, vnetID)
	if err != nil {
		if err, ok := err.(autorest.DetailedError); ok {
			if err.StatusCode == http.StatusNotFound {
				return api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, "properties.masterProfile.subnetId", "The provided master VM subnet '%s' could not be found.", oc.Properties.MasterProfile.SubnetID)
			}
		}

		return err
	}

	for _, action := range []string{
		"Microsoft.Network/virtualNetworks/subnets/join/action",
		"Microsoft.Network/virtualNetworks/subnets/read",
		"Microsoft.Network/virtualNetworks/subnets/write",
	} {
		ok, err := utilpermissions.CanDoAction(permissions, action)
		if err != nil {
			return err
		}
		if !ok {
			return api.NewCloudError(http.StatusBadRequest, code, "", "The "+typ+" does not have Contributor permission on vnet '%s'.", vnetID)
		}
	}

	return nil
}

func validateSubnets(ctx context.Context, subnets subnet.Manager, oc *api.OpenShiftCluster) error {
	master, err := validateSubnet(ctx, subnets, oc, "properties.masterProfile.subnetId", "master", oc.Properties.MasterProfile.SubnetID)
	if err != nil {
		return err
	}

	worker, err := validateSubnet(ctx, subnets, oc, `properties.workerProfiles["worker"].subnetId`, "worker", oc.Properties.WorkerProfiles[0].SubnetID)
	if err != nil {
		return err
	}

	_, pod, err := net.ParseCIDR(oc.Properties.NetworkProfile.PodCIDR)
	if err != nil {
		return err
	}

	_, service, err := net.ParseCIDR(oc.Properties.NetworkProfile.ServiceCIDR)
	if err != nil {
		return err
	}

	err = cidr.VerifyNoOverlap([]*net.IPNet{master, worker, pod, service}, &net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)})
	if err != nil {
		return api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, "", "The provided CIDRs must not overlap: '%s'.", err)
	}

	return nil
}

func validateSubnet(ctx context.Context, subnets subnet.Manager, oc *api.OpenShiftCluster, path, typ, subnetID string) (*net.IPNet, error) {
	s, err := subnets.Get(ctx, subnetID)
	if err != nil {
		if err, ok := err.(autorest.DetailedError); ok {
			if err.StatusCode == http.StatusNotFound {
				return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, path, "The provided "+typ+" VM subnet '%s' could not be found.", subnetID)
			}
		}
		return nil, err
	}

	if oc.Properties.ProvisioningState == api.ProvisioningStateCreating {
		if s.SubnetPropertiesFormat != nil &&
			s.SubnetPropertiesFormat.NetworkSecurityGroup != nil {
			return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, path, "The provided "+typ+" VM subnet '%s' is invalid: must not have a network security group attached.", subnetID)
		}

	} else {
		nsgID, err := subnet.NetworkSecurityGroupID(oc, *s.ID)
		if err != nil {
			return nil, err
		}

		if s.SubnetPropertiesFormat == nil ||
			s.SubnetPropertiesFormat.NetworkSecurityGroup == nil ||
			!strings.EqualFold(*s.SubnetPropertiesFormat.NetworkSecurityGroup.ID, nsgID) {
			return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, path, "The provided "+typ+" VM subnet '%s' is invalid: must have network security group '%s' attached.", subnetID, nsgID)
		}
	}

	_, net, err := net.ParseCIDR(*s.AddressPrefix)
	if err != nil {
		return nil, err
	}
	{
		ones, _ := net.Mask.Size()
		if ones > 27 {
			return nil, api.NewCloudError(http.StatusBadRequest, api.CloudErrorCodeInvalidLinkedVNet, path, "The provided "+typ+" VM subnet '%s' is invalid: must be /27 or larger.", subnetID)
		}
	}

	return net, nil
}

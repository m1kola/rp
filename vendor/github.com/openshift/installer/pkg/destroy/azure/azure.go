package azure

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/azure-sdk-for-go/services/preview/dns/mgmt/2018-03-01-preview/dns"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	azuresession "github.com/openshift/installer/pkg/asset/installconfig/azure"
	"github.com/openshift/installer/pkg/destroy/providers"
	"github.com/openshift/installer/pkg/types"
)

// ClusterUninstaller holds the various options for the cluster we want to delete.
type ClusterUninstaller struct {
	SubscriptionID  string
	TenantID        string
	GraphAuthorizer autorest.Authorizer
	Authorizer      autorest.Authorizer

	ResourceGroup string
	InfraID       string

	Logger logrus.FieldLogger

	resourceGroupsClient    resources.GroupsGroupClient
	zonesClient             dns.ZonesClient
	recordsClient           dns.RecordSetsClient
	serviceprincipalsClient graphrbac.ServicePrincipalsClient
	applicationsClient      graphrbac.ApplicationsClient
}

func (o *ClusterUninstaller) configureClients() {
	o.resourceGroupsClient = resources.NewGroupsGroupClient(o.SubscriptionID)
	o.resourceGroupsClient.Authorizer = o.Authorizer

	o.zonesClient = dns.NewZonesClient(o.SubscriptionID)
	o.zonesClient.Authorizer = o.Authorizer

	o.recordsClient = dns.NewRecordSetsClient(o.SubscriptionID)
	o.recordsClient.Authorizer = o.Authorizer

	o.serviceprincipalsClient = graphrbac.NewServicePrincipalsClient(o.TenantID)
	o.serviceprincipalsClient.Authorizer = o.GraphAuthorizer

	o.applicationsClient = graphrbac.NewApplicationsClient(o.TenantID)
	o.applicationsClient.Authorizer = o.GraphAuthorizer
}

// New returns an Azure destroyer from ClusterMetadata.
func New(logger logrus.FieldLogger, metadata *types.ClusterMetadata) (providers.Destroyer, error) {
	session, err := azuresession.GetSession(nil)
	if err != nil {
		return nil, err
	}

	resourceGroup := metadata.ClusterPlatformMetadata.Azure.ResourceGroup
	if resourceGroup == "" {
		resourceGroup = metadata.InfraID + "-rg"
	}

	return &ClusterUninstaller{
		SubscriptionID:  session.Credentials.SubscriptionID,
		TenantID:        session.Credentials.TenantID,
		GraphAuthorizer: session.GraphAuthorizer,
		Authorizer:      session.Authorizer,
		ResourceGroup:   resourceGroup,
		InfraID:         metadata.InfraID,
		Logger:          logger,
	}, nil
}

// Run is the entrypoint to start the uninstall process.
func (o *ClusterUninstaller) Run() error {
	o.configureClients()
	o.Logger.Debug("deleting public records")
	if err := deletePublicRecords(context.TODO(), o.zonesClient, o.recordsClient, o.Logger, o.ResourceGroup); err != nil {
		o.Logger.Debug(err)
		return errors.Wrap(err, "failed to delete public DNS records")
	}
	o.Logger.Debug("deleting resource group")
	if err := deleteResourceGroup(context.TODO(), o.resourceGroupsClient, o.Logger, o.ResourceGroup); err != nil {
		o.Logger.Debug(err)
		return errors.Wrap(err, "failed to delete resource group")
	}
	o.Logger.Debug("deleting application registrations")
	if err := deleteApplicationRegistrations(context.TODO(), o.applicationsClient, o.serviceprincipalsClient, o.Logger, o.InfraID); err != nil {
		o.Logger.Debug(err)
		return errors.Wrap(err, "failed to delete application registrations and their service principals")
	}

	return nil
}

func deletePublicRecords(ctx context.Context, dnsClient dns.ZonesClient, recordsClient dns.RecordSetsClient, logger logrus.FieldLogger, rgName string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// collect records from private zones in rgName
	var errs []error
	for zonesPage, err := dnsClient.ListByResourceGroup(ctx, rgName, to.Int32Ptr(100)); zonesPage.NotDone(); err = zonesPage.NextWithContext(ctx) {
		if err != nil {
			errs = append(errs, errors.Wrap(err, "failed to list private zone"))
			continue
		}
		for _, zone := range zonesPage.Values() {
			if zone.ZoneType == dns.Private {
				if err := deletePublicRecordsForZone(ctx, dnsClient, recordsClient, logger, rgName, to.String(zone.Name)); err != nil {
					errs = append(errs, errors.Wrapf(err, "failed to delete public records for %s", to.String(zone.Name)))
					continue
				}
			}
		}
	}
	return utilerrors.NewAggregate(errs)
}

func deletePublicRecordsForZone(ctx context.Context, dnsClient dns.ZonesClient, recordsClient dns.RecordSetsClient, logger logrus.FieldLogger, zoneGroup, zoneName string) error {
	// collect all the records from the zoneName
	allPrivateRecords := sets.NewString()
	for recordPages, err := recordsClient.ListByDNSZone(ctx, zoneGroup, zoneName, to.Int32Ptr(100), ""); recordPages.NotDone(); err = recordPages.NextWithContext(ctx) {
		if err != nil {
			return err
		}
		for _, record := range recordPages.Values() {
			if t := toRecordType(to.String(record.Type)); t == dns.SOA || t == dns.NS {
				continue
			}
			allPrivateRecords.Insert(fmt.Sprintf("%s.%s", to.String(record.Name), zoneName))
		}
	}

	sharedZones, err := getSharedDNSZones(ctx, dnsClient, zoneName)
	if err != nil {
		return errors.Wrapf(err, "failed to find shared zone for %s", zoneName)
	}
	for _, sharedZone := range sharedZones {
		logger.Debugf("removing matching private records from %s", sharedZone.Name)
		for recordPages, err := recordsClient.ListByDNSZone(ctx, sharedZone.Group, sharedZone.Name, to.Int32Ptr(100), ""); recordPages.NotDone(); err = recordPages.NextWithContext(ctx) {
			if err != nil {
				return err
			}
			for _, record := range recordPages.Values() {
				if allPrivateRecords.Has(fmt.Sprintf("%s.%s", to.String(record.Name), sharedZone.Name)) {
					resp, err := recordsClient.Delete(ctx, sharedZone.Group, sharedZone.Name, to.String(record.Name), toRecordType(to.String(record.Type)), "")
					if err != nil {
						if wasNotFound(resp.Response) {
							logger.WithField("record", to.String(record.Name)).Debug("already deleted")
							continue
						}
						return errors.Wrapf(err, "failed to delete record %s in zone %s", to.String(record.Name), sharedZone.Name)
					}
					logger.WithField("record", to.String(record.Name)).Info("deleted")
				}
			}
		}
	}
	return nil
}

// getSharedDNSZones returns the all parent public dns zones for privZoneName in decreasing order of closeness.
func getSharedDNSZones(ctx context.Context, client dns.ZonesClient, privZoneName string) ([]dnsZone, error) {
	domain := privZoneName
	parents := sets.NewString(domain)
	for {
		idx := strings.Index(domain, ".")
		if idx == -1 {
			break
		}
		if len(domain[idx+1:]) > 0 {
			parents.Insert(domain[idx+1:])
		}
		domain = domain[idx+1:]
	}

	allPublicZones := []dnsZone{}
	for zonesPage, err := client.List(ctx, to.Int32Ptr(100)); zonesPage.NotDone(); err = zonesPage.NextWithContext(ctx) {
		if err != nil {
			return nil, err
		}
		for _, zone := range zonesPage.Values() {
			if zone.ZoneType == dns.Public && parents.Has(to.String(zone.Name)) {
				allPublicZones = append(allPublicZones, dnsZone{Name: to.String(zone.Name), ID: to.String(zone.ID), Group: groupFromID(to.String(zone.ID)), Public: true})
				continue
			}
		}
	}
	sort.Slice(allPublicZones, func(i, j int) bool { return len(allPublicZones[i].Name) > len(allPublicZones[j].Name) })
	return allPublicZones, nil
}

type dnsZone struct {
	Name   string
	ID     string
	Group  string
	Public bool
}

func groupFromID(id string) string {
	return strings.Split(id, "/")[4]
}

func toRecordType(t string) dns.RecordType {
	return dns.RecordType(strings.TrimPrefix(t, "Microsoft.Network/dnszones/"))
}

func deleteResourceGroup(ctx context.Context, client resources.GroupsGroupClient, logger logrus.FieldLogger, name string) error {
	logger = logger.WithField("resource group", name)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	delFuture, err := client.Delete(ctx, name)
	if err != nil {
		return err
	}

	err = delFuture.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		if wasNotFound(delFuture.Response()) {
			logger.Debug("already deleted")
			return nil
		}
		return errors.Wrapf(err, "failed to delete %s", name)
	}
	logger.Info("deleted")
	return nil
}

func wasNotFound(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

func deleteApplicationRegistrations(ctx context.Context, appClient graphrbac.ApplicationsClient, spClient graphrbac.ServicePrincipalsClient, logger logrus.FieldLogger, infraID string) error {
	errorList := []error{}

	tag := fmt.Sprintf("kubernetes.io_cluster.%s=owned", infraID)
	servicePrincipals, err := getServicePrincipalsByTag(ctx, spClient, tag, infraID)
	if err != nil {
		return errors.Wrap(err, "failed to gather list of Service Principals by tag")
	}

	for _, sp := range servicePrincipals {
		logger = logger.WithField("appID", *sp.AppID)
		appFilter := fmt.Sprintf("appId eq '%s'", *sp.AppID)
		appResults, err := appClient.List(ctx, appFilter)
		if err != nil {
			errorList = append(errorList, err)
			continue
		}

		apps := appResults.Values()
		if len(apps) != 1 {
			msg := fmt.Sprintf("should have recieved only a single result matching AppID, received %d instead", len(apps))
			errorList = append(errorList, errors.New(msg))
			continue
		}

		_, err = appClient.Delete(ctx, *apps[0].ObjectID)
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		logger.Info("deleted")
	}

	return utilerrors.NewAggregate(errorList)
}

func getServicePrincipalsByTag(ctx context.Context, spClient graphrbac.ServicePrincipalsClient, matchTag, infraID string) ([]graphrbac.ServicePrincipal, error) {
	matchedSPs := []graphrbac.ServicePrincipal{}

	infraFilter := fmt.Sprintf("startswith(displayName,'%s')", infraID)

	for spResults, err := spClient.List(ctx, infraFilter); spResults.NotDone(); err = spResults.NextWithContext(ctx) {
		if err != nil {
			return matchedSPs, err
		}

		for _, sp := range spResults.Values() {
			for _, tag := range *sp.Tags {
				if tag == matchTag {
					matchedSPs = append(matchedSPs, sp)
					break
				}
			}
		}
	}

	return matchedSPs, nil
}

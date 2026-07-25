package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dependabot/proxy/internal/config"
)

type OIDCParameters interface {
	Name() string
}

type AzureOIDCParameters struct {
	TenantID string
	ClientID string
}

func (a *AzureOIDCParameters) Name() string {
	return "azure"
}

type JFrogOIDCParameters struct {
	JFrogURL            string
	ProviderName        string
	Audience            string
	IdentityMappingName string
}

func (j *JFrogOIDCParameters) Name() string {
	return "jfrog"
}

type AWSOIDCParameters struct {
	Region      string
	AccountID   string
	RoleName    string
	Audience    string
	Domain      string
	DomainOwner string
}

func (a *AWSOIDCParameters) Name() string {
	return "aws"
}

type CloudsmithOIDCParameters struct {
	OrgName     string
	ServiceSlug string
	ApiHost     string
	Audience    string
}

func (c *CloudsmithOIDCParameters) Name() string {
	return "cloudsmith"
}

type GCPOIDCParameters struct {
	WorkloadIdentityProvider string
	ServiceAccount           string // "" => direct WIF (no impersonation)
	Audience                 string
}

func (g *GCPOIDCParameters) Name() string {
	return "gcp"
}

type DockerHubOIDCParameters struct {
	ConnectionID string
	Username     string
	ExpiresIn    string
	Registry     string
}

func (d *DockerHubOIDCParameters) Name() string {
	return "dockerhub"
}

type OIDCCredential struct {
	parameters  OIDCParameters
	cachedToken string
	tokenExpiry time.Time
	isRejected  bool
	mutex       sync.RWMutex
}

func (c *OIDCCredential) Provider() string {
	return c.parameters.Name()
}

func CreateOIDCCredential(cred config.Credential) (*OIDCCredential, error) {
	if !IsOIDCConfigured() {
		return nil, fmt.Errorf("OIDC is not configured")
	}

	var parameters OIDCParameters

	// azure values
	tenantID := cred.GetString("tenant-id")
	clientID := cred.GetString("client-id")

	// jfrog values
	feedUrl := cred.GetString("url")
	jfrogOidcProviderName := cred.GetString("jfrog-oidc-provider-name")

	// aws values
	awsRegion := cred.GetString("aws-region")
	accountID := cred.GetString("account-id")
	roleName := cred.GetString("role-name")
	domain := cred.GetString("domain")
	domainOwner := cred.GetString("domain-owner")

	// cloudsmith values
	orgName := cred.GetString("namespace")
	serviceSlug := cred.GetString("service-slug")
	cloudsmithAudience := cred.GetString("audience")

	// gcp values
	workloadIdentityProvider := cred.GetString("workload-identity-provider")
	serviceAccount := cred.GetString("service-account")

	// docker hub values
	connectionID := cred.GetString("connection-id")
	username := cred.GetString("username")
	registry := cred.GetString("registry")
	if registry == "" {
		registry = cred.GetString("url")
	}
	if registry == "" {
		registry = cred.GetString("host")
	}

	switch {
	case tenantID != "" && clientID != "":
		parameters = &AzureOIDCParameters{
			TenantID: tenantID,
			ClientID: clientID,
		}
	case jfrogOidcProviderName != "" && feedUrl != "":
		// jfrog domain is extracted from feed url
		jfrogUrlParsed, err := url.Parse(feedUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid jfrog url: %w", err)
		}
		parameters = &JFrogOIDCParameters{
			// required
			JFrogURL:     fmt.Sprintf("%s://%s", jfrogUrlParsed.Scheme, jfrogUrlParsed.Host),
			ProviderName: jfrogOidcProviderName,
			// optional
			Audience:            cred.GetString("audience"),
			IdentityMappingName: cred.GetString("identity-mapping-name"),
		}
	case awsRegion != "" && accountID != "" && roleName != "" && domain != "" && domainOwner != "":
		audience := cred.GetString("audience")
		if audience == "" {
			audience = "sts.amazonaws.com" // defaults to this
		}
		parameters = &AWSOIDCParameters{
			Region:      awsRegion,
			AccountID:   accountID,
			RoleName:    roleName,
			Audience:    audience,
			Domain:      domain,
			DomainOwner: domainOwner,
		}
	case orgName != "" && serviceSlug != "" && cloudsmithAudience != "":
		apiHost := cred.GetString("api-host")
		if apiHost == "" {
			apiHost = "api.cloudsmith.io"
		}
		parameters = &CloudsmithOIDCParameters{
			OrgName:     orgName,
			ServiceSlug: serviceSlug,
			ApiHost:     apiHost,
			Audience:    cloudsmithAudience,
		}
	case workloadIdentityProvider != "":
		audience := cred.GetString("audience")
		if audience == "" {
			audience = "//iam.googleapis.com/" + workloadIdentityProvider
		}
		parameters = &GCPOIDCParameters{
			WorkloadIdentityProvider: workloadIdentityProvider,
			ServiceAccount:           serviceAccount,
			Audience:                 audience,
		}
	case connectionID != "" && username != "" && isDockerHubRegistry(registry):
		parameters = &DockerHubOIDCParameters{
			ConnectionID: connectionID,
			Username:     username,
			ExpiresIn:    cred.GetString("expires-in"),
			Registry:     registry,
		}
	}

	if parameters == nil {
		return nil, fmt.Errorf("OIDC parameters were not specified")
	}

	return &OIDCCredential{
		parameters: parameters,
	}, nil
}

// GetOrRefreshOIDCToken gets a cached token or fetches a new one if expired
func GetOrRefreshOIDCToken(cred *OIDCCredential, ctx context.Context) (string, error) {
	if cred.isRejected {
		return "", fmt.Errorf("credential has been rejected due to previous authentication failure")
	}

	cred.mutex.RLock()
	if cred.cachedToken != "" && time.Now().Before(cred.tokenExpiry) {
		token := cred.cachedToken
		cred.mutex.RUnlock()
		return token, nil
	}
	cred.mutex.RUnlock()

	cred.mutex.Lock()
	defer cred.mutex.Unlock()

	if cred.cachedToken != "" && time.Now().Before(cred.tokenExpiry) {
		return cred.cachedToken, nil
	}

	var oidcAccessToken *OIDCAccessToken
	var err error
	switch params := cred.parameters.(type) {
	case *AzureOIDCParameters:
		oidcAccessToken, err = GetAzureAccessTokenForDevOps(ctx, *params)
	case *JFrogOIDCParameters:
		oidcAccessToken, err = GetJFrogAccessTokenForDevOps(ctx, *params)
	case *AWSOIDCParameters:
		oidcAccessToken, err = GetAWSAccessTokenForDevOps(ctx, *params)
	case *CloudsmithOIDCParameters:
		oidcAccessToken, err = GetCloudsmithAccessTokenForDevOps(ctx, *params)
	case *GCPOIDCParameters:
		oidcAccessToken, err = GetGCPAccessTokenForDevOps(ctx, *params)
	case *DockerHubOIDCParameters:
		oidcAccessToken, err = GetDockerHubAccessTokenForDevOps(ctx, *params)
	default:
		return "", fmt.Errorf("unsupported OIDC provider: %s", cred.Provider())
	}

	if err != nil {
		cred.isRejected = true
		return "", fmt.Errorf("failed to get %s access token: %w", cred.Provider(), err)
	}

	cred.cachedToken = oidcAccessToken.Token
	refreshBuffer := 5 * time.Minute
	if oidcAccessToken.ExpiresIn <= refreshBuffer {
		refreshBuffer = 30 * time.Second
		if oidcAccessToken.ExpiresIn <= refreshBuffer {
			refreshBuffer = oidcAccessToken.ExpiresIn / 10
		}
	}
	cred.tokenExpiry = time.Now().Add(oidcAccessToken.ExpiresIn).Add(-refreshBuffer)

	return oidcAccessToken.Token, nil
}

func isDockerHubRegistry(registry string) bool {
	if registry == "" {
		return false
	}

	host := registry
	if parsed, err := url.Parse(registry); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else if parsed, err := url.Parse("//" + registry); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}

	switch strings.ToLower(host) {
	case "docker.io", "registry-1.docker.io", "registry-1-stage.docker.io", "dhi.io", "registry.hub.docker.com":
		return true
	default:
		return false
	}
}

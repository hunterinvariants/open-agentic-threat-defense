package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
)

type samlOptions struct {
	RootURL         string
	IDPMetadataURL  string
	KeyPath         string
	CertPath        string
	CompletePath    string
	LoginPath       string
	MetadataPath    string
	ACSPath         string
	TenantAttribute string
	RoleAttribute   string
	NameAttribute   string
}

type samlProvider struct {
	middleware      *samlsp.Middleware
	loginPath       string
	completePath    string
	metadataPath    string
	acsPath         string
	tenantAttribute string
	roleAttribute   string
	nameAttribute   string
}

func newSAMLProvider(opts samlOptions) (*samlProvider, error) {
	rootURL := strings.TrimSpace(opts.RootURL)
	idpMetadataURL := strings.TrimSpace(opts.IDPMetadataURL)
	keyPath := strings.TrimSpace(opts.KeyPath)
	certPath := strings.TrimSpace(opts.CertPath)
	if rootURL == "" && idpMetadataURL == "" && keyPath == "" && certPath == "" {
		return nil, nil
	}
	if rootURL == "" {
		return nil, errors.New("saml root url is required")
	}
	if idpMetadataURL == "" {
		return nil, errors.New("saml idp metadata url is required")
	}

	serviceURL, err := url.Parse(rootURL)
	if err != nil {
		return nil, fmt.Errorf("invalid saml root url: %w", err)
	}
	metadataURL, err := url.Parse(idpMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid saml idp metadata url: %w", err)
	}

	key, cert, err := loadSAMLKeyPair(keyPath, certPath, *serviceURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	idpMetadata, err := samlsp.FetchMetadata(ctx, &http.Client{Timeout: 15 * time.Second}, *metadataURL)
	if err != nil {
		return nil, err
	}

	middleware, err := samlsp.New(samlsp.Options{
		EntityID:           serviceURL.String(),
		URL:                *serviceURL,
		Key:                key,
		Certificate:        cert,
		IDPMetadata:        idpMetadata,
		SignRequest:        true,
		DefaultRedirectURI: "/",
		CookieName:         "oatd_saml",
		CookieSameSite:     http.SameSiteLaxMode,
	})
	if err != nil {
		return nil, err
	}

	return &samlProvider{
		middleware:      middleware,
		loginPath:       opts.LoginPath,
		completePath:    opts.CompletePath,
		metadataPath:    opts.MetadataPath,
		acsPath:         opts.ACSPath,
		tenantAttribute: defaultString(opts.TenantAttribute, "tenant"),
		roleAttribute:   defaultString(opts.RoleAttribute, "roles"),
		nameAttribute:   defaultString(opts.NameAttribute, "email"),
	}, nil
}

func (p *samlProvider) Enabled() bool {
	return p != nil && p.middleware != nil
}

func (p *samlProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.middleware == nil {
		http.NotFound(w, r)
		return
	}
	p.middleware.ServeHTTP(w, r)
}

func (p *samlProvider) RequireAccount(next http.Handler) http.Handler {
	if p == nil || p.middleware == nil {
		return next
	}
	return p.middleware.RequireAccount(next)
}

func (p *samlProvider) principalFromAttributes(attributes samlsp.Attributes) (auth.Principal, error) {
	if len(attributes) == 0 {
		return auth.Principal{}, errors.New("saml attributes are missing")
	}
	name := firstNonEmpty(attributes.Get(p.nameAttribute), attributes.Get("name"), attributes.Get("displayName"), attributes.Get("uid"), attributes.Get("sub"))
	if name == "" {
		return auth.Principal{}, errors.New("saml principal name is missing")
	}
	tenant := firstNonEmpty(attributes.Get(p.tenantAttribute), "default")
	roles := splitAttributeValues(attributes.Get(p.roleAttribute))
	if len(roles) == 0 {
		roles = []string{auth.RoleViewer}
	}
	return auth.Principal{
		Name:   name,
		Tenant: tenant,
		Roles:  roles,
	}, nil
}

func loadSAMLKeyPair(keyPath, certPath string, serviceURL url.URL) (*rsa.PrivateKey, *x509.Certificate, error) {
	if keyPath == "" && certPath == "" {
		return generateSAMLKeyPair(serviceURL)
	}
	if keyPath == "" || certPath == "" {
		return nil, nil, errors.New("saml key path and cert path must both be set")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read saml key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read saml cert: %w", err)
	}
	key, err := parseSAMLPrivateKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	cert, err := parseSAMLCertificate(certPEM)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func generateSAMLKeyPair(serviceURL url.URL) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate saml key: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Open Agentic Threat Defense",
			Organization: []string{"Open Agentic Threat Defense"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if host := strings.TrimSpace(serviceURL.Hostname()); host != "" {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("generate saml cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated saml cert: %w", err)
	}
	return key, cert, nil
}

func parseSAMLPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("saml private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse saml private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("saml private key must be RSA")
	}
	return key, nil
}

func parseSAMLCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("saml certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse saml certificate: %w", err)
	}
	return cert, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func splitAttributeValues(value string) []string {
	if value == "" {
		return nil
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t', '\n', '\r':
			return true
		default:
			return false
		}
	})
	values := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		values = append(values, field)
	}
	return values
}

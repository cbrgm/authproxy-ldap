/*
 * Copyright 2019, authproxy authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	apiErrors "github.com/cbrgm/authproxy/api/errors"
	"github.com/cbrgm/authproxy/api/v1/models"
	"io/ioutil"

	"github.com/go-ldap/ldap"
)

// Entry is a synonyme to go-ldap/ldap Entry
type Entry = ldap.Entry

// ServiceConfig
type LdapServiceConfig struct {
	BindURL         string
	BindDN          string
	BindPassword    string
	QueryDN         string
	TLSKey          string
	TLSCert         string
	TLSClientCA     string
	AllowInsecure   bool
	TokenExpiration int
}

// LdapService holds the connection to the LDAP server as well as a given transformer to process retrieved entries.
type LdapService struct {
	bindURL       string
	bindDN        string
	bindPassword  string
	queryDN       string
	selectors     []string
	tlsConfig     *tls.Config
	token         *TokenService
	allowInsecure bool
}

// NewLdapService creates a new LdapService
func NewLdapService(config LdapServiceConfig) (*LdapService, error) {

	// validate config
	if config.TLSKey == "" {
		return nil, errors.New("invalid config: must provide private key for jwt token capabilites")
	}
	if config.TLSCert == "" {
		return nil, errors.New("invalid config: must provide cert for jwt token capabilites")
	}
	if config.TLSClientCA == "" {
		return nil, errors.New("invalid config: must provide ca cert for jwt token capabilites")
	}

	var tlsConfig *tls.Config
	var tokenService *TokenService
	var err error

	tlsConfig, err = newTLSConfigFromArgs(config.TLSKey, config.TLSCert, config.TLSClientCA)
	if err != nil {
		return nil, err
	}

	tokenService, err = NewTokenService(config.TLSKey, config.TLSCert, config.TokenExpiration)
	if err != nil {
		return nil, err
	}

	// create the service struct
	svc := LdapService{
		bindURL:       config.BindURL,
		bindDN:        config.BindDN,
		bindPassword:  config.BindPassword,
		queryDN:       config.QueryDN,
		tlsConfig:     tlsConfig,
		token:         tokenService,
		allowInsecure: config.AllowInsecure,
	}

	// test the connection to ldap server
	conn, err := svc.connection()
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection to ldap server: %s", err)
	}
	defer conn.Close()

	// test if readonly user creds are valid
	bindUsername := svc.bindDN
	bindPassword := svc.bindPassword

	// First bind with a read only user
	err = conn.Bind(bindUsername, bindPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to login as user %s: %s", bindUsername, err)
	}

	return &svc, nil
}

func newTLSConfigFromArgs(tlsKey, tlsCert, tlsCA string) (*tls.Config, error) {
	//parse certificates from cert and key file for the authproxy server
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return nil, fmt.Errorf("invalid config: error parsing tls certificate file: %v", err)
	}

	tlsConfig := tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	// parse certificates from certificate authority file to a new CertPool.
	cPool := x509.NewCertPool()
	clientCert, err := ioutil.ReadFile(tlsCA)
	if err != nil {
		return nil, fmt.Errorf("invalid config: error reading CA file: %v", err)
	}
	if cPool.AppendCertsFromPEM(clientCert) != true {
		return nil, errors.New("invalid config: failed to parse client CA")
	}

	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = cPool

	return &tlsConfig, nil
}

// Login a user with username and passwort with given ldap server and return a bearer token
func (svc *LdapService) Login(username, password string) (*models.TokenReviewRequest, error) {

	conn, err := svc.connection()
	if err != nil {
		return nil, apiErrors.NewInternalError(err)
	}

	defer conn.Close()

	entry, err := svc.searchForUser(conn, username)
	if err != nil {
		return nil, apiErrors.NewUnauthorized(fmt.Sprintf("failed to query user: %s", err))
	}

	// Bind as the user to verify their password
	userDN := entry.DN
	err = conn.Bind(userDN, password)
	if err != nil {
		return nil, apiErrors.NewUnauthorized("invalid user credentials")
	}

	// create the token
	bearerToken, err := svc.token.createToken(UserDetails{
		Username: username,
		Assertions: map[string]string{
			"issuer": svc.bindURL,
			"userDN": userDN,
		},
	})
	if err != nil {
		return nil, apiErrors.NewInternalError(err)
	}

	return &models.TokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview",
		Status: &models.TokenReviewStatus{
			// Required: let the client know if the user has successfully authenticated
			Authenticated: true,

			// optional: add user information for the client
			User: &models.UserInfo{
				Username: username,
				Groups: []string{
					userDN,
				},
			},
		},
		// Required: return the token for the client
		Spec: &models.TokenReviewSpec{
			Token: bearerToken,
		},
	}, nil
}

// Authenticate authenticates a bearer token
// returns user details extracted from the token
// returns true if the token is valid, false if not
func (svc *LdapService) Authenticate(bearerToken string) (*models.TokenReviewRequest, error) {
	details, err := svc.token.verifyToken(bearerToken)
	if err != nil {
		return nil, apiErrors.NewUnauthorized(fmt.Sprintf("failed to validate token: %s", err))
	}

	return &models.TokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview",
		Status: &models.TokenReviewStatus{
			Authenticated: true,
			User: &models.UserInfo{
				Username: details.Username,
			},
		},
	}, nil
}

// connection returns the bindURL ldap server
func (svc *LdapService) connection() (*ldap.Conn, error) {

	// use tls connection
	if svc.tlsConfig != nil && svc.allowInsecure == false {
		return ldap.DialTLS("tcp", svc.bindURL, svc.tlsConfig)
	}

	// use non tls connection if tls config is missing or allowInsecure option is true
	if svc.tlsConfig == nil || svc.allowInsecure {
		return ldap.Dial("tcp", svc.bindURL)
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("error: ldap tls configuration is incomplete")
}

func (svc *LdapService) searchForUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	if conn == nil {
		return nil, errors.New("connect to the server before performing a query")
	}

	// The username and password we want to check
	bindusername := svc.bindDN
	bindpassword := svc.bindPassword

	// First bind with a read only user
	err := conn.Bind(bindusername, bindpassword)
	if err != nil {
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		svc.queryDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		10,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		svc.selectors,
		nil)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, errors.New("user does not exists or there is more than one")
	}

	return sr.Entries[0], nil
}

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

package main

import (
	"fmt"
	ldap "github.com/cbrgm/authproxy-ldap/ldap"
	"github.com/cbrgm/authproxy-ldap/provider"
	"github.com/cbrgm/authproxy/authproxy"
	"github.com/urfave/cli"
	"os"
)

const (

	// api
	FlagHTTPAddr        = "http-addr"
	FlagHTTPPrivateAddr = "http-internal-addr"

	// tls
	FlagTLSCert     = "tls-cert"
	FlagTLSKey      = "tls-key"
	FlagTLSClientCA = "tls-ca-cert"

	// ldap
	FlagBindURL         = "ldap-addr"
	FlagBindDN          = "ldap-bind-dn"
	FlagBindPassword    = "ldap-bind-pass"
	FlagBaseDN          = "ldap-base-dn"
	FlagQueryDN         = "ldap-query-dn"
	FlagAllowInsecure   = "ldap-allow-insecure"
	FlagTokenExpiration = "ldap-token-expiration"

	// logging
	FlagLogJSON  = "log-json"
	FlagLogLevel = "log-level"

	EnvHTTPAddr        = "PROXY_HTTP_ADDR"
	EnvHTTPPrivateAddr = "PROXY_HTTP_PRIVATE_ADDR"
	EnvTLSCert         = "PROXY_TLS_CERT"
	EnvTLSKey          = "PROXY_TLS_KEY"
	EnvTLSClientCA     = "PROXY_TLS_CA"
	EnvBindURL         = "LDAP_HTTP_ADDR"
	EnvBindDN          = "LDAP_BIND_DN"
	EnvBindPassword    = "LDAP_BIND_PW"
	EnvQueryDN         = "LDAP_QUERY_DN"
	EnvBaseDN          = "LDAP_BASE_DN"
	EnvAllowInsecure   = "LDAP_ALLOW_INSECURE"
	EnvTokenExpiration = "LDAP_TOKEN_EXPIRATION"
	EnvLogJSON         = "PROXY_LOG_JSON"
	EnvLogLevel        = "PROXY_LOG_LEVEL"
)

type apiConf struct {
	HTTPAddr        string
	HTTPPrivateAddr string
	TLSCert         string
	TLSKey          string
	TLSClientCA     string
	BindURL         string
	BindDN          string
	BindPassword    string
	BaseDN          string
	QueryDN         string
	AllowInsecure   bool
	TokenExpiration int
	LogJSON         bool
	LogLevel        string
}

var (
	apiConfig = apiConf{}

	apiFlags = []cli.Flag{
		cli.StringFlag{
			Name:        FlagHTTPAddr,
			EnvVar:      EnvHTTPAddr,
			Usage:       "The address the proxy runs on",
			Value:       ":6660",
			Destination: &apiConfig.HTTPAddr,
		},
		cli.StringFlag{
			Name:        FlagHTTPPrivateAddr,
			EnvVar:      EnvHTTPPrivateAddr,
			Usage:       "The address authproxy runs a http server only for internal access",
			Value:       ":6661",
			Destination: &apiConfig.HTTPPrivateAddr,
		},
		cli.StringFlag{
			Name:        FlagTLSKey,
			EnvVar:      EnvTLSKey,
			Usage:       "The tls key file to be used",
			Destination: &apiConfig.TLSKey,
		},
		cli.StringFlag{
			Name:        FlagTLSCert,
			EnvVar:      EnvTLSCert,
			Usage:       "The tls cert file to be used",
			Destination: &apiConfig.TLSCert,
		},
		cli.StringFlag{
			Name:        FlagTLSClientCA,
			EnvVar:      EnvTLSClientCA,
			Usage:       "The tls client ca file to be used",
			Destination: &apiConfig.TLSClientCA,
		},
		cli.BoolFlag{
			Name:        FlagLogJSON,
			EnvVar:      EnvLogJSON,
			Usage:       "The logger will log json lines",
			Destination: &apiConfig.LogJSON,
		},
		cli.StringFlag{
			Name:        FlagLogLevel,
			EnvVar:      EnvLogLevel,
			Usage:       "The log level to filter logs with before printing",
			Value:       "info",
			Destination: &apiConfig.LogLevel,
		},
		cli.StringFlag{
			Name:        FlagBindURL,
			EnvVar:      EnvBindURL,
			Usage:       "The ldap server address to use as backend",
			Value:       ":7636",
			Destination: &apiConfig.BindURL,
		},
		cli.StringFlag{
			Name:        FlagBindDN,
			EnvVar:      EnvBindDN,
			Usage:       "The read-only user to be used for queries",
			Value:       "cn=readonly,dc=example,dc=org",
			Destination: &apiConfig.BindDN,
		},
		cli.StringFlag{
			Name:        FlagBindPassword,
			EnvVar:      EnvBindPassword,
			Usage:       "The read-only user password to be used for queries",
			Value:       "secret",
			Destination: &apiConfig.BindPassword,
		},
		cli.StringFlag{
			Name:        FlagBaseDN,
			EnvVar:      EnvBaseDN,
			Usage:       "The base dn",
			Value:       "cn=students,dc=example,dc=org",
			Destination: &apiConfig.BaseDN,
		},
		cli.StringFlag{
			Name:        FlagQueryDN,
			EnvVar:      EnvQueryDN,
			Usage:       "The query dn",
			Value:       "uid",
			Destination: &apiConfig.QueryDN,
		},
		cli.IntFlag{
			Name:        FlagTokenExpiration,
			EnvVar:      EnvTokenExpiration,
			Usage:       "The token expiration in minutes",
			Value:       720,
			Destination: &apiConfig.TokenExpiration,
		},
		cli.BoolFlag{
			Name:        FlagAllowInsecure,
			EnvVar:      EnvAllowInsecure,
			Usage:       "Disable ldap tls encryption",
			Destination: &apiConfig.AllowInsecure,
		},
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "authproxy-ldap"
	app.Usage = "kubernetes compatible webhook authentication proxy for ldap"
	app.Action = apiAction
	app.Flags = apiFlags

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("failed to run api: %s", err)
		os.Exit(1)
	}
}

func apiAction(c *cli.Context) error {

	svc, err := ldap.NewLdapService(ldap.LdapServiceConfig{
		BindURL:         apiConfig.BindURL,
		BindDN:          apiConfig.BindDN,
		BindPassword:    apiConfig.BindPassword,
		BaseDN:          apiConfig.BaseDN,
		QueryDN:         apiConfig.QueryDN,
		AllowInsecure:   apiConfig.AllowInsecure,
		TLSCert:         apiConfig.TLSCert,
		TLSKey:          apiConfig.TLSKey,
		TLSClientCA:     apiConfig.TLSClientCA,
		TokenExpiration: apiConfig.TokenExpiration,
	})

	if err != nil {
		return err
	}

	// initialize the authentication prv
	prv := provider.NewLdapProvider(svc)

	// add the prv and proxyConfig to the proxy
	prx := authproxy.NewWithProvider(prv, authproxy.ProxyConfig{
		HTTPAddr:        apiConfig.HTTPAddr,
		HTTPPrivateAddr: apiConfig.HTTPPrivateAddr,
		TLSKey:          apiConfig.TLSKey,
		TLSCert:         apiConfig.TLSCert,
		TLSClientCA:     apiConfig.TLSClientCA,
		LogJSON:         apiConfig.LogJSON,
		LogLevel:        apiConfig.LogLevel,
	})

	if err := prx.ListenAndServe(); err != nil {
		fmt.Printf("something went wrong: %s", err)
		os.Exit(1)
	}
	return nil
}

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

package provider

import (
	"github.com/cbrgm/authproxy-ldap/ldap"
	"github.com/cbrgm/authproxy/api/v1/models"
)

// LdapProvider represents a fake identity provider
type LdapProvider struct {
	Name    string
	Service ldap.LdapService
}

// NewLdapProvider returns a new fake identity provider
func NewLdapProvider(svc *ldap.LdapService) *LdapProvider {
	return &LdapProvider{
		Name:    "ldap-authenticator",
		Service: *svc,
	}
}

// Login implements login functionality for user foo and password bar
func (provider *LdapProvider) Login(username, password string) (*models.TokenReviewRequest, error) {
	return provider.Service.Login(username, password)
}

// Authenticate implements bearer token validation functionalities
func (provider *LdapProvider) Authenticate(bearerToken string) (*models.TokenReviewRequest, error) {
	return provider.Service.Authenticate(bearerToken)
}

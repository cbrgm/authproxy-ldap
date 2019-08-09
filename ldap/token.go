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
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type TokenService struct {
	verifyKey       *rsa.PublicKey
	signKey         *rsa.PrivateKey
	tokenExpiration int
}

type UserDetails struct {
	Username   string
	Assertions map[string]string
}

// TokenClaim contains information about the authenticated user
type TokenClaim struct {
	*jwt.StandardClaims
	TokenType   string
	UserDetails UserDetails
}

func NewTokenService(tlsKey string, tlsCert string, tokenExpiration int) (*TokenService, error) {

	if tlsKey == "" || tlsCert == "" {
		return nil, fmt.Errorf("invalid config: no tlskey or tlscert provided")
	}

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return nil, err
	}

	sign := cert.PrivateKey.(*rsa.PrivateKey)
	verify := sign.Public().(*rsa.PublicKey)

	return &TokenService{
		verifyKey:       verify,
		signKey:         sign,
		tokenExpiration: tokenExpiration,
	}, nil
}

func (svc *TokenService) createToken(details UserDetails) (string, error) {
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	// set our claims
	t.Claims = &TokenClaim{
		StandardClaims: &jwt.StandardClaims{
			// set the expire time
			// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(svc.tokenExpiration)).Unix(),
		},
		TokenType:   "level1",
		UserDetails: details,
	}

	// Create token string
	return t.SignedString(svc.signKey)
}

func (svc *TokenService) verifyToken(bearerToken string) (UserDetails, error) {
	token, err := jwt.ParseWithClaims(bearerToken, &TokenClaim{}, func(token *jwt.Token) (interface{}, error) {

		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return svc.verifyKey, nil
	})
	if err != nil {
		return UserDetails{}, err
	}
	claims := token.Claims.(*TokenClaim)
	return claims.UserDetails, nil
}

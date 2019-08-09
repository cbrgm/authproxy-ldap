package ldap

import (
	"testing"
)

func TestNewTokenService(t *testing.T) {
	_, err := NewTokenService("./client.key", "./client.crt", 1)
	if err != nil {
		t.Errorf("failed to create TokenService: %s", err)
	}
}

func TestCreateToken(t *testing.T) {
	svc, err := NewTokenService("./client.key", "./client.crt", 1)
	if err != nil {
		t.Errorf("failed to create TokenService: %s", err)
	}

	token, err := svc.createToken(UserDetails{
		Username: "foo",
		Assertions: map[string]string{
			"issuer": "test",
		},
	})
	if err != nil {
		t.Errorf("failed to create token: %s", err)
	}

	if token == "" {
		t.Errorf("token was empty: %s", err)
	}
}

func TestVerifyToken(t *testing.T) {
	svc, err := NewTokenService("./client.key", "./client.crt", 1)
	if err != nil {
		t.Errorf("failed to create TokenService: %s", err)
	}

	token, err := svc.createToken(UserDetails{
		Username: "foo",
		Assertions: map[string]string{
			"issuer": "test",
		},
	})

	if err != nil {
		t.Errorf("failed to create token: %s", err)
	}

	if token == "" {
		t.Errorf("token was empty: %s", err)
	}

	details, err := svc.verifyToken(token)
	if err != nil {
		t.Errorf("error: %s", err)
	}

	if details.Username != "foo" {
		t.Errorf("error: want: foo, got: %s", details.Username)
	}
}

func TestVerifyTokenInvalid(t *testing.T) {
	svc, err := NewTokenService("./client.key", "./client.crt", 1)
	if err != nil {
		t.Errorf("failed to create TokenService: %s", err)
	}

	token, err := svc.createToken(UserDetails{
		Username: "foo",
		Assertions: map[string]string{
			"issuer": "test",
		},
	})
	if err != nil {
		t.Errorf("failed to create token: %s", err)
	}

	if token == "" {
		t.Errorf("token was empty: %s", err)
	}

	// this token is invalid
	token = token + "fail"

	details, err := svc.verifyToken(token)
	if err == nil {
		t.Errorf("error: %s", err)
	}

	if details.Username != "" {
		t.Errorf("error: want: nothing, got: %s", details.Username)
	}
}

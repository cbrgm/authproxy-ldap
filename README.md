# authproxy-ldap

**Kubernetes compatible [authproxy](https://github.com/cbrgm/authproxy) implementation for LDAP**

[![](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/cbrgm/authproxy/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/cbrgm/authproxy)](https://goreportcard.com/report/github.com/cbrgm/authproxy)


***Build from source***:

```
make build
```


## Trying it out:

Start docker-compose:

```
docker-compose up -d 
```

login, receive a bearer token and validate the token against [localhost:6660/v1](https://localhost:6661/v1):

```bash
# login as user foo with password bar
TOKEN=$(curl -X POST --user foo:bar --cacert ./cmd/ca.crt --key ./cmd/client.key --cert ./cmd/client.crt  https://localhost:6660/v1/login | jq -r '.Spec.Token')

# validate the bearer token
curl \
  -X POST \
  --cacert ./cmd/ca.crt \
  --key ./cmd/client.key \
  --cert ./cmd/client.crt \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer ${TOKEN}" \
  --data '{
    "apiVersion": "authentication.k8s.io/v1beta1",
    "kind": "TokenReview",
    "spec": {
      "token": "'"${TOKEN}"'"
    }
  }' \
  https://localhost:6660/v1/authenticate

```
Result:

```
{
  "kind": "TokenReview"
  "APIVersion": "authentication.k8s.io/v1beta1",
  "Status": {
    "Authenticated": true,
    "User": {
      "Groups": null,
      "Username": "foo"
    }
  },
}

```

also check out the Prometheus metrics endpoint [localhost:6661/metrics](localhost:6661/metrics):

```
# HELP authproxy_authentication_login_attempts_total Number of login attempts that succeeded and failed
# TYPE authproxy_authentication_login_attempts_total counter
authproxy_authentication_login_attempts_total{status="failure"} 0
authproxy_authentication_login_attempts_total{status="success"} 1
```

## Standalone usage


```
./cmd/authproxy-ldap \
   --tls-key ./cmd/server.key \
   --tls-cert ./cmd/server.crt \
   --tls-ca-cert ./cmd/ca.crt \
   --log-level debug \
   --ldap-addr localhost:389 \
   --ldap-bind-dn "cn=readonly,dc=example,dc=org" \
   --ldap-bind-pass readonly \
   --ldap-query-dn "cn=students,dc=example,dc=org" \
   --ldap-allow-insecure=true
```

***Docker usage***

```
docker run

```

***authproxy-ldap configuration explained:***

```
GLOBAL OPTIONS:
   --http-addr value           The address the proxy runs on (default: ":6660") [$API_HTTP_ADDR]
   --http-internal-addr value  The address authproxy runs a http server only for internal access (default: ":6661")
   --tls-key value             The tls key file to be used
   --tls-cert value            The tls cert file to be used
   --tls-ca-cert value         The tls client ca file to be used
   --log-json                  The logger will log json lines [$API_LOG_JSON]
   --log-level value           The log level to filter logs with before printing (default: "info") [$API_LOG_LEVEL]
   --ldap-addr value           The ldap server address to use as backend (default: ":7636")
   --ldap-bind-dn value        The read-only user to be used for queries (default: "authuser")
   --ldap-bind-pass value      The read-only user password to be used for queries (default: "secret")
   --ldap-query-dn value       The query dn (default: ":7636")
   --ldap-allow-insecure       Disable ldap tls encryption
   --help, -h                  show help
   --version, -v               print the version
```
***Authproxy API Endpoints:***

| Endpoints       | Type     | Description                                                            |
|-----------------|----------|------------------------------------------------------------------------|
| v1/login        | public   | Issues bearer tokens for clients                                       |
| v1/authenticate | public   | Validates bearer tokens and provides authentication                    |
| /metrics        | internal | Provides metrics to be observed by Prometheus                          |
| /healthz         | internal | Indicates wether authproxy is healthy or not (for use with Kubernetes) |


## Credit & License

authproxy-ldap is open-source and is developed under the terms of the [Apache 2.0 License](https://github.com/cbrgm/authproxy/blob/master/LICENSE).

Maintainer of this repository is:

-   [@cbrgm](https://github.com/cbrgm) | Christian Bargmann <mailto:chris@cbrgm.net>

Please refer to the git commit log for a complete list of contributors.

## Contributing

See the [Contributing Guide](https://github.com/cbrgm/authproxy/blob/master/CONTRIBUTING.md).
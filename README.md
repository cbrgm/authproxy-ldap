# authproxy-ldap

**Kubernetes compatible [authproxy](https://github.com/cbrgm/authproxy) implementation for LDAP**

[![](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/cbrgm/authproxy/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/cbrgm/authproxy)](https://goreportcard.com/report/github.com/cbrgm/authproxy)


***Build from source***:

```
make build
```

## Docker / Podman

```
docker run --rm -it -p 6660:6660 -p 6661:6661 \
     && -e PROXY_HTTP_ADDR: "0.0.0.0:6660" \
     && -e PROXY_HTTP_PRIVATE_ADDR: "0.0.0.0:6661" \
     && -e ROXY_TLS_CERT: "/certs/server.crt" \
     && -e PROXY_TLS_KEY: "/certs/server.key" \
     && -e PROXY_TLS_CA: "/certs/ca.crt" \
     && -e LDAP_HTTP_ADDR: "openldap:389" \
     && -e LDAP_BIND_DN: "cn=readonly,dc=example,dc=org" \
     && -e LDAP_BIND_PW: "readonly" \
     && -e LDAP_QUERY_DN: "cn=students,dc=example,dc=org" \
     && -e LDAP_ALLOW_INSECURE=true: \
     && -e LDAP_TOKEN_EXPIRATION: "720" # 12 hours \
     && -e PROXY_LOG_JSON=false: \
     && -e PROXY_LOG_LEVEL: "debug" \
     && -v $(pwd)/certs:/certs \
     cbrgm/authproxy-ldap:latest
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
   --ldap-base-dn "ou=example" \
   --ldap-query-dn "cn=students,dc=example,dc=org" \
   --ldap-allow-insecure=true
```

## CLI Flags 

```
   --http-addr value              The address the proxy runs on (default: ":6660") [$PROXY_HTTP_ADDR]
   --http-internal-addr value     The address authproxy runs a http server only for internal access (default: ":6661") [$PROXY_HTTP_PRIVATE_ADDR]
   --tls-key value                The tls key file to be used [$PROXY_TLS_KEY]
   --tls-cert value               The tls cert file to be used [$PROXY_TLS_CERT]
   --tls-ca-cert value            The tls client ca file to be used [$PROXY_TLS_CA]
   --log-json                     The logger will log json lines [$PROXY_LOG_JSON]
   --log-level value              The log level to filter logs with before printing (default: "info") [$PROXY_LOG_LEVEL]
   --ldap-addr value              The ldap server address to use as backend (default: ":7636") [$LDAP_HTTP_ADDR]
   --ldap-bind-dn value           The read-only user to be used for queries (default: "authuser") [$LDAP_BIND_DN]
   --ldap-bind-pass value         The read-only user password to be used for queries (default: "secret") [$LDAP_BIND_PW]
   --ldap-base-dn value           The base dn (subtree) to search for results [$LDAP_BASE_DN]
   --ldap-query-dn value          The query dn [$LDAP_QUERY_DN]
   --ldap-token-expiration value  The token expiration in minutes (default: 720) [$LDAP_TOKEN_EXPIRATION]
   --ldap-allow-insecure          Disable ldap tls encryption [$LDAP_ALLOW_INSECURE]
   --help, -h                     show help
   --version, -v                  print the version
```

***Authproxy API Endpoints:***

| Endpoints       | Type     | Description                                                            |
|-----------------|----------|------------------------------------------------------------------------|
| v1/login        | public   | Issues bearer tokens for clients                                       |
| v1/authenticate | public   | Validates bearer tokens and provides authentication                    |
| /metrics        | internal | Provides metrics to be observed by Prometheus                          |
| /healthz        | internal | Indicates wether authproxy is healthy or not (for use with Kubernetes) |

## Sample usage:

Start docker-compose:

```bash
# Create self-signed certs for tls support
make gencerts

# Launch ldap, phpldamadmin and authproxy
cd deployment/docker-compose
docker-compose up
```

Create a posix group "students" and a sample user foo with password bar at [localhost:8080](http://localhost:8080):

* Login: cn=admin,dc=example,dc=org
* Password: verysecret

login, receive a bearer token and validate the token against [localhost:6660/v1](https://localhost:6660/v1):

```bash
# login as user admin with password verysecret and receive a bearer token
TOKEN=$(curl -X POST --user fbar:bar --cacert ../../certs/ca.crt --key ../../certs/client.key --cert ../../certs/client.crt  https://localhost:6660/v1/login | jq -r '.Spec.Token')

# validate the bearer token
curl \
  -X POST \
  --cacert ../../certs/ca.crt \
  --key ../../certs/client.key \
  --cert ../../certs/client.crt \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer ${TOKEN}" \
  --data '{
    "apiVersion": "authentication.k8s.io/v1beta1",
    "kind": "TokenReview",
    "spec": {
      "token": "'"${TOKEN}"'"
    }
  }' \
  https://localhost:6660/v1/authenticate | jq .

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

## Credit & License

authproxy-ldap is open-source and is developed under the terms of the [Apache 2.0 License](https://github.com/cbrgm/authproxy/blob/master/LICENSE).

Maintainer of this repository is:

-   [@cbrgm](https://github.com/cbrgm) | Christian Bargmann <mailto:chris@cbrgm.net>

Please refer to the git commit log for a complete list of contributors.

## Contributing

See the [Contributing Guide](https://github.com/cbrgm/authproxy/blob/master/CONTRIBUTING.md).
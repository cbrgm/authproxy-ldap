FROM alpine

COPY ./authproxy-ldap /usr/bin/authproxy-ldap
COPY ./server.crt /certs
COPY ./server.key /certs
COPY ./ca.crt /certs

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

EXPOSE 6660/tcp 6661/tcp

ENTRYPOINT ["/usr/bin/authproxy-ldap"]
FROM alpine

LABEL title="authproxy-ldap docker" \
    url1="https://cbrgm.net" \
    twitter="@chrisbargmann" \
    maintainer="Christian Bargmann" \
    version="1.0"

COPY ./authproxy-ldap /usr/bin/authproxy-ldap

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

EXPOSE 6660/tcp 6661/tcp

ENTRYPOINT ["/usr/bin/authproxy-ldap"]
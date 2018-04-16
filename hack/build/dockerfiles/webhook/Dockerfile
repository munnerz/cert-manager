FROM alpine:3.6

RUN apk add --no-cache ca-certificates
ADD cert-manager-webhook_linux_amd64 /usr/bin/webhook

ENTRYPOINT ["/usr/bin/webhook"]
ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/jetstack/cert-manager" \
      org.label-schema.license="Apache-2.0"

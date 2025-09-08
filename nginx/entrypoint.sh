#!/usr/bin/env bash
set -euo pipefail

TEMPLATES_DIR=/etc/nginx/templates
CONF_DIR=/etc/nginx/conf.d
CERT_DIR=/etc/letsencrypt/live
WEBROOT=/var/www/certbot

NGINX_HOST="${NGINX_HOST:-example.com}"
CORE_UPSTREAM="${CORE_UPSTREAM:-http://core:8080}"

mkdir -p "$CONF_DIR" "$WEBROOT"

if [[ -f "$CERT_DIR/$NGINX_HOST/fullchain.pem" && -f "$CERT_DIR/$NGINX_HOST/privkey.pem" ]]; then
  echo "SSL cert found for $NGINX_HOST, enabling HTTPS with redirect"
  envsubst '$NGINX_HOST $CORE_UPSTREAM' < "$TEMPLATES_DIR/http_redirect.conf.template" > "$CONF_DIR/00-http.conf"
  envsubst '$NGINX_HOST $CORE_UPSTREAM' < "$TEMPLATES_DIR/https.conf.template" > "$CONF_DIR/10-https.conf"
else
  echo "No SSL cert for $NGINX_HOST, starting HTTP proxy only"
  envsubst '$NGINX_HOST $CORE_UPSTREAM' < "$TEMPLATES_DIR/http_proxy.conf.template" > "$CONF_DIR/00-http.conf"
fi

exec nginx -g 'daemon off;'

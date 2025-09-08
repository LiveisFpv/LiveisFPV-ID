FROM nginx:alpine
RUN apk add --no-cache bash gettext && rm -f /etc/nginx/conf.d/default.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY templates /etc/nginx/templates

CMD ["/entrypoint.sh"]


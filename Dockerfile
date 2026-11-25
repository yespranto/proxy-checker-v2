# syntax=docker/dockerfile:1
FROM php:8.3-apache

ENV DEBIAN_FRONTEND=noninteractive \
    APACHE_DOCUMENT_ROOT=/var/www/html/public \
    DB_PATH=/data/app.db

RUN apt-get update && apt-get install -y --no-install-recommends \
      sqlite3 curl tini ca-certificates \
 && a2enmod rewrite headers remoteip \
 && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
 && mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && rm -rf /var/lib/apt/lists/*

# Fail the build early if a required extension is missing
RUN php -m | grep -iE '^(curl|pdo_sqlite|sodium)$' | sort -u | wc -l | grep -q '^3$'

COPY docker/php.ini       /usr/local/etc/php/conf.d/zz-app.ini
COPY docker/apache.conf   /etc/apache2/conf-enabled/zz-app.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=www-data:www-data app/ /var/www/html/

RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /data && chown www-data:www-data /data

WORKDIR /var/www/html
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1/health.php || exit 1

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]

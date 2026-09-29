# Minimal PHP container for the OpenEMR transfer case (GHSA-q366-cv5v-83w8).
# The real OpenEMR checkout (at the vulnerable or patched commit) is
# bind-mounted at runtime, not baked into this image, so the same image
# serves both builds by swapping the mounted directory between runs.
FROM php:8.2-cli
RUN docker-php-ext-install mysqli
WORKDIR /var/www/openemr
EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000"]

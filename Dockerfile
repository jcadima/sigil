FROM php:8.3-cli
 
# Arguments defined in docker-compose.yml
ARG user=admin
ARG uid=1000

# Install only what SIGIL actually needs
RUN apt-get update && apt-get install -y \
    git \
    curl \
    zip \
    unzip \
    # needed by symfony/process to shell out to nginx -t
    nginx \
    libonig-dev \
    # needed for composer audit subprocess
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# PHP extensions SIGIL actually uses
# pdo_mysql / pdo_pgsql: only if you want live DB connection checks (optional at MVP)
# mbstring: needed by Composer itself
RUN docker-php-ext-install mbstring

# Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Create non-root user
RUN useradd -G www-data,root -u $uid -d /home/$user $user
RUN mkdir -p /home/$user/.composer && \
    chown -R $user:$user /home/$user

WORKDIR /var/www

USER $user
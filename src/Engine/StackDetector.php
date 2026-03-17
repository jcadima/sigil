<?php

declare(strict_types=1);

namespace Sigil\Engine;

use Sigil\Parsers\DockerConfig;
use Sigil\Parsers\EnvConfig;
use Sigil\ValueObjects\DatabaseType;
use Sigil\ValueObjects\StackProfile;

class StackDetector
{
    public function detect(string $path): StackProfile
    {
        $framework = $this->detectFramework($path);
        $webserver = $this->detectWebserver();
        $dbType    = $this->detectDatabase(null, null, $path);

        return new StackProfile($framework, $webserver, $dbType);
    }

    public function detectDatabase(?EnvConfig $env, ?DockerConfig $docker, string $path = ''): DatabaseType
    {
        // Priority 1: .env DB_CONNECTION
        if ($env !== null) {
            $connection = strtolower($env->get('DB_CONNECTION') ?? '');
            if ($connection === 'mysql') {
                // Could be MySQL or MariaDB — check docker for image hint
                if ($docker !== null) {
                    $type = $this->detectFromDocker($docker);
                    if ($type !== DatabaseType::UNKNOWN) {
                        return $type;
                    }
                }
                return DatabaseType::MYSQL;
            }
            if ($connection === 'pgsql' || $connection === 'postgresql') {
                return DatabaseType::POSTGRESQL;
            }
            if ($connection === 'mariadb') {
                return DatabaseType::MARIADB;
            }
        }

        // Priority 2: docker-compose image names
        if ($docker !== null) {
            $type = $this->detectFromDocker($docker);
            if ($type !== DatabaseType::UNKNOWN) {
                return $type;
            }
        }

        // Priority 3: process detection
        return $this->detectFromProcess();
    }

    private function detectFromDocker(DockerConfig $docker): DatabaseType
    {
        foreach ($docker->getServices() as $name => $svc) {
            $image = strtolower($svc['image'] ?? '');
            if (str_contains($image, 'mariadb')) {
                return DatabaseType::MARIADB;
            }
            if (str_contains($image, 'postgres') || str_contains($image, 'postgresql')) {
                return DatabaseType::POSTGRESQL;
            }
            if (str_contains($image, 'mysql')) {
                return DatabaseType::MYSQL;
            }
        }
        return DatabaseType::UNKNOWN;
    }

    private function detectFromProcess(): DatabaseType
    {
        // Check running processes
        $output = shell_exec('ps aux 2>/dev/null') ?? '';
        if (str_contains($output, 'mysqld') || str_contains($output, 'mariadbd')) {
            // MariaDB process is often called mariadbd in newer versions
            if (str_contains($output, 'mariadbd')) {
                return DatabaseType::MARIADB;
            }
            return DatabaseType::MYSQL;
        }
        if (str_contains($output, 'postgres')) {
            return DatabaseType::POSTGRESQL;
        }

        return DatabaseType::UNKNOWN;
    }

    private function detectFramework(string $path): string
    {
        // Laravel detection
        if (
            file_exists($path . '/artisan') &&
            file_exists($path . '/app/Http') &&
            file_exists($path . '/resources/views')
        ) {
            return 'laravel';
        }

        // Symfony detection
        if (file_exists($path . '/bin/console') && file_exists($path . '/config/bundles.php')) {
            return 'symfony';
        }

        // WordPress detection
        if (file_exists($path . '/wp-config.php') || file_exists($path . '/wp-login.php')) {
            return 'wordpress';
        }

        return 'generic';
    }

    private function detectWebserver(): string
    {
        if (file_exists('/etc/nginx/nginx.conf')) {
            return 'nginx';
        }
        if (file_exists('/etc/apache2/apache2.conf') || file_exists('/etc/httpd/httpd.conf')) {
            return 'apache';
        }
        return 'unknown';
    }
}

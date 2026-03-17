<?php

declare(strict_types=1);

namespace Sigil\Engine;

use Sigil\Rules\FindingCollection;
use Sigil\Rules\RuleInterface;
use Sigil\ValueObjects\DatabaseType;

class RuleEngine
{
    private array $ruleClasses = [];

    private const LARAVEL_RULES = [
        \Sigil\Rules\Laravel\AppDebugEnabledRule::class,
        \Sigil\Rules\Laravel\EnvPubliclyAccessibleRule::class,
        \Sigil\Rules\Laravel\AppKeyMissingRule::class,
        \Sigil\Rules\Laravel\SessionDriverInsecureRule::class,
        \Sigil\Rules\Laravel\CsrfMiddlewareMissingRule::class,
        \Sigil\Rules\Laravel\StorageWorldWritableRule::class,
        \Sigil\Rules\Laravel\NoRateLimitingRule::class,
        \Sigil\Rules\Laravel\ComposerVulnerabilitiesRule::class,
        \Sigil\Rules\Laravel\PhpVersionEolRule::class,
        \Sigil\Rules\Laravel\ExposePhpEnabledRule::class,
        \Sigil\Rules\Laravel\DisplayErrorsEnabledRule::class,
        \Sigil\Rules\Laravel\DisableFunctionsMissingRule::class,
    ];

    private const NGINX_RULES = [
        \Sigil\Rules\Nginx\ServerTokensOnRule::class,
        \Sigil\Rules\Nginx\MissingXFrameOptionsRule::class,
        \Sigil\Rules\Nginx\MissingXContentTypeRule::class,
        \Sigil\Rules\Nginx\MissingHstsRule::class,
        \Sigil\Rules\Nginx\MissingCspRule::class,
        \Sigil\Rules\Nginx\AutoindexEnabledRule::class,
        \Sigil\Rules\Nginx\WeakSslProtocolsRule::class,
        \Sigil\Rules\Nginx\WeakCiphersRule::class,
        \Sigil\Rules\Nginx\NoAuthRateLimitRule::class,
        \Sigil\Rules\Nginx\EnvNotBlockedRule::class,
        \Sigil\Rules\Nginx\BodySizeMissingRule::class,
    ];

    private const DOCKER_RULES = [
        \Sigil\Rules\Docker\ContainerRunsAsRootRule::class,
        \Sigil\Rules\Docker\DockerSocketMountedRule::class,
        \Sigil\Rules\Docker\LatestTagUsedRule::class,
        \Sigil\Rules\Docker\PrivilegedModeRule::class,
        \Sigil\Rules\Docker\NoResourceLimitsRule::class,
        \Sigil\Rules\Docker\SecretsInEnvRule::class,
        \Sigil\Rules\Docker\DatabasePortExposedRule::class,
        \Sigil\Rules\Docker\NoHealthCheckRule::class,
        \Sigil\Rules\Docker\NoDockerignoreRule::class,
    ];

    private const MYSQL_RULES = [
        \Sigil\Rules\MySQL\RootAsAppUserRule::class,
        \Sigil\Rules\MySQL\DatabasePortExposedRule::class,
        \Sigil\Rules\MySQL\NoSslRule::class,
        \Sigil\Rules\MySQL\GeneralLogEnabledRule::class,
        \Sigil\Rules\MySQL\EolVersionRule::class,
    ];

    private const MARIADB_RULES = [
        \Sigil\Rules\MariaDB\RootAsAppUserRule::class,
        \Sigil\Rules\MariaDB\DatabasePortExposedRule::class,
        \Sigil\Rules\MariaDB\NoSslRule::class,
        \Sigil\Rules\MariaDB\EolVersionRule::class,
        \Sigil\Rules\MariaDB\StrictModeRule::class,
    ];

    private const POSTGRESQL_RULES = [
        \Sigil\Rules\PostgreSQL\SuperuserAsAppUserRule::class,
        \Sigil\Rules\PostgreSQL\DatabasePortExposedRule::class,
        \Sigil\Rules\PostgreSQL\HbaTrustAuthRule::class,
        \Sigil\Rules\PostgreSQL\SslOffRule::class,
        \Sigil\Rules\PostgreSQL\AuditLoggingRule::class,
        \Sigil\Rules\PostgreSQL\EolVersionRule::class,
        \Sigil\Rules\PostgreSQL\HbaOpenAccessRule::class,
    ];

    public function __construct()
    {
        $this->ruleClasses = array_merge(
            self::LARAVEL_RULES,
            self::NGINX_RULES,
            self::DOCKER_RULES,
        );
    }

    public function loadRulePack(DatabaseType $dbType): void
    {
        $pack = match($dbType) {
            DatabaseType::MYSQL      => self::MYSQL_RULES,
            DatabaseType::MARIADB    => self::MARIADB_RULES,
            DatabaseType::POSTGRESQL => self::POSTGRESQL_RULES,
            DatabaseType::UNKNOWN    => [],
        };

        $this->ruleClasses = array_merge($this->ruleClasses, $pack);
    }

    public function run(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($this->ruleClasses as $ruleClass) {
            try {
                /** @var RuleInterface $rule */
                $rule     = new $ruleClass();
                $findings = $rule->evaluate($context);
                $collection->merge($findings);
            } catch (\Throwable $e) {
                // Rule failures are non-fatal — log and continue
                error_log("[SIGIL] Rule {$ruleClass} failed: " . $e->getMessage());
            }
        }

        return $collection;
    }

    public function getRuleClasses(): array
    {
        return $this->ruleClasses;
    }

    /**
     * Returns all known rules across all packs (for listing).
     */
    public function getAllRuleClasses(): array
    {
        return array_merge(
            self::LARAVEL_RULES,
            self::NGINX_RULES,
            self::DOCKER_RULES,
            self::MYSQL_RULES,
            self::MARIADB_RULES,
            self::POSTGRESQL_RULES,
        );
    }
}

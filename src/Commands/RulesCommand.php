<?php

declare(strict_types=1);

namespace Sigil\Commands;

use Sigil\Engine\RuleEngine;
use Sigil\Engine\ScanContext;
use Sigil\Rules\RuleInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class RulesCommand extends Command
{
    protected static $defaultName = 'rules';

    /** Static rule ID registry keyed by class name */
    private const RULE_IDS = [
        // Laravel
        \Sigil\Rules\Laravel\AppDebugEnabledRule::class          => 'L001',
        \Sigil\Rules\Laravel\EnvPubliclyAccessibleRule::class     => 'L002',
        \Sigil\Rules\Laravel\AppKeyMissingRule::class             => 'L003',
        \Sigil\Rules\Laravel\SessionDriverInsecureRule::class     => 'L004',
        \Sigil\Rules\Laravel\CsrfMiddlewareMissingRule::class     => 'L005',
        \Sigil\Rules\Laravel\StorageWorldWritableRule::class       => 'L006',
        \Sigil\Rules\Laravel\NoRateLimitingRule::class            => 'L007',
        \Sigil\Rules\Laravel\ComposerVulnerabilitiesRule::class   => 'L008',
        \Sigil\Rules\Laravel\PhpVersionEolRule::class             => 'L009',
        \Sigil\Rules\Laravel\ExposePhpEnabledRule::class          => 'L010',
        \Sigil\Rules\Laravel\DisplayErrorsEnabledRule::class      => 'L011',
        \Sigil\Rules\Laravel\DisableFunctionsMissingRule::class   => 'L012',
        // Nginx
        \Sigil\Rules\Nginx\ServerTokensOnRule::class              => 'N001',
        \Sigil\Rules\Nginx\MissingXFrameOptionsRule::class        => 'N002',
        \Sigil\Rules\Nginx\MissingXContentTypeRule::class         => 'N003',
        \Sigil\Rules\Nginx\MissingHstsRule::class                 => 'N004',
        \Sigil\Rules\Nginx\MissingCspRule::class                  => 'N005',
        \Sigil\Rules\Nginx\AutoindexEnabledRule::class            => 'N006',
        \Sigil\Rules\Nginx\WeakSslProtocolsRule::class            => 'N007',
        \Sigil\Rules\Nginx\WeakCiphersRule::class                 => 'N008',
        \Sigil\Rules\Nginx\NoAuthRateLimitRule::class             => 'N009',
        \Sigil\Rules\Nginx\EnvNotBlockedRule::class               => 'N010',
        \Sigil\Rules\Nginx\BodySizeMissingRule::class             => 'N011',
        // Docker
        \Sigil\Rules\Docker\ContainerRunsAsRootRule::class        => 'D001',
        \Sigil\Rules\Docker\DockerSocketMountedRule::class        => 'D002',
        \Sigil\Rules\Docker\LatestTagUsedRule::class              => 'D003',
        \Sigil\Rules\Docker\PrivilegedModeRule::class             => 'D004',
        \Sigil\Rules\Docker\NoResourceLimitsRule::class           => 'D005',
        \Sigil\Rules\Docker\SecretsInEnvRule::class               => 'D006',
        \Sigil\Rules\Docker\DatabasePortExposedRule::class        => 'D007',
        \Sigil\Rules\Docker\NoHealthCheckRule::class              => 'D008',
        \Sigil\Rules\Docker\NoDockerignoreRule::class             => 'D009',
        // MySQL
        \Sigil\Rules\MySQL\RootAsAppUserRule::class               => 'M001',
        \Sigil\Rules\MySQL\DatabasePortExposedRule::class         => 'M002',
        \Sigil\Rules\MySQL\NoSslRule::class                       => 'M003',
        \Sigil\Rules\MySQL\GeneralLogEnabledRule::class           => 'M004',
        \Sigil\Rules\MySQL\EolVersionRule::class                  => 'M005',
        // MariaDB
        \Sigil\Rules\MariaDB\RootAsAppUserRule::class             => 'MB001',
        \Sigil\Rules\MariaDB\DatabasePortExposedRule::class       => 'MB002',
        \Sigil\Rules\MariaDB\NoSslRule::class                     => 'MB003',
        \Sigil\Rules\MariaDB\EolVersionRule::class                => 'MB004',
        \Sigil\Rules\MariaDB\StrictModeRule::class                => 'MB005',
        // PostgreSQL
        \Sigil\Rules\PostgreSQL\SuperuserAsAppUserRule::class     => 'PG001',
        \Sigil\Rules\PostgreSQL\DatabasePortExposedRule::class    => 'PG002',
        \Sigil\Rules\PostgreSQL\HbaTrustAuthRule::class           => 'PG003',
        \Sigil\Rules\PostgreSQL\SslOffRule::class                 => 'PG004',
        \Sigil\Rules\PostgreSQL\AuditLoggingRule::class           => 'PG005',
        \Sigil\Rules\PostgreSQL\EolVersionRule::class             => 'PG006',
        \Sigil\Rules\PostgreSQL\HbaOpenAccessRule::class          => 'PG007',
    ];

    /** Human-readable descriptions keyed by class name */
    private const RULE_DESCRIPTIONS = [
        'L001' => 'APP_DEBUG=true exposes stack traces with credentials in production',
        'L002' => '.env file accessible via nginx (no deny rule)',
        'L003' => 'APP_KEY is missing or uses a default/weak value',
        'L004' => 'SESSION_DRIVER=file with world-readable storage/ directory',
        'L005' => 'VerifyCsrfToken middleware not registered',
        'L006' => 'storage/ directory has world-writable (0777) permissions',
        'L007' => 'No rate limiting on login/register routes',
        'L008' => 'Known vulnerable Composer packages detected',
        'L009' => 'PHP version has reached end-of-life',
        'L010' => 'expose_php=On leaks PHP version in HTTP headers',
        'L011' => 'display_errors=On shows PHP errors to end users',
        'L012' => 'disable_functions missing dangerous PHP functions',
        'N001' => 'server_tokens=on discloses Nginx version in headers',
        'N002' => 'Missing X-Frame-Options header (clickjacking risk)',
        'N003' => 'Missing X-Content-Type-Options header',
        'N004' => 'Missing HSTS header (SSL stripping risk)',
        'N005' => 'Missing Content-Security-Policy header',
        'N006' => 'autoindex=on exposes directory listings',
        'N007' => 'Weak TLS protocols enabled (TLSv1/TLSv1.1)',
        'N008' => 'Weak cipher suites in ssl_ciphers (RC4, DES, MD5)',
        'N009' => 'No rate limiting on auth/login locations',
        'N010' => 'No nginx block denying access to .env files',
        'N011' => 'client_max_body_size not configured',
        'D001' => 'Container runs as root (no USER directive)',
        'D002' => 'Docker socket mounted — gives container full host root',
        'D003' => 'Image uses :latest tag — builds not reproducible',
        'D004' => 'Container runs with privileged: true',
        'D005' => 'No resource limits (CPU/memory) on services',
        'D006' => 'Plaintext secrets in docker-compose environment',
        'D007' => 'Database port exposed on 0.0.0.0',
        'D008' => 'No healthcheck on web-facing service',
        'D009' => 'No .dockerignore file in project root',
        'M001' => 'Application uses MySQL root user',
        'M002' => 'MySQL port 3306 exposed on all interfaces',
        'M003' => 'MySQL SSL not configured',
        'M004' => 'MySQL general query log enabled in production',
        'M005' => 'MySQL version has reached end-of-life',
        'MB001' => 'Application uses MariaDB root user (password auth)',
        'MB002' => 'MariaDB port 3306 exposed on all interfaces',
        'MB003' => 'MariaDB SSL not configured',
        'MB004' => 'MariaDB version has reached end-of-life',
        'MB005' => 'MariaDB strict SQL mode not enabled',
        'PG001' => 'Application uses PostgreSQL superuser account',
        'PG002' => 'PostgreSQL port 5432 exposed on all interfaces',
        'PG003' => 'pg_hba.conf uses trust authentication',
        'PG004' => 'PostgreSQL SSL is disabled',
        'PG005' => 'PostgreSQL connection logging disabled',
        'PG006' => 'PostgreSQL version has reached end-of-life',
        'PG007' => 'pg_hba.conf allows open access from 0.0.0.0/0',
    ];

    protected function configure(): void
    {
        $this
            ->setName('rules')
            ->setDescription('List all available security rules')
            ->addOption('category', 'c', InputOption::VALUE_REQUIRED, 'Filter by category (laravel/nginx/docker/mysql/mariadb/postgresql)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $categoryFilter = strtolower((string) ($input->getOption('category') ?? ''));
        $engine         = new RuleEngine();
        $allClasses     = $engine->getAllRuleClasses();

        $output->writeln('');
        $output->writeln('<options=bold>SIGIL Security Rules</>');
        $output->writeln(str_repeat('─', 70));

        $byCategory = [];
        foreach ($allClasses as $ruleClass) {
            try {
                /** @var RuleInterface $rule */
                $rule     = new $ruleClass();
                $category = $rule->getCategory();

                if ($categoryFilter && $category !== $categoryFilter) {
                    continue;
                }

                $ruleId = self::RULE_IDS[$ruleClass] ?? '????';

                $byCategory[$category][] = [
                    'id'       => $ruleId,
                    'severity' => $rule->getSeverity(),
                    'fixable'  => $rule->canAutoFix(),
                    'desc'     => self::RULE_DESCRIPTIONS[$ruleId] ?? $rule->getRemediation()->instructions,
                ];
            } catch (\Throwable $e) {
                $output->writeln(sprintf('<error>Failed to load rule %s: %s</error>', $ruleClass, $e->getMessage()));
            }
        }

        if (empty($byCategory)) {
            $output->writeln('<comment>No rules found' . ($categoryFilter ? " for category: {$categoryFilter}" : '') . '.</comment>');
            return Command::SUCCESS;
        }

        foreach ($byCategory as $category => $rules) {
            $output->writeln('');
            $output->writeln(sprintf('<options=bold>  [ %s ]</>', strtoupper($category)));
            $output->writeln('');

            foreach ($rules as $ruleInfo) {
                $severity = $ruleInfo['severity'];
                $fixable  = $ruleInfo['fixable'] ? ' <info>[auto-fix]</info>' : '';

                $output->writeln(sprintf(
                    '  <options=bold>%-8s</> [<%s>%s</>]%s',
                    $ruleInfo['id'],
                    $severity->color(),
                    $severity->value,
                    $fixable,
                ));
                $output->writeln(sprintf('    %s', $ruleInfo['desc']));
                $output->writeln('');
            }
        }

        $total = array_sum(array_map('count', $byCategory));
        $output->writeln(str_repeat('─', 70));
        $output->writeln(sprintf('  Total: %d rule(s)', $total));
        $output->writeln('');

        return Command::SUCCESS;
    }
}

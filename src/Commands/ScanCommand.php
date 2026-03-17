<?php

declare(strict_types=1);

namespace Sigil\Commands;

use Sigil\Engine\RuleEngine;
use Sigil\Engine\ScanContext;
use Sigil\Engine\StackDetector;
use Sigil\Parsers\ComposerParser;
use Sigil\Parsers\Database\MyCnfParser;
use Sigil\Parsers\Database\PostgresConfigParser;
use Sigil\Parsers\DockerComposeParser;
use Sigil\Parsers\EnvParser;
use Sigil\Parsers\FilesystemParser;
use Sigil\Parsers\NginxParser;
use Sigil\Parsers\PhpIniParser;
use Sigil\Reporters\CliReporter;
use Sigil\Reporters\JsonReporter;
use Sigil\Reporters\PatchReporter;
use Sigil\ValueObjects\DatabaseType;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    protected function configure(): void
    {
        $this
            ->setName('scan')
            ->setDescription('Scan a project directory for security findings')
            ->addArgument('path', InputArgument::OPTIONAL, 'Project path to scan', getcwd())
            ->addOption('env', null, InputOption::VALUE_REQUIRED, 'Environment (production/staging/local)', 'production')
            ->addOption('stack', null, InputOption::VALUE_REQUIRED, 'Force stack detection (laravel/wordpress/generic)')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Output format (cli/json/patch)', 'cli')
            ->addOption('compat', null, InputOption::VALUE_NONE, 'Run in compatibility mode (less strict)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $projectPath = realpath((string) $input->getArgument('path')) ?: (string) $input->getArgument('path');
        $environment = (string) $input->getOption('env');
        $format      = strtolower((string) $input->getOption('output'));

        if ($format !== 'json') {
            $output->writeln(sprintf('<comment>Scanning: %s</comment>', $projectPath));
        }

        // Build scan context
        $context              = new ScanContext();
        $context->projectPath = $projectPath;
        $context->environment = $environment;

        // Parse .env
        $envParser        = new EnvParser();
        $context->env     = $envParser->parse($projectPath . '/.env');

        // Parse docker-compose (try local first)
        $dockerParser = new DockerComposeParser();
        foreach (['docker-compose-local.yml', 'docker-compose.yml', 'docker-compose.yaml'] as $dcFile) {
            $dcPath = $projectPath . '/' . $dcFile;
            if (file_exists($dcPath)) {
                $context->docker            = $dockerParser->parse($dcPath);
                $context->dockerComposePath = $dcPath;
                break;
            }
        }

        // Detect database type
        $detector       = new StackDetector();
        $profile        = $detector->detect($projectPath);
        $context->dbType = $detector->detectDatabase($context->env, $context->docker, $projectPath);

        // Parse Nginx config
        $nginxParser = new NginxParser();
        $nginxPaths  = $this->findNginxConfig($context);
        if ($nginxPaths) {
            $context->nginx          = $nginxParser->parse($nginxPaths);
            $context->nginxConfigPath = $nginxPaths;
        }

        // Parse php.ini
        $phpIniParser = new PhpIniParser();
        $phpIniPath   = $this->findPhpIni($context);
        if ($phpIniPath) {
            $context->phpIni    = $phpIniParser->parse($phpIniPath);
            $context->phpIniPath = $phpIniPath;
        }

        // Parse composer
        $composerParser   = new ComposerParser();
        $context->composer = $composerParser->parse($projectPath);

        // Parse filesystem
        $fsParser          = new FilesystemParser();
        $context->filesystem = $fsParser->parse($projectPath);

        // Parse database config
        $context->database = $this->parseDatabase($context);

        // Build rule engine and load DB pack
        $engine = new RuleEngine();
        $engine->loadRulePack($context->dbType);

        // Run rules
        $findings = $engine->run($context);

        // Select reporter
        $reporter = match($format) {
            'json'  => new JsonReporter($output),
            'patch' => new PatchReporter($output),
            default => new CliReporter($output),
        };

        $reporter->render($findings, $context);

        // Return non-zero if critical findings exist
        $critical = $findings->filterBySeverity(\Sigil\Rules\Severity::CRITICAL);
        return count($critical) > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    private function findNginxConfig(ScanContext $context): ?string
    {
        // Check docker-compose volume mounts for nginx config paths
        foreach ($context->docker->allVolumes() as $vol) {
            $volume = $vol['volume'];
            if (str_contains($volume, '/etc/nginx')) {
                // Extract host path
                $parts = explode(':', $volume);
                $host  = $parts[0] ?? '';
                $nginx = rtrim($host, '/') . '/nginx.conf';
                if (file_exists($nginx)) {
                    return $nginx;
                }
                $nginx = rtrim($host, '/') . '/sites-available/default';
                if (file_exists($nginx)) {
                    return $nginx;
                }
            }
        }

        // Standard paths
        $paths = [
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-available/default',
            '/etc/nginx/conf.d/default.conf',
        ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }

    private function findPhpIni(ScanContext $context): ?string
    {
        // Check docker-compose volume mounts
        foreach ($context->docker->allVolumes() as $vol) {
            $volume = $vol['volume'];
            if (str_contains($volume, '/etc/php')) {
                $parts    = explode(':', $volume);
                $host     = $parts[0] ?? '';
                $phpini   = $host . '/fpm/php.ini';
                if (file_exists($phpini)) {
                    return $phpini;
                }
            }
        }

        // Standard paths (check multiple PHP versions)
        $phpPaths = array_merge(
            glob('/etc/php/*/fpm/php.ini') ?: [],
            glob('/etc/php/*/cli/php.ini') ?: [],
            ['/usr/local/etc/php/php.ini', '/etc/php.ini'],
        );

        foreach ($phpPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }

    private function parseDatabase(ScanContext $context): \Sigil\Parsers\DatabaseConfig
    {
        $paths = match($context->dbType) {
            DatabaseType::MYSQL, DatabaseType::MARIADB => [
                '/etc/mysql/my.cnf',
                '/etc/mysql/mysql.conf.d/mysqld.cnf',
                '/etc/my.cnf',
            ],
            DatabaseType::POSTGRESQL => [
                '/etc/postgresql/postgresql.conf',
                '/var/lib/postgresql/data/postgresql.conf',
            ],
            default => [],
        };

        foreach ($paths as $path) {
            if (file_exists($path)) {
                if ($context->dbType === DatabaseType::POSTGRESQL) {
                    $parser = new PostgresConfigParser();
                } else {
                    $parser = new MyCnfParser();
                }
                return $parser->parse($path);
            }
        }

        return new \Sigil\Parsers\DatabaseConfig();
    }
}

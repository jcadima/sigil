<?php

declare(strict_types=1);

namespace Sigil\Commands;

use Sigil\Engine\RuleEngine;
use Sigil\Engine\ScanContext;
use Sigil\Engine\SnapshotManager;
use Sigil\Engine\StackDetector;
use Sigil\Parsers\ComposerParser;
use Sigil\Parsers\DockerComposeParser;
use Sigil\Parsers\EnvParser;
use Sigil\Parsers\FilesystemParser;
use Sigil\Parsers\NginxParser;
use Sigil\Parsers\PhpIniParser;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SnapshotCommand extends Command
{
    protected static $defaultName = 'snapshot';

    protected function configure(): void
    {
        $this
            ->setName('snapshot')
            ->setDescription('Capture a signed snapshot of current security findings')
            ->addArgument('path', InputArgument::OPTIONAL, 'Project path', getcwd());
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $projectPath = realpath((string) $input->getArgument('path')) ?: (string) $input->getArgument('path');

        $output->writeln(sprintf('<comment>Creating snapshot for: %s</comment>', $projectPath));

        $context = $this->buildContext($projectPath);
        $engine  = new RuleEngine();
        $engine->loadRulePack($context->dbType);
        $findings = $engine->run($context);

        $manager  = new SnapshotManager();
        $filepath = $manager->save($findings, $projectPath);

        $output->writeln(sprintf('<info>✓ Snapshot saved: %s</info>', $filepath));
        $output->writeln(sprintf('<info>  Score: %d/100 | Findings: %d</info>', $findings->calculateScore(), count($findings)));

        return Command::SUCCESS;
    }

    private function buildContext(string $projectPath): ScanContext
    {
        $context              = new ScanContext();
        $context->projectPath = $projectPath;

        $context->env = (new EnvParser())->parse($projectPath . '/.env');

        $dockerParser = new DockerComposeParser();
        foreach (['docker-compose-local.yml', 'docker-compose.yml'] as $f) {
            $p = $projectPath . '/' . $f;
            if (file_exists($p)) {
                $context->docker            = $dockerParser->parse($p);
                $context->dockerComposePath = $p;
                break;
            }
        }

        $detector        = new StackDetector();
        $context->dbType = $detector->detectDatabase($context->env, $context->docker);

        $nginxParser = new NginxParser();
        foreach (['/etc/nginx/nginx.conf', '/etc/nginx/sites-available/default'] as $p) {
            if (file_exists($p)) {
                $context->nginx          = $nginxParser->parse($p);
                $context->nginxConfigPath = $p;
                break;
            }
        }

        foreach (array_merge(glob('/etc/php/*/fpm/php.ini') ?: [], ['/etc/php.ini']) as $p) {
            if (file_exists($p)) {
                $context->phpIni    = (new PhpIniParser())->parse($p);
                $context->phpIniPath = $p;
                break;
            }
        }

        $context->composer   = (new ComposerParser())->parse($projectPath);
        $context->filesystem = (new FilesystemParser())->parse($projectPath);

        return $context;
    }
}

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

class DriftCommand extends Command
{
    protected static $defaultName = 'drift';

    protected function configure(): void
    {
        $this
            ->setName('drift')
            ->setDescription('Compare current findings against the last snapshot to detect drift')
            ->addArgument('path', InputArgument::OPTIONAL, 'Project path', getcwd());
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $projectPath = realpath((string) $input->getArgument('path')) ?: (string) $input->getArgument('path');

        $manager  = new SnapshotManager();
        $latest   = $manager->getLatestSnapshot();

        if ($latest === null) {
            $output->writeln('<error>No snapshot found. Run: sigil snapshot ' . $projectPath . '</error>');
            return Command::FAILURE;
        }

        $previous = $manager->load($latest);
        if ($previous === null) {
            $output->writeln('<error>Snapshot is corrupted or tampered. Create a new snapshot.</error>');
            return Command::FAILURE;
        }

        $output->writeln(sprintf('<comment>Comparing against snapshot: %s</comment>', $latest));
        $output->writeln(sprintf('<comment>Snapshot date: %s</comment>', date('Y-m-d H:i:s', $previous['timestamp'])));

        // Run current scan
        $context  = $this->buildContext($projectPath);
        $engine   = new RuleEngine();
        $engine->loadRulePack($context->dbType);
        $current  = $engine->run($context);

        $diff = $manager->diff($previous, $current);

        $output->writeln('');
        $output->writeln('<options=bold>Drift Report</>');
        $output->writeln(str_repeat('─', 50));

        // Score change
        $scoreBefore = $diff['score_before'];
        $scoreAfter  = $diff['score_after'];
        $scoreDelta  = $scoreAfter - $scoreBefore;
        $deltaColor  = $scoreDelta >= 0 ? 'info' : 'error';
        $deltaSign   = $scoreDelta >= 0 ? '+' : '';

        $output->writeln(sprintf(
            'Score: %d → %d (<%s>%s%d</>)',
            $scoreBefore,
            $scoreAfter,
            $deltaColor,
            $deltaSign,
            $scoreDelta,
        ));

        $output->writeln('');

        // New findings
        if (!empty($diff['new'])) {
            $output->writeln(sprintf('<error>New findings (%d):</error>', count($diff['new'])));
            foreach ($diff['new'] as $ruleId) {
                $output->writeln(sprintf('  + %s', $ruleId));
            }
            $output->writeln('');
        }

        // Resolved findings
        if (!empty($diff['resolved'])) {
            $output->writeln(sprintf('<info>Resolved findings (%d):</info>', count($diff['resolved'])));
            foreach ($diff['resolved'] as $ruleId) {
                $output->writeln(sprintf('  - %s', $ruleId));
            }
            $output->writeln('');
        }

        if (empty($diff['new']) && empty($diff['resolved'])) {
            $output->writeln('<info>No drift detected. Configuration is stable.</info>');
        }

        $stableCount = count($diff['stable']);
        if ($stableCount > 0) {
            $output->writeln(sprintf('<comment>%d finding(s) unchanged</comment>', $stableCount));
        }

        return empty($diff['new']) ? Command::SUCCESS : Command::FAILURE;
    }

    private function buildContext(string $projectPath): ScanContext
    {
        $context              = new ScanContext();
        $context->projectPath = $projectPath;
        $context->env         = (new EnvParser())->parse($projectPath . '/.env');

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

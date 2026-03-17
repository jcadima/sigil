<?php

declare(strict_types=1);

namespace Sigil\Commands;

use Sigil\Engine\RuleEngine;
use Sigil\Engine\ScanContext;
use Sigil\Rules\Finding;
use Sigil\Rules\RuleInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;

class EnforceCommand extends Command
{
    protected static $defaultName = 'enforce';

    protected function configure(): void
    {
        $this
            ->setName('enforce')
            ->setDescription('Apply auto-fixes for eligible findings')
            ->addArgument('path', InputArgument::OPTIONAL, 'Project path', getcwd())
            ->addOption('rule', null, InputOption::VALUE_REQUIRED, 'Only fix a specific rule ID')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Preview fixes without applying');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $projectPath = realpath((string) $input->getArgument('path')) ?: (string) $input->getArgument('path');
        $ruleFilter  = $input->getOption('rule');
        $dryRun      = (bool) $input->getOption('dry-run');

        $output->writeln(sprintf('<comment>Running enforce on: %s</comment>', $projectPath));

        // Run a full scan
        $scanCmd = new ScanCommand();
        $context = $this->buildContext($projectPath);
        $engine  = new RuleEngine();
        $engine->loadRulePack($context->dbType);
        $findings = $engine->run($context);

        // Filter to auto-fixable only
        $fixable = $findings->filterAutoFixable();

        if ($ruleFilter) {
            $filtered = new \Sigil\Rules\FindingCollection();
            foreach ($fixable as $f) {
                if ($f->ruleId === $ruleFilter) {
                    $filtered->add($f);
                }
            }
            $fixable = $filtered;
        }

        if ($fixable->isEmpty()) {
            $output->writeln('<info>No auto-fixable findings found.</info>');
            return Command::SUCCESS;
        }

        $output->writeln(sprintf('<info>Found %d auto-fixable finding(s):</info>', count($fixable)));
        foreach ($fixable as $finding) {
            $output->writeln(sprintf(
                '  [%s] %s — %s',
                $finding->severity->value,
                $finding->ruleId,
                $finding->message,
            ));
        }

        if ($dryRun) {
            $output->writeln('<comment>Dry run — no changes applied.</comment>');
            return Command::SUCCESS;
        }

        // Confirm with user
        /** @var QuestionHelper $helper */
        $helper   = $this->getHelper('question');
        $question = new ConfirmationQuestion(
            '<question>Apply these fixes? Files will be backed up to .sigil/backups/ first. [y/N]</question> ',
            false,
        );

        if (!$helper->ask($input, $output, $question)) {
            $output->writeln('<comment>Aborted.</comment>');
            return Command::SUCCESS;
        }

        // Apply fixes
        $ruleEngine = new RuleEngine();
        $ruleEngine->loadRulePack($context->dbType);

        $applied = 0;
        $failed  = 0;

        foreach ($fixable as $finding) {
            // Find the rule class and apply its fix
            foreach ($ruleEngine->getAllRuleClasses() as $ruleClass) {
                $rule = new $ruleClass();
                if (!($rule instanceof RuleInterface)) {
                    continue;
                }

                // Check if this rule would produce this finding
                $testFindings = $rule->evaluate($context);
                $matches      = false;
                foreach ($testFindings as $tf) {
                    if ($tf->ruleId === $finding->ruleId) {
                        $matches = true;
                        break;
                    }
                }

                if ($matches && $rule->canAutoFix()) {
                    $result = $rule->applyFix($context);
                    if ($result->success) {
                        $output->writeln(sprintf('<info>  ✓ Fixed %s: %s</info>', $finding->ruleId, $result->message));
                        if ($result->backupPath) {
                            $output->writeln(sprintf('    Backup: %s', $result->backupPath));
                        }
                        $applied++;
                    } else {
                        $output->writeln(sprintf('<error>  ✖ Failed %s: %s</error>', $finding->ruleId, $result->message));
                        $failed++;
                    }
                    break;
                }
            }
        }

        $output->writeln(sprintf('<info>Applied %d fix(es). Failed: %d</info>', $applied, $failed));
        return $failed > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    private function buildContext(string $projectPath): ScanContext
    {
        $context              = new ScanContext();
        $context->projectPath = $projectPath;

        $envParser        = new \Sigil\Parsers\EnvParser();
        $context->env     = $envParser->parse($projectPath . '/.env');

        $dockerParser = new \Sigil\Parsers\DockerComposeParser();
        foreach (['docker-compose-local.yml', 'docker-compose.yml'] as $dcFile) {
            $dcPath = $projectPath . '/' . $dcFile;
            if (file_exists($dcPath)) {
                $context->docker            = $dockerParser->parse($dcPath);
                $context->dockerComposePath = $dcPath;
                break;
            }
        }

        $detector        = new \Sigil\Engine\StackDetector();
        $context->dbType = $detector->detectDatabase($context->env, $context->docker);

        $phpIniParser = new \Sigil\Parsers\PhpIniParser();
        foreach (array_merge(glob('/etc/php/*/fpm/php.ini') ?: [], ['/etc/php.ini']) as $p) {
            if (file_exists($p)) {
                $context->phpIni    = $phpIniParser->parse($p);
                $context->phpIniPath = $p;
                break;
            }
        }

        $fsParser          = new \Sigil\Parsers\FilesystemParser();
        $context->filesystem = $fsParser->parse($projectPath);

        return $context;
    }
}

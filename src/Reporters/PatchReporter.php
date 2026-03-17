<?php

declare(strict_types=1);

namespace Sigil\Reporters;

use Sigil\Engine\ScanContext;
use Sigil\Fixers\NginxPatchGenerator;
use Sigil\Rules\FindingCollection;
use Symfony\Component\Console\Output\OutputInterface;

class PatchReporter implements ReporterInterface
{
    public function __construct(private OutputInterface $output)
    {
    }

    public function render(FindingCollection $findings, ScanContext $context): void
    {
        $generator = new NginxPatchGenerator();
        $nginx     = $findings->filterByCategory('nginx');

        if ($nginx->isEmpty()) {
            $this->output->writeln('<comment>No nginx findings to patch.</comment>');
            return;
        }

        $generated = 0;
        foreach ($nginx as $finding) {
            if ($finding->remediation->patchRef === null) {
                continue;
            }

            $result = $generator->generatePatch($finding, '# Patch for ' . $finding->ruleId . "\n");

            if ($result->success) {
                $this->output->writeln(sprintf('<info>✓ Generated patch for %s: %s</info>', $finding->ruleId, $result->backupPath));
                $generated++;
            } else {
                $this->output->writeln(sprintf('<error>✖ Failed to generate patch for %s: %s</error>', $finding->ruleId, $result->message));
            }
        }

        if ($generated === 0) {
            $this->output->writeln('<comment>No patchable nginx findings found.</comment>');
        } else {
            $this->output->writeln(sprintf('<info>Generated %d patch(es) in .sigil/patches/</info>', $generated));
        }
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Reporters;

use Sigil\Engine\ScanContext;
use Sigil\Rules\Finding;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Severity;
use Symfony\Component\Console\Output\OutputInterface;

class CliReporter implements ReporterInterface
{
    public function __construct(private OutputInterface $output)
    {
    }

    public function render(FindingCollection $findings, ScanContext $context): void
    {
        $score      = $findings->calculateScore();
        $scoreColor = $this->scoreColor($score);

        $this->output->writeln('');
        $this->output->writeln('<options=bold>SIGIL Infrastructure Hardening Report</>');
        $this->output->writeln(str_repeat('─', 60));
        $this->output->writeln(sprintf('  Project: <comment>%s</comment>', $context->projectPath));
        $this->output->writeln(sprintf('  Score:   <%s><options=bold>%d / 100</></>', $scoreColor, $score));
        $this->output->writeln(sprintf('  Findings: %d', count($findings)));
        $this->output->writeln(str_repeat('─', 60));

        if ($findings->isEmpty()) {
            $this->output->writeln('<info>  ✓ No findings. Your configuration looks good!</info>');
            $this->output->writeln('');
            return;
        }

        // Group by category
        $byCategory = [];
        foreach ($findings as $finding) {
            $byCategory[$finding->category][] = $finding;
        }

        foreach ($byCategory as $category => $categoryFindings) {
            $this->output->writeln('');
            $this->output->writeln(sprintf('<options=bold>  [ %s ]</>', strtoupper($category)));
            $this->output->writeln('');

            foreach ($categoryFindings as $finding) {
                $this->renderFinding($finding);
            }
        }

        $this->output->writeln('');
        $this->output->writeln(str_repeat('─', 60));
        $this->renderSummary($findings);
        $this->output->writeln('');
    }

    private function renderFinding(Finding $finding): void
    {
        $severityTag = $this->severityTag($finding->severity);
        $fixable     = $finding->canAutoFix ? ' <info>[auto-fix available]</info>' : '';

        $this->output->writeln(sprintf(
            '  ✖ [%s] <options=bold>%s</>%s',
            $severityTag,
            $finding->ruleId,
            $fixable,
        ));
        $this->output->writeln(sprintf('    %s', $finding->message));
        $this->output->writeln(sprintf('    <comment>File: %s</comment>', $finding->file));
        $this->output->writeln(sprintf('    <fg=gray>Fix: %s</>', $finding->remediation->instructions));
        $this->output->writeln('');
    }

    private function renderSummary(FindingCollection $findings): void
    {
        $counts = [];
        foreach (Severity::cases() as $sev) {
            $count = count($findings->filterBySeverity($sev));
            if ($count > 0) {
                $counts[] = sprintf('%s<%s>%d %s</>', '', $sev->color(), $count, $sev->value);
            }
        }

        if (!empty($counts)) {
            $this->output->writeln('  Breakdown: ' . implode('  ', $counts));
        }
    }

    private function severityTag(Severity $severity): string
    {
        $color = $severity->color();
        return sprintf('<%s>%s</>', $color, $severity->value);
    }

    private function scoreColor(int $score): string
    {
        if ($score >= 80) {
            return 'info';
        }
        if ($score >= 60) {
            return 'comment';
        }
        return 'error';
    }
}

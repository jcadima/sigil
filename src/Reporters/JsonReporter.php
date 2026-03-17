<?php

declare(strict_types=1);

namespace Sigil\Reporters;

use Sigil\Engine\ScanContext;
use Sigil\Rules\FindingCollection;
use Symfony\Component\Console\Output\OutputInterface;

class JsonReporter implements ReporterInterface
{
    public function __construct(private OutputInterface $output)
    {
    }

    public function render(FindingCollection $findings, ScanContext $context): void
    {
        $data = [
            'sigil_version' => '1.0.0',
            'generated_at'  => date('c'),
            'project'       => $context->projectPath,
            'score'         => $findings->calculateScore(),
            'total_findings' => count($findings),
            'findings'      => $findings->toArray(),
        ];

        $this->output->write(json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

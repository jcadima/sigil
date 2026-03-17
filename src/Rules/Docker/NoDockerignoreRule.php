<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoDockerignoreRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $dockerignore = $context->projectPath . '/.dockerignore';

        if (file_exists($dockerignore)) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'D009',
            Severity::LOW,
            $context->projectPath,
            0,
            'No .dockerignore file found. Sensitive files (.env, tests, git history) may be copied into images.',
            'docker',
            new Remediation(
                'Create a .dockerignore file to exclude sensitive and unnecessary files from Docker builds.',
                null,
                [
                    'Create .dockerignore with at least:',
                    '.env',
                    '.git',
                    'tests/',
                    'node_modules/',
                    '*.log',
                ],
            ),
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::LOW;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Create .dockerignore with .env, .git, tests/ excluded.');
    }
}

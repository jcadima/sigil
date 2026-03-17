<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class SessionDriverInsecureRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $driver  = strtolower($context->env->get('SESSION_DRIVER') ?? 'file');
        $storage = $context->projectPath . '/storage';

        if ($driver !== 'file') {
            return $this->pass();
        }

        // Check if storage is world-readable
        if (!$context->filesystem->isWorldReadable($storage)) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L004',
            Severity::HIGH,
            $context->projectPath . '/.env',
            0,
            'SESSION_DRIVER=file with world-readable storage directory exposes session data.',
            'laravel',
            new Remediation(
                'Use database or redis session driver, or restrict storage/ permissions.',
                null,
                [
                    'Option 1: Set SESSION_DRIVER=database and run php artisan session:table',
                    'Option 2: Set SESSION_DRIVER=redis',
                    'Option 3: chmod o-r storage/',
                ],
            ),
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::HIGH;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Change SESSION_DRIVER to database or redis.');
    }
}

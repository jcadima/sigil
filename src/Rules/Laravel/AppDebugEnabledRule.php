<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Fixers\EnvValueFixer;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;
use Sigil\ValueObjects\FixResult;

class AppDebugEnabledRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        if (strtolower($context->env->get('APP_DEBUG') ?? 'false') !== 'true') {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L001',
            Severity::CRITICAL,
            $context->projectPath . '/.env',
            0,
            'APP_DEBUG is set to true. Stack traces with credentials are leaked to end users.',
            'laravel',
            new Remediation(
                'Set APP_DEBUG=false in your .env file.',
                null,
                ['1. Edit .env', '2. Set APP_DEBUG=false', '3. Clear cache: php artisan config:cache'],
            ),
            true,
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Set APP_DEBUG=false in your .env file.');
    }

    public function canAutoFix(): bool
    {
        return true;
    }

    public function applyFix(ScanContext $context): FixResult
    {
        $fixer = new EnvValueFixer();
        return $fixer->fixValue($context->projectPath . '/.env', 'APP_DEBUG', 'false');
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Fixers\PhpIniValueFixer;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;
use Sigil\ValueObjects\FixResult;

class ExposePhpEnabledRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $value = $context->phpIni->get('', 'expose_php');

        // Default is On if not set
        if ($value !== null && strtolower($value) !== 'on') {
            return $this->pass();
        }

        if ($value === null) {
            // Check with ini_get() if running as PHP
            $live = ini_get('expose_php');
            if ($live !== false && $live === '0') {
                return $this->pass();
            }
        }

        return $this->fail($this->finding(
            'L010',
            Severity::LOW,
            $context->phpIniPath ?? 'php.ini',
            0,
            'expose_php is On. PHP version is disclosed in HTTP headers (X-Powered-By).',
            'laravel',
            new Remediation(
                'Set expose_php = Off in php.ini.',
                null,
                ['1. Edit php.ini', '2. Set expose_php = Off', '3. Restart PHP-FPM'],
            ),
            true,
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::LOW;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Set expose_php = Off in php.ini.');
    }

    public function canAutoFix(): bool
    {
        return true;
    }

    public function applyFix(ScanContext $context): FixResult
    {
        if ($context->phpIniPath === null) {
            return FixResult::failure('php.ini path not found.');
        }
        $fixer = new PhpIniValueFixer();
        return $fixer->fix($context->phpIniPath, 'expose_php', 'Off');
    }
}

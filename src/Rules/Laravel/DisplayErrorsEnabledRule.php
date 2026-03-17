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

class DisplayErrorsEnabledRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $value = $context->phpIni->get('', 'display_errors');

        if ($value === null) {
            return $this->pass(); // No php.ini found, can't check
        }

        if (strtolower($value) !== 'on' && $value !== '1') {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L011',
            Severity::LOW,
            $context->phpIniPath ?? 'php.ini',
            0,
            'display_errors is On. PHP errors including sensitive data may be shown to users.',
            'laravel',
            new Remediation(
                'Set display_errors = Off in php.ini.',
                null,
                ['1. Edit php.ini', '2. Set display_errors = Off', '3. Restart PHP-FPM'],
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
        return new Remediation('Set display_errors = Off in php.ini.');
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
        return $fixer->fix($context->phpIniPath, 'display_errors', 'Off');
    }
}

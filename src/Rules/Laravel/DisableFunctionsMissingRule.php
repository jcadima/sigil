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

class DisableFunctionsMissingRule extends AbstractRule
{
    private const DANGEROUS_FUNCTIONS = [
        'exec',
        'passthru',
        'shell_exec',
        'system',
        'proc_open',
        'popen',
        'curl_exec',
        'parse_ini_file',
        'show_source',
    ];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $value = $context->phpIni->get('', 'disable_functions');

        if ($value === null) {
            return $this->fail($this->finding(
                'L012',
                Severity::HIGH,
                $context->phpIniPath ?? 'php.ini',
                0,
                'disable_functions is not set. Dangerous PHP functions (exec, shell_exec, etc.) are available.',
                'laravel',
                new Remediation(
                    'Set disable_functions in php.ini to restrict dangerous functions.',
                    null,
                    ['Add: disable_functions = exec,passthru,shell_exec,system,proc_open,popen'],
                ),
                true,
            ));
        }

        $disabled = array_map('trim', explode(',', $value));
        $missing  = array_diff(self::DANGEROUS_FUNCTIONS, $disabled);

        if (empty($missing)) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L012',
            Severity::HIGH,
            $context->phpIniPath ?? 'php.ini',
            0,
            sprintf(
                'disable_functions is set but missing dangerous functions: %s',
                implode(', ', $missing),
            ),
            'laravel',
            new Remediation(
                'Add missing functions to disable_functions in php.ini.',
                null,
                ['Add to disable_functions: ' . implode(',', $missing)],
            ),
            true,
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
        return new Remediation('Set disable_functions = exec,passthru,shell_exec,system,proc_open,popen in php.ini.');
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
        $value = implode(',', self::DANGEROUS_FUNCTIONS);
        return $fixer->fix($context->phpIniPath, 'disable_functions', $value);
    }
}

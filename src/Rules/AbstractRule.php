<?php

declare(strict_types=1);

namespace Sigil\Rules;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

abstract class AbstractRule implements RuleInterface
{
    public function canAutoFix(): bool
    {
        return false;
    }

    public function applyFix(ScanContext $context): FixResult
    {
        return FixResult::failure('This rule does not support auto-fix.');
    }

    protected function finding(
        string      $ruleId,
        Severity    $severity,
        string      $file,
        int         $line,
        string      $message,
        string      $category,
        Remediation $remediation,
        bool        $canAutoFix = false,
    ): Finding {
        return new Finding($ruleId, $severity, $file, $line, $message, $category, $remediation, $canAutoFix);
    }

    protected function pass(): FindingCollection
    {
        return new FindingCollection();
    }

    protected function fail(Finding $finding): FindingCollection
    {
        $collection = new FindingCollection();
        $collection->add($finding);
        return $collection;
    }
}

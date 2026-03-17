<?php

declare(strict_types=1);

namespace Sigil\Rules;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

interface RuleInterface
{
    public function evaluate(ScanContext $context): FindingCollection;

    public function getSeverity(): Severity;

    public function getCategory(): string;

    public function getRemediation(): Remediation;

    public function canAutoFix(): bool;

    public function applyFix(ScanContext $context): FixResult;
}

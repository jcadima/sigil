<?php

declare(strict_types=1);

namespace Sigil\Reporters;

use Sigil\Engine\ScanContext;
use Sigil\Rules\FindingCollection;

interface ReporterInterface
{
    public function render(FindingCollection $findings, ScanContext $context): void;
}

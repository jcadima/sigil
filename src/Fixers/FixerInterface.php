<?php

declare(strict_types=1);

namespace Sigil\Fixers;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

interface FixerInterface
{
    public function apply(ScanContext $context): FixResult;
}

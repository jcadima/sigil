<?php

declare(strict_types=1);

namespace Sigil\Rules;

readonly class Remediation
{
    public function __construct(
        public string  $instructions,
        public ?string $patchRef    = null,
        public array   $manualSteps = [],
    ) {}
}

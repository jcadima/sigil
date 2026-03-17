<?php

declare(strict_types=1);

namespace Sigil\Rules;

readonly class Finding
{
    public function __construct(
        public string      $ruleId,
        public Severity    $severity,
        public string      $file,
        public int         $line,
        public string      $message,
        public string      $category,
        public Remediation $remediation,
        public bool        $canAutoFix = false,
    ) {}
}

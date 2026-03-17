<?php

declare(strict_types=1);

namespace Sigil\ValueObjects;

readonly class FixResult
{
    public function __construct(
        public bool    $success,
        public string  $message,
        public ?string $backupPath = null,
    ) {}

    public static function success(string $message, ?string $backupPath = null): self
    {
        return new self(true, $message, $backupPath);
    }

    public static function failure(string $message): self
    {
        return new self(false, $message);
    }
}

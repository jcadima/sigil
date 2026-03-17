<?php

declare(strict_types=1);

namespace Sigil\ValueObjects;

readonly class StackProfile
{
    public function __construct(
        public string       $framework,
        public string       $webserver,
        public DatabaseType $dbType,
    ) {}
}

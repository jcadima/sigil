<?php

declare(strict_types=1);

namespace Sigil\Parsers;

interface ParserInterface
{
    public function parse(string $path): mixed;
}

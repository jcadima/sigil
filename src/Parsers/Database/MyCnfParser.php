<?php

declare(strict_types=1);

namespace Sigil\Parsers\Database;

use Sigil\Parsers\DatabaseConfig;
use Sigil\Parsers\ParserInterface;

class MyCnfParser implements ParserInterface
{
    public function parse(string $path): DatabaseConfig
    {
        if (!file_exists($path)) {
            return new DatabaseConfig([], [], $path);
        }

        $result = @parse_ini_file($path, true, INI_SCANNER_RAW);

        if ($result === false) {
            $result = $this->manualParse($path);
        }

        return new DatabaseConfig($result, [], $path);
    }

    private function manualParse(string $path): array
    {
        $sections = [];
        $current  = '__global__';
        $lines    = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                continue;
            }

            if (preg_match('/^\[(.+)\]$/', $line, $m)) {
                $current = trim($m[1]);
                continue;
            }

            $pos = strpos($line, '=');
            if ($pos !== false) {
                $key                      = trim(substr($line, 0, $pos));
                $value                    = trim(substr($line, $pos + 1));
                $sections[$current][$key] = $value;
            } else {
                // Boolean flags like "skip-networking"
                $sections[$current][$line] = '1';
            }
        }

        return $sections;
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Parsers\Database;

use Sigil\Parsers\DatabaseConfig;
use Sigil\Parsers\ParserInterface;

class PostgresConfigParser implements ParserInterface
{
    public function parse(string $path): DatabaseConfig
    {
        $directives = [];
        $hbaRules   = [];

        if (file_exists($path)) {
            $directives = $this->parsePostgresConf($path);
        }

        // Also try to parse pg_hba.conf in same dir
        $hbaPath = dirname($path) . '/pg_hba.conf';
        if (file_exists($hbaPath)) {
            $hbaRules = $this->parseHba($hbaPath);
        }

        return new DatabaseConfig($directives, $hbaRules, $path);
    }

    private function parsePostgresConf(string $path): array
    {
        $data  = [];
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Strip inline comments
            $line = preg_replace('/#.*$/', '', $line);
            $line = trim($line ?? '');

            $pos = strpos($line, '=');
            if ($pos === false) {
                continue;
            }

            $key   = trim(substr($line, 0, $pos));
            $value = trim(substr($line, $pos + 1));

            // Strip quotes
            $value = trim($value, "'\"");

            $data[$key] = $value;
        }

        return $data;
    }

    private function parseHba(string $path): array
    {
        $rules = [];
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // pg_hba.conf columns: type database user address method [options]
            $cols = preg_split('/\s+/', $line, -1, PREG_SPLIT_NO_EMPTY);
            if (count($cols) < 4) {
                continue;
            }

            $rules[] = [
                'type'     => $cols[0] ?? '',
                'database' => $cols[1] ?? '',
                'user'     => $cols[2] ?? '',
                'address'  => $cols[3] ?? '',
                'method'   => $cols[4] ?? '',
            ];
        }

        return $rules;
    }
}

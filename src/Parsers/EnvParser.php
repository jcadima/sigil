<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class EnvParser implements ParserInterface
{
    public function parse(string $path): EnvConfig
    {
        $data = [];

        if (!file_exists($path)) {
            return new EnvConfig($data);
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return new EnvConfig($data);
        }

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip comments
            if (str_starts_with($line, '#')) {
                continue;
            }

            // Split on first = only
            $pos = strpos($line, '=');
            if ($pos === false) {
                continue;
            }

            $key   = trim(substr($line, 0, $pos));
            $value = trim(substr($line, $pos + 1));

            // Strip surrounding quotes
            if (strlen($value) >= 2) {
                $first = $value[0];
                $last  = $value[-1];
                if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                    $value = substr($value, 1, -1);
                }
            }

            if ($key !== '') {
                $data[$key] = $value;
            }
        }

        return new EnvConfig($data);
    }
}

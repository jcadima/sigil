<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class PhpIniParser implements ParserInterface
{
    public function parse(string $path): PhpIniConfig
    {
        if (!file_exists($path)) {
            return new PhpIniConfig();
        }

        // Try with sections first
        $result = @parse_ini_file($path, true, INI_SCANNER_RAW);

        if ($result === false) {
            // Fallback: manual parse
            $result = $this->manualParse($path);
        }

        return new PhpIniConfig($result);
    }

    private function manualParse(string $path): array
    {
        $sections = [];
        $current  = '__global__';
        $lines    = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, ';') || str_starts_with($line, '#')) {
                continue;
            }

            if (preg_match('/^\[(.+)\]$/', $line, $m)) {
                $current = trim($m[1]);
                continue;
            }

            $pos = strpos($line, '=');
            if ($pos !== false) {
                $key   = trim(substr($line, 0, $pos));
                $value = trim(substr($line, $pos + 1));
                // Strip inline comments
                if (($cpos = strpos($value, ';')) !== false) {
                    $value = trim(substr($value, 0, $cpos));
                }
                $sections[$current][$key] = $value;
            }
        }

        return $sections;
    }
}

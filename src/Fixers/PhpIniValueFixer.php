<?php

declare(strict_types=1);

namespace Sigil\Fixers;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

class PhpIniValueFixer implements FixerInterface
{
    public function apply(ScanContext $context): FixResult
    {
        return FixResult::failure('Use fix() directly.');
    }

    public function fix(string $iniPath, string $directive, string $value): FixResult
    {
        if (!file_exists($iniPath)) {
            return FixResult::failure("File not found: {$iniPath}");
        }

        $backup = $this->backup($iniPath);
        if (!$backup) {
            return FixResult::failure("Failed to create backup of {$iniPath}");
        }

        $content = file_get_contents($iniPath);
        if ($content === false) {
            return FixResult::failure("Cannot read {$iniPath}");
        }

        // Match directive with optional leading semicolon (commented out)
        $pattern     = '/^;?\s*(' . preg_quote($directive, '/') . '\s*=).*/m';
        $replacement = '$1 ' . $value;

        if (preg_match($pattern, $content)) {
            $newContent = preg_replace($pattern, $replacement, $content);
        } else {
            $newContent = rtrim($content) . "\n{$directive} = {$value}\n";
        }

        if ($newContent === null) {
            return FixResult::failure("Regex error updating {$directive}");
        }

        if (file_put_contents($iniPath, $newContent) === false) {
            return FixResult::failure("Failed to write {$iniPath}");
        }

        return FixResult::success("Set {$directive} = {$value} in {$iniPath}", $backup);
    }

    private function backup(string $path): ?string
    {
        $dir = '.sigil/backups';
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        $backup = $dir . '/' . basename($path) . '.' . date('Ymd_His');
        return copy($path, $backup) ? $backup : null;
    }
}

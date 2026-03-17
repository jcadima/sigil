<?php

declare(strict_types=1);

namespace Sigil\Fixers;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

class EnvValueFixer implements FixerInterface
{
    public function apply(ScanContext $context): FixResult
    {
        return FixResult::failure('Use fixValue() directly.');
    }

    public function fixValue(string $envPath, string $key, string $newValue): FixResult
    {
        if (!file_exists($envPath)) {
            return FixResult::failure("File not found: {$envPath}");
        }

        $backup = $this->backup($envPath);
        if (!$backup) {
            return FixResult::failure("Failed to create backup of {$envPath}");
        }

        $content = file_get_contents($envPath);
        if ($content === false) {
            return FixResult::failure("Cannot read {$envPath}");
        }

        // Replace existing key or add it
        $pattern     = '/^(' . preg_quote($key, '/') . '\s*=).*/m';
        $replacement = '$1' . $newValue;

        if (preg_match($pattern, $content)) {
            $newContent = preg_replace($pattern, $replacement, $content);
        } else {
            // Key doesn't exist — append
            $newContent = rtrim($content) . "\n{$key}={$newValue}\n";
        }

        if ($newContent === null || $newContent === $content) {
            return FixResult::failure("Failed to update {$key} in {$envPath}");
        }

        if (file_put_contents($envPath, $newContent) === false) {
            return FixResult::failure("Failed to write {$envPath}");
        }

        return FixResult::success("Updated {$key}={$newValue} in {$envPath}", $backup);
    }

    private function backup(string $path): ?string
    {
        $dir    = '.sigil/backups';
        $this->ensureDir($dir);
        $backup = $dir . '/' . basename($path) . '.' . date('Ymd_His');
        return copy($path, $backup) ? $backup : null;
    }

    private function ensureDir(string $dir): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}

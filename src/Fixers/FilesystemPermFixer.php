<?php

declare(strict_types=1);

namespace Sigil\Fixers;

use Sigil\Engine\ScanContext;
use Sigil\ValueObjects\FixResult;

class FilesystemPermFixer implements FixerInterface
{
    public function apply(ScanContext $context): FixResult
    {
        return FixResult::failure('Use fix() directly.');
    }

    public function fix(string $path, int $mode): FixResult
    {
        if (!file_exists($path)) {
            return FixResult::failure("Path not found: {$path}");
        }

        // Backup current permissions state
        $backup = $this->backupPermState($path);

        if (!chmod($path, $mode)) {
            return FixResult::failure("chmod({$path}, {$mode}) failed. Check permissions.");
        }

        return FixResult::success(
            sprintf('Changed permissions of %s to %04o', $path, $mode),
            $backup,
        );
    }

    private function backupPermState(string $path): string
    {
        $dir = '.sigil/backups';
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $perms      = fileperms($path);
        $backupFile = $dir . '/perms_' . md5($path) . '.' . date('Ymd_His') . '.txt';
        $content    = sprintf("%s: %04o\n", $path, $perms & 0777);
        file_put_contents($backupFile, $content);

        return $backupFile;
    }
}

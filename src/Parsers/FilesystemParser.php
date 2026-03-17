<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class FilesystemParser implements ParserInterface
{
    private const DEFAULT_PATHS = [
        'storage',
        'storage/logs',
        'storage/framework',
        'storage/framework/cache',
        'storage/framework/sessions',
        'storage/framework/views',
        'bootstrap/cache',
        'public',
    ];

    public function parse(string $path): FilesystemInfo
    {
        $info    = new FilesystemInfo();
        $base    = rtrim($path, '/');
        $targets = self::DEFAULT_PATHS;

        foreach ($targets as $rel) {
            $full = $base . '/' . $rel;
            $this->snapshot($info, $full);
        }

        // Also snapshot the project root
        $this->snapshot($info, $base);

        return $info;
    }

    public function snapshotPath(FilesystemInfo $info, string $path): void
    {
        $this->snapshot($info, $path);
    }

    private function snapshot(FilesystemInfo $info, string $path): void
    {
        if (!file_exists($path)) {
            return;
        }

        $perms = fileperms($path);
        $stat  = stat($path);
        $owner = $stat['uid'] ?? 0;
        $mode  = $this->formatMode($perms);

        $info->addSnapshot($path, $perms, $owner, $mode);
    }

    private function formatMode(int $perms): string
    {
        return sprintf('%04o', $perms & 0777);
    }
}

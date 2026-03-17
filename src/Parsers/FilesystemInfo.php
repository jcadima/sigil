<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class FilesystemInfo
{
    /** @var array<string, array{perms: int, owner: int, mode: string}> */
    private array $snapshots = [];

    public function addSnapshot(string $path, int $perms, int $owner, string $mode): void
    {
        $this->snapshots[$path] = [
            'perms' => $perms,
            'owner' => $owner,
            'mode'  => $mode,
        ];
    }

    public function getPerms(string $path): ?int
    {
        return $this->snapshots[$path]['perms'] ?? null;
    }

    public function getOwner(string $path): ?int
    {
        return $this->snapshots[$path]['owner'] ?? null;
    }

    public function getMode(string $path): ?string
    {
        return $this->snapshots[$path]['mode'] ?? null;
    }

    public function isWorldWritable(string $path): bool
    {
        $perms = $this->getPerms($path);
        if ($perms === null) {
            return false;
        }
        return (bool) ($perms & 0002);
    }

    public function isWorldReadable(string $path): bool
    {
        $perms = $this->getPerms($path);
        if ($perms === null) {
            return false;
        }
        return (bool) ($perms & 0004);
    }

    public function hasOctalMode(string $path, int $octal): bool
    {
        $perms = $this->getPerms($path);
        if ($perms === null) {
            return false;
        }
        return ($perms & 0777) === $octal;
    }

    public function all(): array
    {
        return $this->snapshots;
    }

    public function exists(string $path): bool
    {
        return isset($this->snapshots[$path]);
    }
}

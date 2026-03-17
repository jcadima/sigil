<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class ComposerConfig
{
    public function __construct(
        private array  $packages = [],
        private array  $lockData = [],
        private string $phpRequirement = '',
    ) {}

    public function getPackageVersion(string $name): ?string
    {
        return $this->packages[$name] ?? null;
    }

    public function hasPackage(string $name): bool
    {
        return isset($this->packages[$name]);
    }

    public function getPackages(): array
    {
        return $this->packages;
    }

    public function getLockData(): array
    {
        return $this->lockData;
    }

    public function getPhpRequirement(): string
    {
        return $this->phpRequirement;
    }

    public function getInstalledPackages(): array
    {
        return $this->lockData['packages'] ?? [];
    }
}

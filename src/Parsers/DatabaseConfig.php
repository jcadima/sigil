<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class DatabaseConfig
{
    public function __construct(
        private array  $directives = [],
        private array  $hbaRules   = [],
        private string $configPath  = '',
    ) {}

    public function get(string $key, string $section = ''): ?string
    {
        if ($section !== '' && isset($this->directives[$section][$key])) {
            return (string) $this->directives[$section][$key];
        }

        // Flat lookup
        if (isset($this->directives[$key])) {
            return (string) $this->directives[$key];
        }

        // Search all sections
        foreach ($this->directives as $sec => $data) {
            if (is_array($data) && isset($data[$key])) {
                return (string) $data[$key];
            }
        }

        return null;
    }

    public function getSection(string $section): array
    {
        return $this->directives[$section] ?? [];
    }

    public function getHbaRules(): array
    {
        return $this->hbaRules;
    }

    public function addHbaRule(array $rule): void
    {
        $this->hbaRules[] = $rule;
    }

    public function getConfigPath(): string
    {
        return $this->configPath;
    }

    public function all(): array
    {
        return $this->directives;
    }
}

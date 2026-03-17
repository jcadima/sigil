<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class PhpIniConfig
{
    public function __construct(private array $sections = []) {}

    /**
     * Get a directive value. Pass empty string for section to get from global/no-section.
     */
    public function get(string $section, string $key): ?string
    {
        if ($section === '') {
            // Search all sections
            foreach ($this->sections as $sec => $directives) {
                if (isset($directives[$key])) {
                    return (string) $directives[$key];
                }
            }
            return null;
        }

        $value = $this->sections[$section][$key] ?? null;
        return $value !== null ? (string) $value : null;
    }

    public function getSection(string $section): array
    {
        return $this->sections[$section] ?? [];
    }

    public function all(): array
    {
        return $this->sections;
    }
}

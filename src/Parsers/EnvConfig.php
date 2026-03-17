<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class EnvConfig
{
    private const MASKED_KEYS = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'PASS'];

    public function __construct(private array $data = []) {}

    public function get(string $key): ?string
    {
        return $this->data[$key] ?? null;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function __toString(): string
    {
        $lines = [];
        foreach ($this->data as $key => $value) {
            $masked = false;
            foreach (self::MASKED_KEYS as $sensitive) {
                if (str_contains(strtoupper($key), $sensitive)) {
                    $masked = true;
                    break;
                }
            }
            $lines[] = $key . '=' . ($masked ? '***' : $value);
        }
        return implode("\n", $lines);
    }
}

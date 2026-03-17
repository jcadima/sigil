<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class NginxConfig
{
    public function __construct(private array $tree = []) {}

    /**
     * Get a top-level directive value.
     */
    public function getDirective(string $name): ?string
    {
        return $this->tree[$name] ?? null;
    }

    /**
     * Get all blocks of a given type (e.g., 'server', 'http').
     */
    public function getBlocks(string $type): array
    {
        return $this->tree['blocks'][$type] ?? [];
    }

    /**
     * Search recursively for any directive with the given name across all blocks.
     */
    public function findDirectives(string $name): array
    {
        return $this->searchDirectives($this->tree, $name);
    }

    /**
     * Check if a directive exists anywhere in the config tree.
     */
    public function hasDirective(string $name): bool
    {
        return !empty($this->findDirectives($name));
    }

    /**
     * Search for a location block pattern in server blocks.
     */
    public function hasLocationBlock(string $pattern): bool
    {
        $servers = $this->getBlocks('server');
        foreach ($servers as $server) {
            $locations = $server['blocks']['location'] ?? [];
            foreach ($locations as $loc) {
                if (isset($loc['_key']) && str_contains($loc['_key'], $pattern)) {
                    return true;
                }
            }
        }
        return false;
    }

    public function getRawTree(): array
    {
        return $this->tree;
    }

    private function searchDirectives(array $node, string $name): array
    {
        $results = [];
        foreach ($node as $key => $value) {
            if ($key === $name && !is_array($value)) {
                $results[] = $value;
            } elseif ($key === 'blocks' && is_array($value)) {
                foreach ($value as $blockType => $blockList) {
                    foreach ($blockList as $block) {
                        $results = array_merge($results, $this->searchDirectives($block, $name));
                    }
                }
            }
        }
        return $results;
    }
}

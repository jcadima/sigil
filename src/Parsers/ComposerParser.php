<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class ComposerParser implements ParserInterface
{
    public function parse(string $path): ComposerConfig
    {
        $jsonPath = rtrim($path, '/') . '/composer.json';
        $lockPath = rtrim($path, '/') . '/composer.lock';

        $packages       = [];
        $lockData       = [];
        $phpRequirement = '';

        if (file_exists($jsonPath)) {
            $json = json_decode(file_get_contents($jsonPath), true);
            if (is_array($json)) {
                $phpRequirement = $json['require']['php'] ?? '';
                foreach (array_merge($json['require'] ?? [], $json['require-dev'] ?? []) as $pkg => $ver) {
                    if ($pkg !== 'php') {
                        $packages[$pkg] = $ver;
                    }
                }
            }
        }

        if (file_exists($lockPath)) {
            $lock = json_decode(file_get_contents($lockPath), true);
            if (is_array($lock)) {
                $lockData = $lock;
                // Override with actual installed versions from lock file
                foreach (array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []) as $pkg) {
                    if (isset($pkg['name'], $pkg['version'])) {
                        $packages[$pkg['name']] = $pkg['version'];
                    }
                }
            }
        }

        return new ComposerConfig($packages, $lockData, $phpRequirement);
    }
}

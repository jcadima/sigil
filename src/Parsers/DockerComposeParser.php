<?php

declare(strict_types=1);

namespace Sigil\Parsers;

use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;

class DockerComposeParser implements ParserInterface
{
    public function parse(string $path): DockerConfig
    {
        if (!file_exists($path)) {
            return new DockerConfig();
        }

        try {
            $data = Yaml::parseFile($path);
        } catch (ParseException) {
            return new DockerConfig();
        }

        if (!is_array($data) || !isset($data['services'])) {
            return new DockerConfig();
        }

        $services = [];
        foreach ($data['services'] as $name => $svc) {
            if (!is_array($svc)) {
                continue;
            }

            $services[$name] = [
                'image'       => $svc['image'] ?? null,
                'volumes'     => $this->normalizeVolumes($svc['volumes'] ?? []),
                'ports'       => $this->normalizePorts($svc['ports'] ?? []),
                'environment' => $this->normalizeEnv($svc['environment'] ?? []),
                'user'        => $svc['user'] ?? null,
                'privileged'  => $svc['privileged'] ?? false,
                'healthcheck' => $svc['healthcheck'] ?? null,
                'deploy'      => $svc['deploy'] ?? [],
                'build'       => $svc['build'] ?? null,
            ];
        }

        return new DockerConfig($services);
    }

    private function normalizeVolumes(array $vols): array
    {
        $result = [];
        foreach ($vols as $vol) {
            if (is_string($vol)) {
                $result[] = $vol;
            } elseif (is_array($vol) && isset($vol['source'])) {
                $result[] = $vol['source'] . ':' . ($vol['target'] ?? '');
            }
        }
        return $result;
    }

    private function normalizePorts(array $ports): array
    {
        $result = [];
        foreach ($ports as $port) {
            if (is_string($port) || is_int($port)) {
                $result[] = (string) $port;
            } elseif (is_array($port)) {
                $published = $port['published'] ?? '';
                $target    = $port['target'] ?? '';
                $result[]  = "{$published}:{$target}";
            }
        }
        return $result;
    }

    private function normalizeEnv(mixed $env): array
    {
        if (is_array($env)) {
            $result = [];
            foreach ($env as $key => $value) {
                if (is_int($key)) {
                    // "KEY=VALUE" format
                    $pos = strpos((string) $value, '=');
                    if ($pos !== false) {
                        $k          = substr((string) $value, 0, $pos);
                        $v          = substr((string) $value, $pos + 1);
                        $result[$k] = $v;
                    }
                } else {
                    $result[$key] = (string) $value;
                }
            }
            return $result;
        }
        return [];
    }
}

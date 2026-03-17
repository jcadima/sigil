<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class DockerConfig
{
    public function __construct(private array $services = []) {}

    public function getServices(): array
    {
        return $this->services;
    }

    public function getService(string $name): ?array
    {
        return $this->services[$name] ?? null;
    }

    public function getImage(string $service): ?string
    {
        return $this->services[$service]['image'] ?? null;
    }

    public function getVolumes(string $service): array
    {
        return $this->services[$service]['volumes'] ?? [];
    }

    public function getPorts(string $service): array
    {
        return $this->services[$service]['ports'] ?? [];
    }

    public function getEnvironment(string $service): array
    {
        return $this->services[$service]['environment'] ?? [];
    }

    public function getUser(string $service): ?string
    {
        return $this->services[$service]['user'] ?? null;
    }

    public function isPrivileged(string $service): bool
    {
        return ($this->services[$service]['privileged'] ?? false) === true;
    }

    public function hasHealthCheck(string $service): bool
    {
        return isset($this->services[$service]['healthcheck']);
    }

    public function getDeployLimits(string $service): ?array
    {
        return $this->services[$service]['deploy']['resources']['limits'] ?? null;
    }

    public function allVolumes(): array
    {
        $all = [];
        foreach ($this->services as $name => $svc) {
            foreach ($svc['volumes'] ?? [] as $vol) {
                $all[] = ['service' => $name, 'volume' => $vol];
            }
        }
        return $all;
    }

    public function allPorts(): array
    {
        $all = [];
        foreach ($this->services as $name => $svc) {
            foreach ($svc['ports'] ?? [] as $port) {
                $all[] = ['service' => $name, 'port' => $port];
            }
        }
        return $all;
    }
}

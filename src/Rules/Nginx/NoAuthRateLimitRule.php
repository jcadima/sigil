<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoAuthRateLimitRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $tree = $context->nginx->getRawTree();

        // Check if any location matching auth/login has limit_req
        $hasAuthLocation = false;
        $hasRateLimit    = false;

        $servers = $tree['blocks']['server'] ?? [];
        foreach ($servers as $server) {
            $locations = $server['blocks']['location'] ?? [];
            foreach ($locations as $loc) {
                $key = strtolower($loc['_key'] ?? '');
                if (
                    str_contains($key, 'login') ||
                    str_contains($key, 'auth') ||
                    str_contains($key, 'signin')
                ) {
                    $hasAuthLocation = true;
                    if (isset($loc['limit_req'])) {
                        $hasRateLimit = true;
                    }
                }
            }

            // Also check for limit_req_zone defined globally
            if (isset($server['limit_req_zone'])) {
                $hasRateLimit = true;
            }
        }

        // Check http block
        if (isset($tree['limit_req_zone'])) {
            $hasRateLimit = true;
        }

        if (!$hasAuthLocation || $hasRateLimit) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'N009',
            Severity::MEDIUM,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'No rate limiting (limit_req) on auth/login locations. Brute force attacks are possible.',
            'nginx',
            new Remediation(
                'Add limit_req_zone and limit_req to authentication location blocks.',
                null,
                [
                    'Add to http block: limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;',
                    'Add to location /login: limit_req zone=auth burst=10 nodelay;',
                ],
            ),
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function getCategory(): string
    {
        return 'nginx';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Add limit_req to auth location blocks.');
    }
}

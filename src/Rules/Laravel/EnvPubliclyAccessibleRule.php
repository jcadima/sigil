<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class EnvPubliclyAccessibleRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        // Check if nginx has a deny rule for .env files
        $nginx = $context->nginx;

        // Check for location blocks denying .env access
        $tree       = $nginx->getRawTree();
        $hasEnvDeny = $this->checkForEnvDeny($tree);

        if ($hasEnvDeny) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L002',
            Severity::CRITICAL,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'Nginx configuration has no deny rule for .env files. Secrets may be publicly accessible.',
            'laravel',
            new Remediation(
                'Add a location block to deny access to .env files.',
                'nginx/block-env.conf.stub',
                [
                    '1. Add to your nginx server block:',
                    '   location ~ /\\.env { deny all; return 404; }',
                    '2. Test: nginx -t',
                    '3. Reload: nginx -s reload',
                ],
            ),
        ));
    }

    private function checkForEnvDeny(array $tree): bool
    {
        $servers = $tree['blocks']['server'] ?? [];
        foreach ($servers as $server) {
            $locations = $server['blocks']['location'] ?? [];
            foreach ($locations as $loc) {
                $key = $loc['_key'] ?? '';
                if (str_contains($key, '.env') || str_contains($key, '\.env')) {
                    if (isset($loc['deny']) && str_contains((string) $loc['deny'], 'all')) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public function getSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Add location ~ /\\.env { deny all; return 404; } to nginx config.');
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class EnvNotBlockedRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $tree    = $context->nginx->getRawTree();
        $servers = $tree['blocks']['server'] ?? [];

        foreach ($servers as $server) {
            $locations = $server['blocks']['location'] ?? [];
            foreach ($locations as $loc) {
                $key = $loc['_key'] ?? '';
                // Check for .env blocking pattern
                if (
                    (str_contains($key, '.env') || str_contains($key, '\\.env')) &&
                    isset($loc['deny']) &&
                    str_contains((string) $loc['deny'], 'all')
                ) {
                    return $this->pass();
                }
            }
        }

        return $this->fail($this->finding(
            'N010',
            Severity::CRITICAL,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'No nginx location block found to block access to .env files. Credentials may be publicly accessible.',
            'nginx',
            new Remediation(
                'Add a location block to deny .env file access.',
                'nginx/block-env.conf.stub',
                [
                    'Add to server block:',
                    'location ~ /\\.env {',
                    '    deny all;',
                    '    return 404;',
                    '}',
                ],
            ),
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function getCategory(): string
    {
        return 'nginx';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Add location ~ /\\.env { deny all; return 404; } to nginx server block.');
    }
}

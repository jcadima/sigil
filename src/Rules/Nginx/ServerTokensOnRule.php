<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class ServerTokensOnRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $values = $context->nginx->findDirectives('server_tokens');

        // If not set, default is 'on'
        if (empty($values)) {
            return $this->fail($this->finding(
                'N001',
                Severity::LOW,
                $context->nginxConfigPath ?? 'nginx.conf',
                0,
                'server_tokens is not set (defaults to on). Nginx version is disclosed in error pages and headers.',
                'nginx',
                new Remediation(
                    'Add server_tokens off; to your nginx http block.',
                    null,
                    ['Add to http block: server_tokens off;'],
                ),
            ));
        }

        foreach ($values as $val) {
            if (strtolower(trim($val)) === 'on') {
                return $this->fail($this->finding(
                    'N001',
                    Severity::LOW,
                    $context->nginxConfigPath ?? 'nginx.conf',
                    0,
                    'server_tokens is on. Nginx version is disclosed in error pages and Server header.',
                    'nginx',
                    new Remediation(
                        'Set server_tokens off; in the http block of nginx.conf.',
                        null,
                        ['Change to: server_tokens off;'],
                    ),
                ));
            }
        }

        return $this->pass();
    }

    public function getSeverity(): Severity
    {
        return Severity::LOW;
    }

    public function getCategory(): string
    {
        return 'nginx';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Set server_tokens off; in nginx.conf http block.');
    }
}

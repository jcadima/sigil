<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class MissingXContentTypeRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $headers = $context->nginx->findDirectives('add_header');

        foreach ((array) $headers as $h) {
            if (str_contains(strtolower((string) $h), 'x-content-type-options')) {
                return $this->pass();
            }
        }

        return $this->fail($this->finding(
            'N003',
            Severity::LOW,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'Missing X-Content-Type-Options header. MIME sniffing attacks are possible.',
            'nginx',
            new Remediation(
                'Add: add_header X-Content-Type-Options "nosniff" always;',
                'nginx/security-headers.stub',
                ['Add to server block: add_header X-Content-Type-Options "nosniff" always;'],
            ),
        ));
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
        return new Remediation('Add X-Content-Type-Options: nosniff header.');
    }
}

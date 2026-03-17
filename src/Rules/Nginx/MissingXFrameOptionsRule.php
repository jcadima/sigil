<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class MissingXFrameOptionsRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $headers = $context->nginx->findDirectives('add_header');

        foreach ((array) $headers as $h) {
            if (str_contains(strtolower((string) $h), 'x-frame-options')) {
                return $this->pass();
            }
        }

        return $this->fail($this->finding(
            'N002',
            Severity::MEDIUM,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'Missing X-Frame-Options header. Clickjacking attacks are possible.',
            'nginx',
            new Remediation(
                'Add: add_header X-Frame-Options "SAMEORIGIN" always;',
                'nginx/security-headers.stub',
                ['Add to server block: add_header X-Frame-Options "SAMEORIGIN" always;'],
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
        return new Remediation('Add X-Frame-Options header to nginx server block.');
    }
}

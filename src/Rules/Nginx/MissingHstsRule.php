<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class MissingHstsRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $headers = $context->nginx->findDirectives('add_header');

        foreach ((array) $headers as $h) {
            if (str_contains(strtolower((string) $h), 'strict-transport-security')) {
                return $this->pass();
            }
        }

        return $this->fail($this->finding(
            'N004',
            Severity::MEDIUM,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'Missing HSTS (Strict-Transport-Security) header. SSL stripping attacks are possible.',
            'nginx',
            new Remediation(
                'Add HSTS header to enforce HTTPS connections.',
                'nginx/hsts-header.stub',
                ['Add: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'],
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
        return new Remediation('Add Strict-Transport-Security header with max-age=31536000.');
    }
}

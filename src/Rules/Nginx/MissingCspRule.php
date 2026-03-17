<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class MissingCspRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $headers = $context->nginx->findDirectives('add_header');

        foreach ((array) $headers as $h) {
            if (str_contains(strtolower((string) $h), 'content-security-policy')) {
                return $this->pass();
            }
        }

        return $this->fail($this->finding(
            'N005',
            Severity::MEDIUM,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'Missing Content-Security-Policy header. XSS and injection attacks are harder to mitigate.',
            'nginx',
            new Remediation(
                'Add a Content-Security-Policy header appropriate for your application.',
                'nginx/security-headers.stub',
                [
                    'Add: add_header Content-Security-Policy "default-src \'self\'" always;',
                    'Adjust policy to match your application\'s resource requirements.',
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
        return new Remediation('Add Content-Security-Policy header to nginx config.');
    }
}

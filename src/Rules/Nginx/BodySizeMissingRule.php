<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class BodySizeMissingRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $values = $context->nginx->findDirectives('client_max_body_size');

        if (!empty($values)) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'N011',
            Severity::LOW,
            $context->nginxConfigPath ?? 'nginx.conf',
            0,
            'client_max_body_size not set. Default (1MB) may be too restrictive or too permissive for your application.',
            'nginx',
            new Remediation(
                'Set client_max_body_size to an appropriate value for your application.',
                null,
                ['Add to http or server block: client_max_body_size 10M;'],
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
        return new Remediation('Add client_max_body_size directive to nginx config.');
    }
}

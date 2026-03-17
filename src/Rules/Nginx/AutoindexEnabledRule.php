<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class AutoindexEnabledRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $values = $context->nginx->findDirectives('autoindex');

        foreach ($values as $val) {
            if (strtolower(trim($val)) === 'on') {
                return $this->fail($this->finding(
                    'N006',
                    Severity::HIGH,
                    $context->nginxConfigPath ?? 'nginx.conf',
                    0,
                    'autoindex is on. Directory listing is enabled and exposes file structure.',
                    'nginx',
                    new Remediation(
                        'Set autoindex off; in your nginx configuration.',
                        null,
                        ['Change autoindex on; to autoindex off;'],
                    ),
                ));
            }
        }

        return $this->pass();
    }

    public function getSeverity(): Severity
    {
        return Severity::HIGH;
    }

    public function getCategory(): string
    {
        return 'nginx';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Set autoindex off; in nginx.conf.');
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class WeakSslProtocolsRule extends AbstractRule
{
    private const WEAK_PROTOCOLS = ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3'];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $values = $context->nginx->findDirectives('ssl_protocols');

        foreach ($values as $val) {
            $protocols = preg_split('/\s+/', trim($val), -1, PREG_SPLIT_NO_EMPTY) ?: [];
            $weak      = array_intersect($protocols, self::WEAK_PROTOCOLS);

            if (!empty($weak)) {
                return $this->fail($this->finding(
                    'N007',
                    Severity::HIGH,
                    $context->nginxConfigPath ?? 'nginx.conf',
                    0,
                    sprintf('Weak SSL/TLS protocols enabled: %s', implode(', ', $weak)),
                    'nginx',
                    new Remediation(
                        'Update ssl_protocols to only allow TLSv1.2 and TLSv1.3.',
                        null,
                        ['Set: ssl_protocols TLSv1.2 TLSv1.3;'],
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
        return new Remediation('Set ssl_protocols TLSv1.2 TLSv1.3;');
    }
}

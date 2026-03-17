<?php

declare(strict_types=1);

namespace Sigil\Rules\Nginx;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class WeakCiphersRule extends AbstractRule
{
    private const WEAK_PATTERNS = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL', 'aNULL', 'eNULL', '3DES'];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $values = $context->nginx->findDirectives('ssl_ciphers');

        foreach ($values as $val) {
            $val  = strtoupper(trim($val));
            $weak = [];

            foreach (self::WEAK_PATTERNS as $pattern) {
                if (str_contains($val, $pattern)) {
                    $weak[] = $pattern;
                }
            }

            if (!empty($weak)) {
                return $this->fail($this->finding(
                    'N008',
                    Severity::HIGH,
                    $context->nginxConfigPath ?? 'nginx.conf',
                    0,
                    sprintf('Weak cipher suites detected: %s', implode(', ', $weak)),
                    'nginx',
                    new Remediation(
                        'Use a modern cipher suite string from Mozilla SSL Configuration Generator.',
                        null,
                        [
                            'Recommended: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...',
                            'See: https://ssl-config.mozilla.org/',
                        ],
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
        return new Remediation('Remove weak ciphers (RC4, DES, MD5) from ssl_ciphers.');
    }
}

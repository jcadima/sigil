<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class PhpVersionEolRule extends AbstractRule
{
    // EOL dates: version => EOL date (as timestamp)
    private const EOL_MATRIX = [
        '8.0' => '2023-11-26',
        '8.1' => '2024-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '7.4' => '2022-11-28',
        '7.3' => '2021-12-06',
        '7.2' => '2020-11-30',
        '7.1' => '2019-12-01',
        '7.0' => '2019-01-10',
    ];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $version      = PHP_VERSION;
        $majorMinor   = implode('.', array_slice(explode('.', $version), 0, 2));
        $eolDate      = self::EOL_MATRIX[$majorMinor] ?? null;

        if ($eolDate === null) {
            return $this->pass(); // Unknown version — skip
        }

        $eolTimestamp = strtotime($eolDate);
        if ($eolTimestamp === false || time() < $eolTimestamp) {
            return $this->pass(); // Not EOL yet
        }

        return $this->fail($this->finding(
            'L009',
            Severity::MEDIUM,
            'php',
            0,
            sprintf('PHP %s reached end-of-life on %s and no longer receives security updates.', $version, $eolDate),
            'laravel',
            new Remediation(
                'Upgrade to a supported PHP version (8.2 or newer).',
                null,
                ['Upgrade PHP to 8.2+', 'Update Dockerfile base image', 'Test application compatibility'],
            ),
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Upgrade to a supported PHP version (8.2+).');
    }
}

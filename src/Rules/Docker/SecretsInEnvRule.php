<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class SecretsInEnvRule extends AbstractRule
{
    private const SENSITIVE_PATTERNS = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'PASS', 'CREDENTIAL'];
    private const PLACEHOLDER_VALUES = ['changeme', 'secret', 'password', 'example', 'test', 'dummy', '123456', 'admin'];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($context->docker->getServices() as $name => $svc) {
            $env = $context->docker->getEnvironment($name);

            foreach ($env as $key => $value) {
                $keyUpper = strtoupper($key);
                $isSensitive = false;

                foreach (self::SENSITIVE_PATTERNS as $pattern) {
                    if (str_contains($keyUpper, $pattern)) {
                        $isSensitive = true;
                        break;
                    }
                }

                if (!$isSensitive) {
                    continue;
                }

                // Check if value looks like a plaintext secret (not an env var reference)
                $isEnvRef    = str_starts_with($value, '$') || str_starts_with($value, '${');
                $isPlaceholder = in_array(strtolower($value), self::PLACEHOLDER_VALUES, true);
                $isEmpty     = $value === '';

                if (!$isEnvRef && !$isEmpty && !$isPlaceholder) {
                    $collection->add($this->finding(
                        'D006',
                        Severity::HIGH,
                        $context->dockerComposePath ?? 'docker-compose.yml',
                        0,
                        sprintf(
                            'Service "%s" has plaintext secret in environment: %s',
                            $name,
                            $key,
                        ),
                        'docker',
                        new Remediation(
                            'Use Docker secrets or environment variable references instead of hardcoded values.',
                            null,
                            [
                                'Use: ' . $key . ': ${' . $key . '}',
                                'Or use Docker secrets: secrets: [' . strtolower($key) . ']',
                                'Store actual values in .env file (not committed to git)',
                            ],
                        ),
                    ));
                }
            }
        }

        return $collection;
    }

    public function getSeverity(): Severity
    {
        return Severity::HIGH;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Use Docker secrets or .env references instead of hardcoded secrets in docker-compose.yml.');
    }
}

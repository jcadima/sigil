<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoHealthCheckRule extends AbstractRule
{
    private const WEB_KEYWORDS = ['nginx', 'php', 'web', 'app', 'fpm', 'laravel'];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($context->docker->getServices() as $name => $svc) {
            $image = strtolower($context->docker->getImage($name) ?? $name);
            $isWeb = false;

            foreach (self::WEB_KEYWORDS as $kw) {
                if (str_contains($image, $kw) || str_contains(strtolower($name), $kw)) {
                    $isWeb = true;
                    break;
                }
            }

            if (!$isWeb) {
                continue;
            }

            if (!$context->docker->hasHealthCheck($name)) {
                $collection->add($this->finding(
                    'D008',
                    Severity::LOW,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf('Service "%s" has no healthcheck defined. Unhealthy containers may serve traffic silently.', $name),
                    'docker',
                    new Remediation(
                        'Add a healthcheck to service ' . $name . '.',
                        null,
                        [
                            'Add to service:',
                            '  healthcheck:',
                            '    test: ["CMD", "curl", "-f", "http://localhost/health"]',
                            '    interval: 30s',
                            '    timeout: 10s',
                            '    retries: 3',
                        ],
                    ),
                ));
            }
        }

        return $collection;
    }

    public function getSeverity(): Severity
    {
        return Severity::LOW;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Add healthcheck to web-facing services in docker-compose.yml.');
    }
}

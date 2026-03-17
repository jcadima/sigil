<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoResourceLimitsRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($context->docker->getServices() as $name => $svc) {
            $limits = $context->docker->getDeployLimits($name);
            if ($limits === null) {
                $collection->add($this->finding(
                    'D005',
                    Severity::MEDIUM,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf('Service "%s" has no resource limits (CPU/memory). DoS via resource exhaustion is possible.', $name),
                    'docker',
                    new Remediation(
                        'Add deploy.resources.limits to service ' . $name . '.',
                        null,
                        [
                            'Add to service ' . $name . ':',
                            '  deploy:',
                            '    resources:',
                            '      limits:',
                            '        cpus: "0.5"',
                            '        memory: 512M',
                        ],
                    ),
                ));
            }
        }

        return $collection;
    }

    public function getSeverity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Add deploy.resources.limits to all services in docker-compose.yml.');
    }
}

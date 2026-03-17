<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class PrivilegedModeRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        foreach ($context->docker->getServices() as $name => $svc) {
            if ($context->docker->isPrivileged($name)) {
                return $this->fail($this->finding(
                    'D004',
                    Severity::CRITICAL,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf('Service "%s" runs in privileged mode. This grants full host kernel access.', $name),
                    'docker',
                    new Remediation(
                        'Remove privileged: true from docker-compose.yml.',
                        null,
                        [
                            'Remove: privileged: true from service ' . $name,
                            'Use specific capabilities with cap_add instead',
                        ],
                    ),
                ));
            }
        }

        return $this->pass();
    }

    public function getSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Remove privileged: true from docker-compose.yml.');
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class DockerSocketMountedRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        foreach ($context->docker->allVolumes() as $vol) {
            $volume = $vol['volume'];
            if (str_contains($volume, '/var/run/docker.sock')) {
                return $this->fail($this->finding(
                    'D002',
                    Severity::CRITICAL,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf(
                        'Docker socket mounted in service "%s". This grants full host root access from within the container.',
                        $vol['service'],
                    ),
                    'docker',
                    new Remediation(
                        'Remove the Docker socket volume mount. Use specific Docker API access patterns instead.',
                        null,
                        [
                            'Remove: /var/run/docker.sock:/var/run/docker.sock from volumes',
                            'Consider using Docker-in-Docker or Podman instead',
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
        return new Remediation('Remove /var/run/docker.sock volume mount from docker-compose.yml.');
    }
}

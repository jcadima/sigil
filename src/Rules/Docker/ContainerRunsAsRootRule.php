<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class ContainerRunsAsRootRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();
        $dockerfile = $context->projectPath . '/Dockerfile';

        // Check Dockerfile for USER directive
        if (file_exists($dockerfile)) {
            $content = file_get_contents($dockerfile);
            if ($content && !preg_match('/^USER\s+(?!root)/mi', $content)) {
                // No USER directive or USER root
                if (!str_contains($content, 'USER ') || preg_match('/^USER\s+root/mi', $content)) {
                    $collection->add($this->finding(
                        'D001',
                        Severity::HIGH,
                        $dockerfile,
                        0,
                        'Dockerfile has no USER directive or runs as root. Containers should run as non-root.',
                        'docker',
                        new Remediation(
                            'Add a USER directive to run the container as a non-root user.',
                            null,
                            [
                                'Add to Dockerfile: RUN useradd -r appuser',
                                'Add: USER appuser',
                            ],
                        ),
                    ));
                }
            }
        }

        // Check docker-compose services for user: root
        foreach ($context->docker->getServices() as $name => $svc) {
            $user = $context->docker->getUser($name);
            if ($user !== null && (strtolower($user) === 'root' || $user === '0')) {
                $collection->add($this->finding(
                    'D001',
                    Severity::HIGH,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf('Service "%s" is configured to run as root user.', $name),
                    'docker',
                    new Remediation(
                        'Set user: to a non-root user in docker-compose.yml.',
                        null,
                        ['Change user: root to user: 1000 or a named non-root user'],
                    ),
                ));
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
        return new Remediation('Add USER <nonroot> directive to Dockerfile.');
    }
}

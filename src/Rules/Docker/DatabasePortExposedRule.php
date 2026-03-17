<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class DatabasePortExposedRule extends AbstractRule
{
    private const DB_PORTS = ['3306', '5432', '27017', '6379'];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($context->docker->allPorts() as $portInfo) {
            $port    = (string) $portInfo['port'];
            $service = $portInfo['service'];

            // Parse "HOST:CONTAINER" format
            if (str_contains($port, ':')) {
                [$host, $container] = explode(':', $port, 2);
                // Remove port from container part if it has a specific bind
                $containerPort = explode(':', $container)[0];

                foreach (self::DB_PORTS as $dbPort) {
                    if ($containerPort === $dbPort || $container === $dbPort) {
                        $boundTo = str_contains($host, '0.0.0.0') || $host === '' ? '0.0.0.0' : $host;

                        if ($boundTo === '0.0.0.0' || $host === '') {
                            $collection->add($this->finding(
                                'D007',
                                Severity::HIGH,
                                $context->dockerComposePath ?? 'docker-compose.yml',
                                0,
                                sprintf(
                                    'Service "%s" exposes database port %s on 0.0.0.0 (all interfaces). Database accessible from internet.',
                                    $service,
                                    $dbPort,
                                ),
                                'docker',
                                new Remediation(
                                    'Bind database port to 127.0.0.1 only.',
                                    null,
                                    [
                                        'Change: "' . $port . '"',
                                        'To:     "127.0.0.1:' . $dbPort . ':' . $dbPort . '"',
                                    ],
                                ),
                            ));
                        }
                    }
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
        return new Remediation('Bind database ports to 127.0.0.1 instead of 0.0.0.0.');
    }
}

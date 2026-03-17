<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class DatabasePortExposedRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        foreach ($context->docker->allPorts() as $p) {
            $port = (string)$p['port'];
            if (str_contains($port, '5432') && !str_contains($port, '127.0.0.1')) {
                return $this->fail($this->finding('PG002', Severity::HIGH,
                    $context->dockerComposePath ?? 'docker-compose.yml', 0,
                    'PostgreSQL port 5432 exposed on 0.0.0.0.', 'postgresql',
                    new Remediation('Bind PostgreSQL to 127.0.0.1.', null, ['Change to 127.0.0.1:5432:5432']),
                ));
            }
        }
        $listenAddr = $context->database->get('listen_addresses');
        if ($listenAddr !== null && str_contains($listenAddr, '*')) {
            return $this->fail($this->finding('PG002', Severity::HIGH,
                $context->database->getConfigPath() ?: 'postgresql.conf', 0,
                'PostgreSQL listen_addresses=* listens on all interfaces.', 'postgresql',
                new Remediation('Set listen_addresses=\'localhost\' in postgresql.conf.'),
            ));
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::HIGH; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Restrict PostgreSQL to localhost only.'); }
}

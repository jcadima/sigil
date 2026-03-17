<?php
declare(strict_types=1);
namespace Sigil\Rules\MariaDB;
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
            if (str_contains($port, '3306') && !str_contains($port, '127.0.0.1')) {
                return $this->fail($this->finding('MB002', Severity::HIGH,
                    $context->dockerComposePath ?? 'docker-compose.yml', 0,
                    'MariaDB port 3306 exposed on 0.0.0.0.', 'mariadb',
                    new Remediation('Bind to 127.0.0.1.', null, ['Change to 127.0.0.1:3306:3306']),
                ));
            }
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::HIGH; }
    public function getCategory(): string { return 'mariadb'; }
    public function getRemediation(): Remediation { return new Remediation('Bind MariaDB to 127.0.0.1.'); }
}

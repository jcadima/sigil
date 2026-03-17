<?php
declare(strict_types=1);
namespace Sigil\Rules\MySQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class DatabasePortExposedRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $bindAddress = $context->database->get('bind-address', 'mysqld') ?? $context->database->get('bind_address', 'mysqld');
        if ($bindAddress !== null && $bindAddress !== '0.0.0.0') {
            return $this->pass();
        }
        // Check docker ports too
        foreach ($context->docker->allPorts() as $p) {
            $port = (string)$p['port'];
            if (str_contains($port, '3306') && !str_contains($port, '127.0.0.1')) {
                return $this->fail($this->finding('M002', Severity::HIGH,
                    $context->dockerComposePath ?? 'docker-compose.yml', 0,
                    'MySQL port 3306 is exposed on 0.0.0.0. Database accessible from internet.', 'mysql',
                    new Remediation('Bind MySQL to 127.0.0.1 in my.cnf and docker-compose.yml.', null,
                        ['Set bind-address = 127.0.0.1 in [mysqld]', 'Change port to 127.0.0.1:3306:3306']),
                ));
            }
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::HIGH; }
    public function getCategory(): string { return 'mysql'; }
    public function getRemediation(): Remediation { return new Remediation('Bind MySQL to 127.0.0.1.'); }
}

<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class HbaOpenAccessRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();
        foreach ($context->database->getHbaRules() as $rule) {
            $addr = $rule['address'] ?? '';
            $user = $rule['user'] ?? '';
            $db   = $rule['database'] ?? '';
            if (($addr === '0.0.0.0/0' || $addr === '::/0' || $addr === 'all') && ($user === 'all' || $db === 'all')) {
                $collection->add($this->finding('PG007', Severity::HIGH,
                    $context->database->getConfigPath() ?: 'pg_hba.conf', 0,
                    sprintf('pg_hba.conf allows open access from %s for all users/databases.', $addr), 'postgresql',
                    new Remediation('Restrict pg_hba.conf to specific IP ranges and users.', null,
                        ['Replace 0.0.0.0/0 with specific client IP ranges']),
                ));
            }
        }
        return $collection;
    }
    public function getSeverity(): Severity { return Severity::HIGH; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Restrict pg_hba.conf access to specific IP ranges.'); }
}

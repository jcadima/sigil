<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class HbaTrustAuthRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();
        foreach ($context->database->getHbaRules() as $rule) {
            if (strtolower($rule['method'] ?? '') === 'trust') {
                $collection->add($this->finding('PG003', Severity::CRITICAL,
                    $context->database->getConfigPath() ?: 'pg_hba.conf', 0,
                    sprintf('pg_hba.conf has trust authentication for %s/%s. No password required.', $rule['database'] ?? '*', $rule['user'] ?? '*'),
                    'postgresql',
                    new Remediation('Change trust to scram-sha-256 or md5 in pg_hba.conf.', null,
                        ['Edit pg_hba.conf', 'Replace "trust" with "scram-sha-256"']),
                ));
            }
        }
        return $collection;
    }
    public function getSeverity(): Severity { return Severity::CRITICAL; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Replace trust auth with scram-sha-256 in pg_hba.conf.'); }
}

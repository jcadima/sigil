<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class SuperuserAsAppUserRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $user = strtolower($context->env->get('DB_USERNAME') ?? '');
        if ($user === 'postgres' || $user === 'superuser') {
            return $this->fail($this->finding('PG001', Severity::CRITICAL,
                $context->projectPath . '/.env', 0,
                'Application uses PostgreSQL superuser account. Row-level security and privilege separation are bypassed.', 'postgresql',
                new Remediation('Create a dedicated app user with minimal privileges.', null,
                    ['CREATE USER appuser WITH PASSWORD \'...\';', 'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO appuser;']),
            ));
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::CRITICAL; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Create a dedicated PostgreSQL application user.'); }
}

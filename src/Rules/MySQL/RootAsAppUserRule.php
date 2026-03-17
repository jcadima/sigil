<?php
declare(strict_types=1);
namespace Sigil\Rules\MySQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class RootAsAppUserRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $dbUser = $context->env->get('DB_USERNAME') ?? '';
        if (strtolower($dbUser) !== 'root') {
            return $this->pass();
        }
        return $this->fail($this->finding(
            'M001', Severity::CRITICAL, $context->projectPath . '/.env', 0,
            'DB_USERNAME=root. Application is using the MySQL root user, bypassing access controls.',
            'mysql',
            new Remediation('Create a dedicated MySQL user with minimal privileges.', null,
                ['CREATE USER appuser@localhost IDENTIFIED BY \'...\';', 'GRANT SELECT,INSERT,UPDATE,DELETE ON mydb.* TO appuser@localhost;']),
        ));
    }
    public function getSeverity(): Severity { return Severity::CRITICAL; }
    public function getCategory(): string { return 'mysql'; }
    public function getRemediation(): Remediation { return new Remediation('Create a dedicated MySQL user.'); }
}

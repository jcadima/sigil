<?php
declare(strict_types=1);
namespace Sigil\Rules\MariaDB;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class RootAsAppUserRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $dbUser = strtolower($context->env->get('DB_USERNAME') ?? '');
        if ($dbUser !== 'root') { return $this->pass(); }
        // unix_socket exception: if no MYSQL_ROOT_PASSWORD set and using unix_socket, skip
        foreach ($context->docker->getServices() as $name => $svc) {
            $env = $context->docker->getEnvironment($name);
            $img = strtolower($context->docker->getImage($name) ?? '');
            if (str_contains($img, 'mariadb')) {
                $hasRootPw = isset($env['MYSQL_ROOT_PASSWORD']) && !empty($env['MYSQL_ROOT_PASSWORD']);
                if (!$hasRootPw) { return $this->pass(); } // unix_socket auth implied
            }
        }
        return $this->fail($this->finding('MB001', Severity::CRITICAL,
            $context->projectPath . '/.env', 0,
            'DB_USERNAME=root. Application uses MariaDB root user with password authentication.', 'mariadb',
            new Remediation('Create a dedicated MariaDB user.', null,
                ['CREATE USER appuser@localhost IDENTIFIED BY \'...\';', 'GRANT SELECT,INSERT,UPDATE,DELETE ON mydb.* TO appuser@localhost;']),
        ));
    }
    public function getSeverity(): Severity { return Severity::CRITICAL; }
    public function getCategory(): string { return 'mariadb'; }
    public function getRemediation(): Remediation { return new Remediation('Create a dedicated MariaDB application user.'); }
}

<?php
declare(strict_types=1);
namespace Sigil\Rules\MariaDB;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoSslRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $ssl = $context->database->get('ssl_cert', 'mysqld') ?? $context->database->get('ssl-cert', 'mysqld');
        $req = $context->database->get('require_secure_transport', 'mysqld');
        if ($ssl !== null || $req !== null) { return $this->pass(); }
        return $this->fail($this->finding('MB003', Severity::MEDIUM,
            $context->database->getConfigPath() ?: 'my.cnf', 0,
            'MariaDB SSL not configured.', 'mariadb',
            new Remediation('Enable SSL for MariaDB.', null, ['Set ssl_cert in [mysqld]']),
        ));
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'mariadb'; }
    public function getRemediation(): Remediation { return new Remediation('Configure SSL for MariaDB.'); }
}

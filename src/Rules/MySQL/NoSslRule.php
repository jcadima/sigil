<?php
declare(strict_types=1);
namespace Sigil\Rules\MySQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoSslRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $ssl = $context->database->get('ssl', 'mysqld') ?? $context->database->get('require_secure_transport', 'mysqld');
        $haveSsl = $context->database->get('ssl_cert', 'mysqld') ?? $context->database->get('ssl-cert', 'mysqld');
        if ($ssl !== null || $haveSsl !== null) {
            return $this->pass();
        }
        return $this->fail($this->finding('M003', Severity::MEDIUM,
            $context->database->getConfigPath() ?: 'my.cnf', 0,
            'MySQL SSL is not configured. Database connections may be unencrypted.', 'mysql',
            new Remediation('Enable SSL for MySQL connections.', null,
                ['Add to [mysqld]: ssl_cert=/etc/mysql/certs/server-cert.pem', 'Add: require_secure_transport=ON']),
        ));
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'mysql'; }
    public function getRemediation(): Remediation { return new Remediation('Enable require_secure_transport=ON in my.cnf.'); }
}

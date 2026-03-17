<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class AuditLoggingRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $log = $context->database->get('log_connections');
        $logDisconnections = $context->database->get('log_disconnections');
        if ($log !== null && in_array(strtolower($log), ['on', '1', 'true'], true)) {
            return $this->pass();
        }
        return $this->fail($this->finding('PG005', Severity::LOW,
            $context->database->getConfigPath() ?: 'postgresql.conf', 0,
            'PostgreSQL connection logging is disabled. Failed auth attempts are not logged.', 'postgresql',
            new Remediation('Enable connection logging.', null,
                ['Set log_connections = on', 'Set log_disconnections = on']),
        ));
    }
    public function getSeverity(): Severity { return Severity::LOW; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Enable log_connections and log_disconnections.'); }
}

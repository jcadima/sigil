<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class SslOffRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $ssl = $context->database->get('ssl');
        if ($ssl !== null && in_array(strtolower($ssl), ['off', 'false', '0'], true)) {
            return $this->fail($this->finding('PG004', Severity::MEDIUM,
                $context->database->getConfigPath() ?: 'postgresql.conf', 0,
                'PostgreSQL SSL is disabled. Database connections are unencrypted.', 'postgresql',
                new Remediation('Enable SSL in postgresql.conf.', null, ['Set ssl = on']),
            ));
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Set ssl = on in postgresql.conf.'); }
}

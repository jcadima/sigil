<?php
declare(strict_types=1);
namespace Sigil\Rules\MySQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class GeneralLogEnabledRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $generalLog = $context->database->get('general_log', 'mysqld') ?? $context->database->get('general-log', 'mysqld');
        if ($generalLog === null || in_array(strtolower($generalLog), ['0', 'off', 'false'], true)) {
            return $this->pass();
        }
        return $this->fail($this->finding('M004', Severity::LOW,
            $context->database->getConfigPath() ?: 'my.cnf', 0,
            'MySQL general query log is enabled. All queries including credentials are logged to disk.', 'mysql',
            new Remediation('Disable general_log in production.', null, ['Set general_log = 0 in [mysqld]']),
        ));
    }
    public function getSeverity(): Severity { return Severity::LOW; }
    public function getCategory(): string { return 'mysql'; }
    public function getRemediation(): Remediation { return new Remediation('Set general_log = 0 in my.cnf.'); }
}

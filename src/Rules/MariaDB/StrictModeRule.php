<?php
declare(strict_types=1);
namespace Sigil\Rules\MariaDB;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class StrictModeRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $sqlMode = $context->database->get('sql_mode', 'mysqld') ?? $context->database->get('sql-mode', 'mysqld');
        if ($sqlMode !== null && str_contains(strtoupper($sqlMode), 'STRICT_TRANS_TABLES')) {
            return $this->pass();
        }
        return $this->fail($this->finding('MB005', Severity::MEDIUM,
            $context->database->getConfigPath() ?: 'my.cnf', 0,
            'MariaDB strict mode (STRICT_TRANS_TABLES) is not enabled. Malformed data may be silently accepted.', 'mariadb',
            new Remediation('Enable strict SQL mode.', null,
                ['Add to [mysqld]: sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION']),
        ));
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'mariadb'; }
    public function getRemediation(): Remediation { return new Remediation('Enable STRICT_TRANS_TABLES sql_mode.'); }
}

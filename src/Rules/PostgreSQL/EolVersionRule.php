<?php
declare(strict_types=1);
namespace Sigil\Rules\PostgreSQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class EolVersionRule extends AbstractRule
{
    private const EOL = ['9.6' => '2021-11-11', '10' => '2022-11-10', '11' => '2023-11-09', '12' => '2024-11-14', '13' => '2025-11-13'];
    public function evaluate(ScanContext $context): FindingCollection
    {
        foreach ($context->docker->getServices() as $name => $svc) {
            $img = strtolower($context->docker->getImage($name) ?? '');
            if (!str_contains($img, 'postgres')) continue;
            foreach (self::EOL as $ver => $eolDate) {
                if ((str_contains($img, ':' . $ver) || str_contains($img, 'postgres:' . $ver)) && time() > strtotime($eolDate)) {
                    return $this->fail($this->finding('PG006', Severity::MEDIUM,
                        $context->dockerComposePath ?? 'docker-compose.yml', 0,
                        sprintf('PostgreSQL %s reached EOL on %s.', $ver, $eolDate), 'postgresql',
                        new Remediation('Upgrade PostgreSQL to version 15 or newer.'),
                    ));
                }
            }
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'postgresql'; }
    public function getRemediation(): Remediation { return new Remediation('Upgrade PostgreSQL to a supported version.'); }
}

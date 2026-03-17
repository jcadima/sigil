<?php
declare(strict_types=1);
namespace Sigil\Rules\MariaDB;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class EolVersionRule extends AbstractRule
{
    private const EOL = ['10.3' => '2023-05-25', '10.4' => '2024-06-18', '10.5' => '2025-06-24'];
    public function evaluate(ScanContext $context): FindingCollection
    {
        foreach ($context->docker->getServices() as $name => $svc) {
            $img = strtolower($context->docker->getImage($name) ?? '');
            if (!str_contains($img, 'mariadb')) continue;
            foreach (self::EOL as $ver => $eolDate) {
                if (str_contains($img, ':' . $ver) && time() > strtotime($eolDate)) {
                    return $this->fail($this->finding('MB004', Severity::MEDIUM,
                        $context->dockerComposePath ?? 'docker-compose.yml', 0,
                        sprintf('MariaDB %s reached EOL on %s.', $ver, $eolDate), 'mariadb',
                        new Remediation('Upgrade MariaDB to 10.6 LTS or 11.x.'),
                    ));
                }
            }
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'mariadb'; }
    public function getRemediation(): Remediation { return new Remediation('Upgrade MariaDB to a supported LTS version.'); }
}

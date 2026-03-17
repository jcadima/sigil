<?php
declare(strict_types=1);
namespace Sigil\Rules\MySQL;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class EolVersionRule extends AbstractRule
{
    private const EOL = ['5.5' => '2018-12-31', '5.6' => '2021-02-28', '5.7' => '2023-10-31'];
    public function evaluate(ScanContext $context): FindingCollection
    {
        $image = '';
        foreach ($context->docker->getServices() as $name => $svc) {
            $img = strtolower($context->docker->getImage($name) ?? '');
            if (str_contains($img, 'mysql')) { $image = $img; break; }
        }
        foreach (self::EOL as $ver => $eolDate) {
            if (str_contains($image, 'mysql:' . $ver) || str_contains($image, 'mysql/' . $ver)) {
                if (time() > strtotime($eolDate)) {
                    return $this->fail($this->finding('M005', Severity::MEDIUM,
                        $context->dockerComposePath ?? 'docker-compose.yml', 0,
                        sprintf('MySQL %s reached EOL on %s.', $ver, $eolDate), 'mysql',
                        new Remediation('Upgrade to MySQL 8.0+.', null, ['Update image to mysql:8.0']),
                    ));
                }
            }
        }
        return $this->pass();
    }
    public function getSeverity(): Severity { return Severity::MEDIUM; }
    public function getCategory(): string { return 'mysql'; }
    public function getRemediation(): Remediation { return new Remediation('Upgrade MySQL to a supported version.'); }
}

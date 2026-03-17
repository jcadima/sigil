<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\NvdClient;
use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;
use Symfony\Component\Process\Process;

class ComposerVulnerabilitiesRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection  = new FindingCollection();
        $projectPath = $context->projectPath;

        if (!file_exists($projectPath . '/composer.json')) {
            return $this->pass();
        }

        // Try composer audit first
        $findings = $this->runComposerAudit($projectPath);

        if ($findings === null) {
            // Fallback to NVD client
            $findings = $this->checkViaNvd($context);
        }

        foreach ($findings as $finding) {
            $collection->add($finding);
        }

        return $collection;
    }

    private function runComposerAudit(string $projectPath): ?array
    {
        try {
            $process = new Process(['composer', 'audit', '--format=json', '--no-interaction'], $projectPath);
            $process->setTimeout(30);
            $process->run();

            if ($process->getExitCode() === 127) {
                return null; // composer not found
            }

            $output = $process->getOutput() ?: $process->getErrorOutput();
            $data   = json_decode($output, true);

            if (!is_array($data)) {
                return null;
            }

            $findings = [];
            foreach ($data['advisories'] ?? [] as $packageName => $advisories) {
                foreach ($advisories as $advisory) {
                    $findings[] = $this->finding(
                        'L008',
                        Severity::MEDIUM,
                        $projectPath . '/composer.lock',
                        0,
                        sprintf(
                            'Vulnerable package: %s — %s (CVE: %s)',
                            $packageName,
                            $advisory['title'] ?? 'Unknown vulnerability',
                            $advisory['cve'] ?? 'N/A',
                        ),
                        'laravel',
                        new Remediation(
                            'Run composer update ' . $packageName . ' to get the latest patched version.',
                            null,
                            ['composer update ' . $packageName],
                        ),
                    );
                }
            }

            return $findings;
        } catch (\Throwable) {
            return null;
        }
    }

    private function checkViaNvd(ScanContext $context): array
    {
        $client   = new NvdClient();
        $packages = $context->composer->getPackages();
        $findings = [];

        // Only check a subset to avoid API hammering
        $critical = array_keys(array_filter($packages, fn($v) => str_starts_with($v, 'v') || !empty($v)));
        $toCheck  = array_slice($critical, 0, 10); // limit to 10

        foreach ($toCheck as $pkg) {
            $cves = $client->getCves($pkg);
            foreach ($cves as $cve) {
                $findings[] = $this->finding(
                    'L008',
                    Severity::MEDIUM,
                    $context->projectPath . '/composer.lock',
                    0,
                    sprintf('Package %s may have known vulnerability: %s', $pkg, $cve),
                    'laravel',
                    new Remediation('Check NVD for ' . $cve . ' and update ' . $pkg),
                );
            }
        }

        return $findings;
    }

    public function getSeverity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Run composer audit and update vulnerable packages.');
    }
}

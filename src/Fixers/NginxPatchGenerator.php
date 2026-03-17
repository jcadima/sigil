<?php

declare(strict_types=1);

namespace Sigil\Fixers;

use Sigil\Engine\ScanContext;
use Sigil\Rules\Finding;
use Sigil\ValueObjects\FixResult;

class NginxPatchGenerator implements FixerInterface
{
    private string $patchDir;

    public function __construct(string $patchDir = '.sigil/patches')
    {
        $this->patchDir = $patchDir;
    }

    public function apply(ScanContext $context): FixResult
    {
        return FixResult::failure('Use generatePatch() directly.');
    }

    /**
     * Generate a unified diff patch file for an nginx finding.
     * Does NOT apply the patch — outputs to .sigil/patches/
     */
    public function generatePatch(Finding $finding, string $patchContent): FixResult
    {
        if (!is_dir($this->patchDir)) {
            mkdir($this->patchDir, 0755, true);
        }

        $filename  = $this->patchDir . '/' . $finding->ruleId . '_' . date('Ymd_His') . '.patch';
        $patchRef  = $finding->remediation->patchRef ?? '';
        $stubPath  = __DIR__ . '/../../stubs/' . $patchRef;

        $header = sprintf(
            "--- a/%s\n+++ b/%s\n@@ -0,0 +1 @@\n",
            basename($finding->file),
            basename($finding->file),
        );

        // Load stub if available
        if ($patchRef && file_exists($stubPath)) {
            $stub    = file_get_contents($stubPath);
            $content = $header . $stub;
        } else {
            $content = $header . $patchContent;
        }

        if (file_put_contents($filename, $content) === false) {
            return FixResult::failure("Failed to write patch to {$filename}");
        }

        return FixResult::success("Patch written to {$filename}. Apply manually with: patch -p1 < {$filename}", $filename);
    }
}

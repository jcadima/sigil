<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Fixers\FilesystemPermFixer;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;
use Sigil\ValueObjects\FixResult;

class StorageWorldWritableRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $storage = $context->projectPath . '/storage';

        if (!$context->filesystem->exists($storage)) {
            return $this->pass();
        }

        if (!$context->filesystem->hasOctalMode($storage, 0777)) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L006',
            Severity::HIGH,
            $storage,
            0,
            'storage/ directory has world-writable permissions (0777). PHP web shells can be dropped here.',
            'laravel',
            new Remediation(
                'Restrict storage/ permissions to 0755 or 0775.',
                null,
                [
                    'chmod 755 storage/',
                    'chmod -R 755 storage/',
                    'Ensure www-data owns the directory',
                ],
            ),
            true,
        ));
    }

    public function getSeverity(): Severity
    {
        return Severity::HIGH;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('chmod 755 storage/ and ensure www-data owns it.');
    }

    public function canAutoFix(): bool
    {
        return true;
    }

    public function applyFix(ScanContext $context): FixResult
    {
        $fixer = new FilesystemPermFixer();
        return $fixer->fix($context->projectPath . '/storage', 0755);
    }
}

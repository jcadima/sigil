<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class CsrfMiddlewareMissingRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        // Check app/Http/Kernel.php for VerifyCsrfToken
        $kernelPath = $context->projectPath . '/app/Http/Kernel.php';

        if (!file_exists($kernelPath)) {
            // Not a Laravel app or using newer bootstrapped structure
            // Try bootstrap/app.php for Laravel 11+
            $bootstrapPath = $context->projectPath . '/bootstrap/app.php';
            if (!file_exists($bootstrapPath)) {
                return $this->pass();
            }

            $content = file_get_contents($bootstrapPath);
            if ($content && (
                str_contains($content, 'VerifyCsrfToken') ||
                str_contains($content, 'csrf') ||
                str_contains($content, 'withMiddleware')
            )) {
                return $this->pass();
            }

            return $this->fail($this->finding(
                'L005',
                Severity::HIGH,
                $bootstrapPath,
                0,
                'CSRF middleware (VerifyCsrfToken) not detected in application bootstrap.',
                'laravel',
                new Remediation(
                    'Ensure VerifyCsrfToken middleware is registered.',
                    null,
                    ['Add VerifyCsrfToken to your middleware stack.'],
                ),
            ));
        }

        $content = file_get_contents($kernelPath);
        if ($content && str_contains($content, 'VerifyCsrfToken')) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L005',
            Severity::HIGH,
            $kernelPath,
            0,
            'VerifyCsrfToken middleware is not registered in app/Http/Kernel.php.',
            'laravel',
            new Remediation(
                'Add VerifyCsrfToken to $middlewareGroups[\'web\'] in Kernel.php.',
                null,
                ['Add \\App\\Http\\Middleware\\VerifyCsrfToken::class to web middleware group'],
            ),
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
        return new Remediation('Register VerifyCsrfToken in your middleware stack.');
    }
}

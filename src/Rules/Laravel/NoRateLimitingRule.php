<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class NoRateLimitingRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $routeFiles = [
            $context->projectPath . '/routes/web.php',
            $context->projectPath . '/routes/api.php',
            $context->projectPath . '/routes/auth.php',
        ];

        $hasLoginRoute   = false;
        $hasRateLimit    = false;

        foreach ($routeFiles as $file) {
            if (!file_exists($file)) {
                continue;
            }

            $content = file_get_contents($file);
            if (!$content) {
                continue;
            }

            if (
                str_contains($content, '/login') ||
                str_contains($content, '/register') ||
                str_contains($content, 'auth')
            ) {
                $hasLoginRoute = true;
            }

            if (
                str_contains($content, 'throttle') ||
                str_contains($content, 'RateLimiter') ||
                str_contains($content, 'limit_req')
            ) {
                $hasRateLimit = true;
            }
        }

        // Also check RouteServiceProvider for throttle middleware
        $providerPath = $context->projectPath . '/app/Providers/RouteServiceProvider.php';
        if (file_exists($providerPath)) {
            $content = file_get_contents($providerPath);
            if ($content && str_contains($content, 'throttle')) {
                $hasRateLimit = true;
            }
        }

        if (!$hasLoginRoute || $hasRateLimit) {
            return $this->pass();
        }

        return $this->fail($this->finding(
            'L007',
            Severity::MEDIUM,
            $context->projectPath . '/routes/web.php',
            0,
            'No rate limiting detected on auth routes. Login/register endpoints are vulnerable to brute force.',
            'laravel',
            new Remediation(
                'Apply throttle middleware to auth routes.',
                null,
                [
                    'Option 1: Route::middleware([\'throttle:6,1\'])->group(...)',
                    'Option 2: Define rate limiter in RouteServiceProvider',
                ],
            ),
        ));
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
        return new Remediation('Apply throttle:6,1 middleware to login/register routes.');
    }
}

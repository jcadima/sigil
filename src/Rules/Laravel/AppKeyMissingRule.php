<?php

declare(strict_types=1);

namespace Sigil\Rules\Laravel;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class AppKeyMissingRule extends AbstractRule
{
    private const DEFAULT_KEYS = [
        '',
        'SomeRandomString',
        'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    ];

    public function evaluate(ScanContext $context): FindingCollection
    {
        $key = $context->env->get('APP_KEY') ?? '';

        if (in_array($key, self::DEFAULT_KEYS, true)) {
            return $this->fail($this->finding(
                'L003',
                Severity::CRITICAL,
                $context->projectPath . '/.env',
                0,
                'APP_KEY is missing or set to a default value. Encryption is broken.',
                'laravel',
                new Remediation(
                    'Generate a new APP_KEY using: php artisan key:generate',
                    null,
                    ['Run: php artisan key:generate', 'Verify APP_KEY is set in .env'],
                ),
            ));
        }

        // Key exists but sanity check it looks like a proper base64 key
        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7));
            if ($decoded === false || strlen($decoded) < 32) {
                return $this->fail($this->finding(
                    'L003',
                    Severity::CRITICAL,
                    $context->projectPath . '/.env',
                    0,
                    'APP_KEY appears malformed or too short. Encryption may be insecure.',
                    'laravel',
                    new Remediation('Regenerate APP_KEY: php artisan key:generate'),
                ));
            }
        }

        return $this->pass();
    }

    public function getSeverity(): Severity
    {
        return Severity::CRITICAL;
    }

    public function getCategory(): string
    {
        return 'laravel';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Run: php artisan key:generate');
    }
}

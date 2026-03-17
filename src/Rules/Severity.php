<?php

declare(strict_types=1);

namespace Sigil\Rules;

enum Severity: string
{
    case CRITICAL = 'CRITICAL';
    case HIGH     = 'HIGH';
    case MEDIUM   = 'MEDIUM';
    case LOW      = 'LOW';
    case INFO     = 'INFO';

    public function scoreDeduction(): int
    {
        return match($this) {
            self::CRITICAL => 25,
            self::HIGH     => 10,
            self::MEDIUM   => 5,
            self::LOW      => 2,
            self::INFO     => 0,
        };
    }

    public function color(): string
    {
        return match($this) {
            self::CRITICAL => 'red',
            self::HIGH     => 'yellow',
            self::MEDIUM   => 'cyan',
            self::LOW      => 'blue',
            self::INFO     => 'white',
        };
    }
}

<?php

declare(strict_types=1);

namespace Sigil\ValueObjects;

enum DatabaseType: string
{
    case MYSQL      = 'mysql';
    case MARIADB    = 'mariadb';
    case POSTGRESQL = 'postgresql';
    case UNKNOWN    = 'unknown';
}

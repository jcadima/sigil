<?php

declare(strict_types=1);

namespace Sigil;

use Sigil\Commands\DriftCommand;
use Sigil\Commands\EnforceCommand;
use Sigil\Commands\RulesCommand;
use Sigil\Commands\ScanCommand;
use Sigil\Commands\SnapshotCommand;
use Symfony\Component\Console\Application as ConsoleApplication;

class Application extends ConsoleApplication
{
    private const VERSION = '1.0.0';
    private const NAME    = 'SIGIL';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);

        $this->addCommands([
            new ScanCommand(),
            new EnforceCommand(),
            new DriftCommand(),
            new SnapshotCommand(),
            new RulesCommand(),
        ]);

        $this->setDefaultCommand('scan');
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Engine;

use Sigil\Parsers\ComposerConfig;
use Sigil\Parsers\DatabaseConfig;
use Sigil\Parsers\DockerConfig;
use Sigil\Parsers\EnvConfig;
use Sigil\Parsers\FilesystemInfo;
use Sigil\Parsers\NginxConfig;
use Sigil\Parsers\PhpIniConfig;
use Sigil\ValueObjects\DatabaseType;

class ScanContext
{
    public string         $projectPath  = '';
    public string         $environment  = 'production';
    public DatabaseType   $dbType       = DatabaseType::UNKNOWN;
    public EnvConfig      $env;
    public NginxConfig    $nginx;
    public DockerConfig   $docker;
    public PhpIniConfig   $phpIni;
    public ComposerConfig $composer;
    public FilesystemInfo $filesystem;
    public DatabaseConfig $database;
    public ?string        $dockerComposePath = null;
    public ?string        $nginxConfigPath   = null;
    public ?string        $phpIniPath        = null;

    public function __construct()
    {
        $this->env        = new EnvConfig();
        $this->nginx      = new NginxConfig();
        $this->docker     = new DockerConfig();
        $this->phpIni     = new PhpIniConfig();
        $this->composer   = new ComposerConfig();
        $this->filesystem = new FilesystemInfo();
        $this->database   = new DatabaseConfig();
    }
}

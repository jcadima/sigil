<?php

declare(strict_types=1);

namespace Sigil\Engine;

use Sigil\Rules\FindingCollection;

class SnapshotManager
{
    private const HMAC_KEY_FILE = '.sigil/snapshot.key';

    public function __construct(private string $snapshotDir = '.sigil/snapshots')
    {
    }

    public function save(FindingCollection $findings, string $projectPath): string
    {
        $this->ensureDir($this->snapshotDir);

        $data = json_encode([
            'timestamp'   => time(),
            'project'     => $projectPath,
            'score'       => $findings->calculateScore(),
            'findings'    => $findings->toArray(),
        ], JSON_PRETTY_PRINT);

        $key       = $this->getOrCreateKey();
        $signature = hash_hmac('sha256', $data, $key);
        $payload   = json_encode(['data' => $data, 'sig' => $signature], JSON_PRETTY_PRINT);

        $filename = $this->snapshotDir . '/snapshot_' . date('Ymd_His') . '.json';
        file_put_contents($filename, $payload);

        return $filename;
    }

    public function load(string $path): ?array
    {
        if (!file_exists($path)) {
            return null;
        }

        $payload = json_decode(file_get_contents($path), true);
        if (!is_array($payload) || !isset($payload['data'], $payload['sig'])) {
            return null;
        }

        $key       = $this->getOrCreateKey();
        $expected  = hash_hmac('sha256', $payload['data'], $key);

        if (!hash_equals($expected, $payload['sig'])) {
            return null; // Tampered
        }

        return json_decode($payload['data'], true);
    }

    public function getLatestSnapshot(): ?string
    {
        $files = glob($this->snapshotDir . '/snapshot_*.json') ?: [];
        if (empty($files)) {
            return null;
        }
        rsort($files); // Newest first
        return $files[0];
    }

    public function diff(array $previous, FindingCollection $current): array
    {
        $prevIds = array_column($previous['findings'] ?? [], 'rule_id');
        $currIds = array_map(fn($f) => $f->ruleId, $current->all());

        $newFindings      = array_diff($currIds, $prevIds);
        $resolvedFindings = array_diff($prevIds, $currIds);

        return [
            'new'      => array_values($newFindings),
            'resolved' => array_values($resolvedFindings),
            'stable'   => array_values(array_intersect($prevIds, $currIds)),
            'score_before' => $previous['score'] ?? 0,
            'score_after'  => $current->calculateScore(),
        ];
    }

    private function getOrCreateKey(): string
    {
        $keyFile = self::HMAC_KEY_FILE;
        if (file_exists($keyFile)) {
            return trim(file_get_contents($keyFile));
        }

        $this->ensureDir(dirname($keyFile));
        $key = bin2hex(random_bytes(32));
        file_put_contents($keyFile, $key);
        chmod($keyFile, 0600);

        return $key;
    }

    private function ensureDir(string $dir): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}

<?php

declare(strict_types=1);

namespace Sigil\Engine;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class NvdClient
{
    private const API_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    private const CACHE_TTL  = 86400; // 24 hours
    private string $cacheDir;
    private Client $client;

    public function __construct(string $cacheDir = '.sigil/cache/nvd')
    {
        $this->cacheDir = $cacheDir;
        $this->client   = new Client([
            'timeout'         => 10,
            'connect_timeout' => 5,
        ]);
    }

    /**
     * Get CVEs for a given package name. Returns array of CVE IDs.
     */
    public function getCves(string $packageName): array
    {
        $cacheFile = $this->cacheDir . '/' . md5($packageName) . '.json';

        // Check cache
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < self::CACHE_TTL) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        try {
            $response = $this->client->get(self::API_BASE, [
                'query' => [
                    'keywordSearch' => $packageName,
                    'resultsPerPage' => 20,
                ],
            ]);

            $data = json_decode((string) $response->getBody(), true);
            $cves = [];

            foreach ($data['vulnerabilities'] ?? [] as $vuln) {
                $cveId = $vuln['cve']['id'] ?? null;
                if ($cveId) {
                    $cves[] = $cveId;
                }
            }

            // Cache result
            $this->ensureCacheDir();
            file_put_contents($cacheFile, json_encode($cves));

            return $cves;
        } catch (GuzzleException $e) {
            // Graceful degrade — return empty, log warning
            error_log("[SIGIL] NVD API unavailable for {$packageName}: " . $e->getMessage());
            return [];
        } catch (\Throwable $e) {
            error_log("[SIGIL] NVD client error: " . $e->getMessage());
            return [];
        }
    }

    private function ensureCacheDir(): void
    {
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }
}

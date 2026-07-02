<?php
// virustotal.class.php - VirusTotal API Integration

class VirusTotal {
    private string $apiKey;
    private string $apiUrl = 'https://www.virustotal.com/api/v3/';
    private array $cache = [];
    private int $cacheTime = 3600; // 1 hour cache

    public function __construct() {
        $this->apiKey = defined('VT_API_KEY') ? VT_API_KEY : '';
    }

    /**
     * Check if API key is configured
     */
    public function isConfigured(): bool {
        return !empty($this->apiKey) && $this->apiKey !== '52ca91943e65f3a05df5dd8fe51076b5fbe7ebb318f490ae580521f54e112262';
    }

    /**
     * Scan suspicious files with VirusTotal
     */
    public function scanFindings(array $findings): array {
        if (!$this->isConfigured()) {
            return ['error' => 'VirusTotal API key not configured'];
        }

        $results = [];
        $fileHashes = [];

        // Collect unique file hashes
        foreach ($findings as $finding) {
            $file = $finding['file'] ?? '';
            if (!empty($file) && file_exists($file)) {
                $hash = $this->getFileHash($file);
                if ($hash) {
                    $fileHashes[$hash] = $file;
                }
            }
        }

        // Limit to 10 files per request to avoid rate limiting
        $fileHashes = array_slice($fileHashes, 0, 10);

        foreach ($fileHashes as $hash => $file) {
            $result = $this->checkHash($hash);
            if ($result) {
                $results[$file] = $result;
            }
        }

        return $results;
    }

    /**
     * Check file hash against VirusTotal
     */
    private function checkHash(string $hash): ?array {
        // Check cache first
        $cacheKey = 'vt_' . $hash;
        if (isset($this->cache[$cacheKey]) && (time() - $this->cache[$cacheKey]['time']) < $this->cacheTime) {
            return $this->cache[$cacheKey]['data'];
        }

        $url = $this->apiUrl . 'files/' . $hash;
        $headers = [
            'x-apikey: ' . $this->apiKey
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            $result = $this->parseResponse($data);
            
            // Cache the result
            $this->cache[$cacheKey] = [
                'time' => time(),
                'data' => $result
            ];
            
            return $result;
        }

        return null;
    }

    /**
     * Parse VirusTotal response
     */
    private function parseResponse(array $data): array {
        $attributes = $data['data']['attributes'] ?? [];
        
        return [
            'positives' => $attributes['last_analysis_stats']['malicious'] ?? 0,
            'total' => array_sum($attributes['last_analysis_stats'] ?? []) ?: 0,
            'scan_date' => $attributes['last_analysis_date'] ?? '',
            'reputation' => $attributes['reputation'] ?? 0,
            'threat_score' => $this->calculateThreatScore($attributes),
            'detected_by' => $this->getDetectedEngines($attributes)
        ];
    }

    /**
     * Calculate threat score (0-100)
     */
    private function calculateThreatScore(array $attributes): int {
        $stats = $attributes['last_analysis_stats'] ?? [];
        $total = array_sum($stats) ?: 1;
        $malicious = $stats['malicious'] ?? 0;
        
        return min(100, round(($malicious / $total) * 100));
    }

    /**
     * Get list of engines that detected the file
     */
    private function getDetectedEngines(array $attributes): array {
        $engines = [];
        $results = $attributes['last_analysis_results'] ?? [];
        
        foreach ($results as $engine => $result) {
            if (($result['category'] ?? '') === 'malicious') {
                $engines[] = $engine;
            }
        }
        
        return array_slice($engines, 0, 5);
    }

    /**
     * Get SHA-256 hash of file
     */
    private function getFileHash(string $filePath): ?string {
        if (!file_exists($filePath)) {
            return null;
        }
        return hash_file('sha256', $filePath);
    }

    /**
     * Upload file to VirusTotal for scanning
     */
    public function uploadFile(string $filePath): ?array {
        if (!$this->isConfigured() || !file_exists($filePath)) {
            return null;
        }

        $url = $this->apiUrl . 'files';
        $headers = ['x-apikey: ' . $this->apiKey];
        
        $fileContent = file_get_contents($filePath);
        if ($fileContent === false) {
            return null;
        }

        $post = [
            'file' => new CURLFile($filePath)
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            $hash = $data['data']['id'] ?? null;
            
            if ($hash) {
                // Wait a moment and check results
                sleep(2);
                return $this->checkHash($hash);
            }
        }

        return null;
    }
}
?>
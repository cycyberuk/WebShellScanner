<?php
// scanner.class.php - Core Scanning Logic

require_once 'signatures.db.php';

class WebShellScanner {
    private $signatures;
    private $scanResults;
    private $startTime;
    private $totalFilesScanned;
    private $totalSizeScanned;
    private $excludedDirs;
    private $maxFileSize;
    private $allowedExtensions;

    public function __construct() {
        $this->signatures = require 'signatures.db.php';
        $this->scanResults = [];
        $this->totalFilesScanned = 0;
        $this->totalSizeScanned = 0;
        $this->startTime = microtime(true);
        
        // Configuration - adjust as needed
        $this->excludedDirs = ['.git', 'vendor', 'node_modules', 'cache', 'logs', 'reports'];
        $this->maxFileSize = 5 * 1024 * 1024; // 5MB max file size
        $this->allowedExtensions = ['php', 'phtml', 'php5', 'php7', 'inc', 'txt', 'html', 'htm'];
    }

    /**
     * Main scan function - recursively scan directory
     */
    public function scan($directory) {
        // Normalize path and validate
        $directory = realpath($directory);
        if (!$directory || !is_dir($directory)) {
            throw new Exception("Invalid directory: " . $directory);
        }

        $this->scanDirectory($directory);
        $this->scanResults['scan_metadata'] = $this->getMetadata();
        return $this->scanResults;
    }

    /**
     * Recursively scan directory
     */
    private function scanDirectory($dir) {
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            $relativePath = str_replace($_SERVER['DOCUMENT_ROOT'], '', $path);
            
            // Skip excluded directories
            if (is_dir($path)) {
                $dirName = basename($path);
                if (in_array($dirName, $this->excludedDirs)) continue;
                $this->scanDirectory($path);
                continue;
            }

            // Skip non-PHP files (configurable)
            $extension = pathinfo($path, PATHINFO_EXTENSION);
            if (!in_array(strtolower($extension), $this->allowedExtensions)) continue;

            // Skip large files
            $fileSize = filesize($path);
            if ($fileSize > $this->maxFileSize) {
                $this->addResult($path, 'info', "File too large to scan (" . $this->formatSize($fileSize) . ")");
                continue;
            }

            $this->scanFile($path, $relativePath);
            $this->totalFilesScanned++;
            $this->totalSizeScanned += $fileSize;
        }
    }

    /**
     * Scan individual file for signatures
     */
    private function scanFile($path, $relativePath) {
        $content = file_get_contents($path);
        if ($content === false) {
            $this->addResult($path, 'info', "Could not read file");
            return;
        }

        // Check for each signature category
        foreach ($this->signatures as $severity => $category) {
            if (!isset($category['pattern']) || !is_array($category['pattern'])) {
                continue;
            }
            
            foreach ($category['pattern'] as $pattern) {
                if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    // Get line number
                    $lineNumber = $this->getLineNumber($content, $matches[0][1]);
                    
                    // Get surrounding context (3 lines before and after)
                    $context = $this->getContext($content, $matches[0][1]);
                    
                    $this->addResult(
                        $path,
                        $severity,
                        "Found dangerous pattern: " . htmlspecialchars($matches[0][0]),
                        array(
                            'line' => $lineNumber,
                            'context' => $context,
                            'matched_pattern' => $pattern,
                            'severity' => $severity,
                            'risk_score' => isset($category['risk_score']) ? $category['risk_score'] : 0,
                            'relative_path' => $relativePath,
                            'file_size' => $this->formatSize(filesize($path)),
                            'last_modified' => date('Y-m-d H:i:s', filemtime($path))
                        )
                    );
                }
            }
        }

        // Additional check for known webshell patterns
        $this->checkForWebshellPatterns($path, $content);
    }

    /**
     * Check for known webshell patterns (signature-based detection)
     */
    private function checkForWebshellPatterns($path, $content) {
        // Check for common webshell obfuscation patterns
        $obfuscationPatterns = array(
            '/[a-zA-Z0-9]{40,}\s*=\s*["\'].*["\']/i',
            '/\$\w+\s*=\s*\$\w+\.\$\w+/i',
            '/\$\w+\s*=\s*strrev\(/i',
            '/\$\w+\s*=\s*base64_decode\(/i',
            '/\$\w+\s*=\s*str_rot13\(/i',
        );

        $obfuscationScore = 0;
        foreach ($obfuscationPatterns as $pattern) {
            if (preg_match_all($pattern, $content) > 0) {
                $obfuscationScore++;
            }
        }

        if ($obfuscationScore >= 3) {
            $this->addResult(
                $path,
                'high',
                "High likelihood of obfuscation (score: $obfuscationScore/5)",
                array(
                    'severity' => 'high',
                    'risk_score' => 8,
                    'obfuscation_score' => $obfuscationScore,
                    'file_size' => $this->formatSize(filesize($path))
                )
            );
        }
    }

    /**
     * Add result to scan results
     */
    private function addResult($file, $severity, $message, $extra = array()) {
        $result = array(
            'file' => $file,
            'severity' => $severity,
            'message' => $message,
            'timestamp' => date('Y-m-d H:i:s')
        );
        
        // Merge extra data
        foreach ($extra as $key => $value) {
            $result[$key] = $value;
        }
        
        $this->scanResults['findings'][] = $result;
    }

    /**
     * Get line number from offset
     */
    private function getLineNumber($content, $offset) {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }

    /**
     * Get surrounding context
     */
    private function getContext($content, $offset, $lines = 3) {
        $linesArray = explode("\n", $content);
        $lineNumber = $this->getLineNumber($content, $offset);
        $start = max(0, $lineNumber - $lines - 1);
        $end = min(count($linesArray), $lineNumber + $lines);
        
        $context = array();
        for ($i = $start; $i < $end; $i++) {
            $context[] = array(
                'line' => $i + 1,
                'content' => htmlspecialchars(trim($linesArray[$i]))
            );
        }
        return $context;
    }

    /**
     * Format file size
     */
    private function formatSize($bytes) {
        if ($bytes >= 1073741824) {
            return number_format($bytes / 1073741824, 2) . ' GB';
        } elseif ($bytes >= 1048576) {
            return number_format($bytes / 1048576, 2) . ' MB';
        } elseif ($bytes >= 1024) {
            return number_format($bytes / 1024, 2) . ' KB';
        } else {
            return $bytes . ' bytes';
        }
    }

/**
 * Get scan metadata
 */
private function getMetadata(): array {
    $totalFindings = count($this->scanResults['findings'] ?? []);
    
    return [
        'scan_start' => date('Y-m-d H:i:s', (int)$this->startTime), // Cast to int
        'scan_end' => date('Y-m-d H:i:s'),
        'duration' => round(microtime(true) - $this->startTime, 2) . ' seconds',
        'files_scanned' => $this->totalFilesScanned,
        'total_size_scanned' => $this->formatSize($this->totalSizeScanned),
        'total_findings' => $totalFindings,
        'finding_summary' => $this->getFindingSummary()
    ];
}

/**
 * Add VirusTotal results to findings
 */
public function addVirusTotalResults(array $vtResults): void {
    if (empty($vtResults)) {
        return;
    }
    
    foreach ($this->scanResults['findings'] ?? [] as &$finding) {
        $file = $finding['file'] ?? '';
        if (isset($vtResults[$file])) {
            $finding['vt_results'] = $vtResults[$file];
            // Boost risk score if VT detected something
            if (($vtResults[$file]['positives'] ?? 0) > 0) {
                $finding['risk_score'] = min(20, ($finding['risk_score'] ?? 0) + 5);
            }
        }
    }
}

    /**
     * Get summary of findings by severity
     */
    private function getFindingSummary() {
        $summary = array('critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0);
        if (isset($this->scanResults['findings'])) {
            foreach ($this->scanResults['findings'] as $finding) {
                $severity = isset($finding['severity']) ? $finding['severity'] : 'info';
                if (isset($summary[$severity])) {
                    $summary[$severity]++;
                }
            }
        }
        return $summary;
    }

    /**
     * Get statistics for a specific file
     */
    public function getFileStats($path) {
        if (!file_exists($path)) return null;
        
        $stats = array(
            'path' => $path,
            'size' => $this->formatSize(filesize($path)),
            'modified' => date('Y-m-d H:i:s', filemtime($path)),
            'permissions' => substr(sprintf('%o', fileperms($path)), -4)
        );
        
        if (function_exists('posix_getpwuid')) {
            $ownerInfo = posix_getpwuid(fileowner($path));
            $stats['owner'] = isset($ownerInfo['name']) ? $ownerInfo['name'] : 'N/A';
        } else {
            $stats['owner'] = 'N/A';
        }
        
        return $stats;
    }
}
?>
<?php
// config.php - Configuration Settings

// ===== VirusTotal API =====
// Get your free API key from: https://www.virustotal.com/gui/join-us
define('VT_API_KEY', '52ca91943e65f3a05df5dd8fe51076b5fbe7ebb318f490ae580521f54e112262'); // Replace with your actual API key

// ===== Scan Settings =====
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('ENABLE_LOGGING', true);
define('LOG_FILE', 'logs/scan_activity.log');

// ===== Create necessary directories =====
foreach (['logs', 'reports'] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// ===== Rate Limiting for API =====
define('VT_RATE_LIMIT', 4); // 4 requests per minute (free tier)
define('VT_CACHE_TIME', 3600); // Cache results for 1 hour
?>
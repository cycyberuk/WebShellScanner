<?php
// signatures.db.php - Suspicious Code Pattern Database

return [
    'critical' => [
        'pattern' => [
            '/eval\s*\(/i',
            '/base64_decode\s*\(/i',
            '/gzinflate\s*\(/i',
            '/str_rot13\s*\(/i',
            '/assert\s*\(/i',
            '/system\s*\(/i',
            '/shell_exec\s*\(/i',
            '/exec\s*\(/i',
            '/passthru\s*\(/i',
            '/pcntl_exec\s*\(/i',
            '/popen\s*\(/i',
            '/proc_open\s*\(/i',
            '/`.*`/',
            '/\$_GET\s*\[.*\]\s*\)/i',
            '/\$_POST\s*\[.*\]\s*\)/i',
            '/\$_COOKIE\s*\[.*\]\s*\)/i',
            '/file_put_contents\s*\(/i',
            '/fwrite\s*\(/i',
            '/chmod\s*\(/i',
            '/chown\s*\(/i',
        ],
        'description' => 'Critical: Code execution, system commands, or file manipulation detected.',
        'risk_score' => 10
    ],
    'high' => [
        'pattern' => [
            '/create_function\s*\(/i',
            '/call_user_func\s*\(/i',
            '/call_user_func_array\s*\(/i',
            '/preg_replace\s*\(.*\/e/i',
            '/extract\s*\(/i',
            '/parse_str\s*\(/i',
            '/include\s*\(\s*\$_/i',
            '/require\s*\(\s*\$_/i',
            '/file_get_contents\s*\(\s*http/i',
            '/curl_exec\s*\(/i',
        ],
        'description' => 'High: Suspicious functions often used in malicious code.',
        'risk_score' => 7
    ],
    'medium' => [
        'pattern' => [
            '/\$_SESSION\s*\[.*\]\s*=\s*eval/i',
            '/\$_REQUEST\s*\[.*\]\s*=\s*eval/i',
            '/array_map\s*\(/i',
            '/usort\s*\(/i',
            '/uksort\s*\(/i',
            '/uasort\s*\(/i',
            '/ob_start\s*\(/i',
            '/error_reporting\s*\(0\)/i',
            '/@\s*include/i',
            '/@\s*require/i',
        ],
        'description' => 'Medium: Obfuscation or suspicious patterns that warrant review.',
        'risk_score' => 4
    ],
    'info' => [
        'pattern' => [
            '/phpinfo\s*\(/i',
            '/\$_SERVER\s*\[.*\]/i',
            '/ini_set\s*\(/i',
            '/set_time_limit\s*\(0\)/i',
        ],
        'description' => 'Informational: These may be benign but should be reviewed.',
        'risk_score' => 1
    ]
];
?>
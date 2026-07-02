<?php
// report.class.php - Report Generation

class ReportGenerator {
    private array $scanData;
    private string $outputDir;

    public function __construct(array $scanData, string $outputDir = 'reports') {
        $this->scanData = $scanData;
        $this->outputDir = $outputDir;
        
        if (!is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
        }
    }

    /**
     * Generate HTML report
     */
    public function generateHTML(?string $filename = null): string {
        $filename ??= 'scan_report_' . date('Y-m-d_His') . '.html';
        $filepath = $this->outputDir . '/' . $filename;
        file_put_contents($filepath, $this->buildHTMLReport());
        return $filepath;
    }

    /**
     * Build HTML report content
     */
    private function buildHTMLReport(): string {
        $findings = $this->scanData['findings'] ?? [];
        $metadata = $this->scanData['scan_metadata'] ?? [];
        
        // Group findings by severity
        $groupedFindings = [
            'critical' => [],
            'high' => [],
            'medium' => [],
            'info' => []
        ];
        
        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'info';
            if (isset($groupedFindings[$severity])) {
                $groupedFindings[$severity][] = $finding;
            }
        }
        
        // Get metadata with defaults
        $duration = $metadata['duration'] ?? 'N/A';
        $filesScanned = $metadata['files_scanned'] ?? 0;
        $totalSize = $metadata['total_size_scanned'] ?? 'N/A';
        $totalFindings = $metadata['total_findings'] ?? 0;
        $scanEnd = $metadata['scan_end'] ?? date('Y-m-d H:i:s');
        
        $summary = $metadata['finding_summary'] ?? [];
        $criticalCount = $summary['critical'] ?? 0;
        $highCount = $summary['high'] ?? 0;
        $mediumCount = $summary['medium'] ?? 0;
        $infoCount = $summary['info'] ?? 0;
        
        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShell Scanner Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { max-width: 1400px; }
        .risk-critical { border-left: 5px solid #dc3545; }
        .risk-high { border-left: 5px solid #ffc107; }
        .risk-medium { border-left: 5px solid #17a2b8; }
        .risk-info { border-left: 5px solid #6c757d; }
        .risk-card { margin-bottom: 20px; }
        .finding-count { font-size: 24px; font-weight: bold; }
        .code-snippet { background: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row mb-4">
            <div class="col">
                <h1>🛡️ WebShell Scanner Report</h1>
                <p class="lead">Automated security scan for malicious code patterns</p>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Scan Duration</h6>
                        <p class="card-text">{$duration}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Files Scanned</h6>
                        <p class="card-text">{$filesScanned}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Total Size</h6>
                        <p class="card-text">{$totalSize}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Findings</h6>
                        <p class="card-text">{$totalFindings}</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col">
                <h3>📊 Finding Summary</h3>
                <div class="row">
                    <div class="col-md-3">
                        <div class="card bg-danger text-white summary-card">
                            <div class="card-body text-center">
                                <h5>Critical</h5>
                                <p class="finding-count">{$criticalCount}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning summary-card">
                            <div class="card-body text-center">
                                <h5>High</h5>
                                <p class="finding-count">{$highCount}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-info summary-card">
                            <div class="card-body text-center">
                                <h5>Medium</h5>
                                <p class="finding-count">{$mediumCount}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-secondary text-white summary-card">
                            <div class="card-body text-center">
                                <h5>Info</h5>
                                <p class="finding-count">{$infoCount}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col">
                <h3>🔍 Detailed Findings</h3>
HTML;

        if (!empty($groupedFindings['critical'])) {
            $html .= $this->renderFindingSection('Critical', 'critical', $groupedFindings['critical']);
        }
        if (!empty($groupedFindings['high'])) {
            $html .= $this->renderFindingSection('High Risk', 'high', $groupedFindings['high']);
        }
        if (!empty($groupedFindings['medium'])) {
            $html .= $this->renderFindingSection('Medium Risk', 'medium', $groupedFindings['medium']);
        }
        if (!empty($groupedFindings['info'])) {
            $html .= $this->renderFindingSection('Informational', 'info', $groupedFindings['info']);
        }

        if (empty($findings)) {
            $html .= '<div class="alert alert-success"><h4>✅ No suspicious patterns found!</h4></div>';
        }

        $html .= <<<HTML
            </div>
        </div>
        <div class="row mt-5">
            <div class="col">
                <hr>
                <p class="text-muted text-center">Generated by WebShell Scanner • {$scanEnd}</p>
            </div>
        </div>
    </div>
</body>
</html>
HTML;

        return $html;
    }

    private function renderFindingSection(string $title, string $severity, array $findings): string {
        $html = "<h4 class='mt-4'>{$title}</h4>";
        
        foreach ($findings as $finding) {
            $file = htmlspecialchars($finding['file'] ?? 'Unknown');
            $message = htmlspecialchars($finding['message'] ?? 'No message');
            $context = $finding['context'] ?? [];
            $line = $finding['line'] ?? '?';
            $bgColor = match($severity) {
                'critical' => 'danger',
                'high' => 'warning',
                'medium' => 'info',
                default => 'secondary'
            };
            
            $html .= "<div class='card risk-{$severity} risk-card'>
                <div class='card-body'>
                    <h5 class='card-title'>
                        <span class='badge bg-{$bgColor}'>{$severity}</span>
                        {$message}
                    </h5>
                    <p class='card-text'>📁 {$file} | Line: {$line}</p>";
            
            if (!empty($context)) {
                $html .= "<div class='code-snippet'><pre style='margin:0;font-size:12px;'>";
                foreach ($context as $lineData) {
                    $lineNum = $lineData['line'] ?? '?';
                    $content = $lineData['content'] ?? '';
                    $style = ($lineNum == $line) ? 'background:#fff3cd;border-left:3px solid #ffc107;' : '';
                    $html .= "<div style='{$style}padding:2px 5px;'><span style='color:#6c757d;'>{$lineNum}.</span> {$content}</div>";
                }
                $html .= "</pre></div>";
            }
            
            $html .= "</div></div>";
        }
        
        return $html;
    }

    public function generateJSON(?string $filename = null): string {
        $filename ??= 'scan_report_' . date('Y-m-d_His') . '.json';
        $filepath = $this->outputDir . '/' . $filename;
        file_put_contents($filepath, json_encode($this->scanData, JSON_PRETTY_PRINT));
        return $filepath;
    }

    public function generateCSV(?string $filename = null): string {
        $filename ??= 'scan_report_' . date('Y-m-d_His') . '.csv';
        $filepath = $this->outputDir . '/' . $filename;
        $handle = fopen($filepath, 'w');
        
        fputcsv($handle, ['File', 'Severity', 'Message', 'Line', 'Timestamp']);
        
        foreach ($this->scanData['findings'] ?? [] as $finding) {
            fputcsv($handle, [
                $finding['file'] ?? '',
                $finding['severity'] ?? '',
                $finding['message'] ?? '',
                $finding['line'] ?? '',
                $finding['timestamp'] ?? ''
            ]);
        }
        
        fclose($handle);
        return $filepath;
    }
}
?>
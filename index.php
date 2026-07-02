<?php
// index.php - Main Scanner Interface - Dark Theme v2.0

require_once 'scanner.class.php';
require_once 'report.class.php';
require_once 'config.php';
require_once 'virustotal.class.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set execution time for large scans
set_time_limit(0);

// Handle scan request
$scanResult = null;
$reportFiles = [];
$error = null;
$vtResults = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan_path'])) {
    $scanPath = trim($_POST['scan_path']);
    $documentRoot = str_replace('\\', '/', $_SERVER['DOCUMENT_ROOT']);
    
    // Clean the path
    $scanPath = trim($scanPath, '/\\ ');
    $scanPath = str_replace('\\', '/', $scanPath);
    
    // Check if it's an absolute path
    if (preg_match('/^[a-zA-Z]:/', $scanPath)) {
        $fullPath = str_replace('\\', '/', $scanPath);
    } else {
        $fullPath = $documentRoot . '/' . $scanPath;
    }
    
    $fullPath = str_replace(['//', '\\\\'], '/', $fullPath);
    
    if (is_dir($fullPath)) {
        try {
            $scanner = new WebShellScanner();
            $scanResult = $scanner->scan($fullPath);
            
            // VirusTotal Integration
            if (defined('VT_API_KEY') && VT_API_KEY !== 'YOUR_API_KEY_HERE') {
                $vt = new VirusTotal();
                $vtResults = $vt->scanFindings($scanResult['findings'] ?? []);
            }
            
            // Generate reports
            $reportGenerator = new ReportGenerator($scanResult, 'reports');
            $reportFiles = [
                'html' => $reportGenerator->generateHTML(),
                'json' => $reportGenerator->generateJSON(),
                'csv' => $reportGenerator->generateCSV()
            ];
        } catch (Exception $e) {
            $error = "Scan failed: " . $e->getMessage();
        }
    } else {
        $error = "Directory not found: <strong>" . htmlspecialchars($fullPath) . "</strong>";
    }
}

// Get list of available reports
$availableReports = glob('reports/*.{html,json,csv}', GLOB_BRACE) ?: [];

// Get POST value safely
$postedPath = htmlspecialchars($_POST['scan_path'] ?? '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>WebShell Scanner - Advanced Security Tool</title>
    
    <!-- Bootstrap 5 Dark Theme -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,300;0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
    
    <style>
        /* ===== CSS Variables for Dark Theme ===== */
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111927;
            --bg-card: #1a2332;
            --bg-card-hover: #22304a;
            --text-primary: #e8edf5;
            --text-secondary: #8899bb;
            --text-muted: #5a6b8a;
            --border-color: #2a3a4a;
            --accent-blue: #4f8cf7;
            --accent-purple: #7c5cfc;
            --accent-cyan: #00d4ff;
            --accent-green: #00e676;
            --accent-red: #ff5252;
            --accent-orange: #ffab40;
            --gradient-primary: linear-gradient(135deg, #4f8cf7 0%, #7c5cfc 100%);
            --gradient-secondary: linear-gradient(135deg, #00d4ff 0%, #7c5cfc 100%);
            --shadow-card: 0 8px 32px rgba(0, 0, 0, 0.4);
            --radius-card: 16px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        /* ===== Global Styles ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ===== Scrollbar Styling ===== */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: var(--bg-secondary);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb {
            background: var(--accent-blue);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-purple);
        }

        /* ===== Animated Background ===== */
        .bg-animated {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: -1;
            background: 
                radial-gradient(ellipse at 10% 20%, rgba(79, 140, 247, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 90% 80%, rgba(124, 92, 252, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(0, 212, 255, 0.03) 0%, transparent 70%);
        }

        /* ===== Navbar ===== */
        .navbar-custom {
            background: rgba(17, 25, 39, 0.8);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 0;
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .navbar-custom .brand {
            font-weight: 800;
            font-size: 1.4rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-decoration: none;
        }

        .navbar-custom .brand i {
            -webkit-text-fill-color: var(--accent-cyan);
            margin-right: 8px;
        }

        .nav-badge {
            background: var(--accent-red);
            color: white;
            font-size: 0.6rem;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
            margin-left: 6px;
        }

        /* ===== Cards ===== */
        .card-glass {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-card);
            box-shadow: var(--shadow-card);
            transition: var(--transition);
            backdrop-filter: blur(10px);
        }

        .card-glass:hover {
            border-color: var(--accent-blue);
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(79, 140, 247, 0.15);
        }

        .card-glass .card-header {
            background: transparent;
            border-bottom: 1px solid var(--border-color);
            padding: 20px 24px;
            font-weight: 600;
        }

        .card-glass .card-body {
            padding: 24px;
        }

        /* ===== Hero Section ===== */
        .hero-section {
            padding: 30px 0 20px 0;
            text-align: center;
        }

        .hero-section .hero-icon {
            font-size: 3.5rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .hero-section h1 {
            font-weight: 800;
            font-size: clamp(2rem, 5vw, 3.5rem);
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }

        .hero-section .subtitle {
            color: var(--text-secondary);
            font-size: clamp(0.9rem, 1.2vw, 1.2rem);
            max-width: 600px;
            margin: 0 auto;
        }

        /* ===== Search/Input ===== */
        .input-group-custom {
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            transition: var(--transition);
            overflow: hidden;
        }

        .input-group-custom:focus-within {
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(79, 140, 247, 0.15);
        }

        .input-group-custom .input-group-text {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            padding: 12px 16px;
        }

        .input-group-custom .form-control {
            background: transparent;
            border: none;
            color: var(--text-primary);
            padding: 12px 16px;
            font-size: 1rem;
        }

        .input-group-custom .form-control:focus {
            box-shadow: none;
        }

        .input-group-custom .form-control::placeholder {
            color: var(--text-muted);
        }

        .btn-scan {
            background: var(--gradient-primary);
            border: none;
            color: white;
            font-weight: 600;
            padding: 12px 32px;
            border-radius: 12px;
            transition: var(--transition);
            width: 100%;
        }

        .btn-scan:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(79, 140, 247, 0.4);
            color: white;
        }

        .btn-scan:active {
            transform: translateY(0);
        }

        .btn-scan:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }

        /* ===== Stats Cards ===== */
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px 20px;
            text-align: center;
            transition: var(--transition);
            height: 100%;
        }

        .stat-card:hover {
            border-color: var(--accent-blue);
            transform: translateY(-4px);
        }

        .stat-card .stat-icon {
            font-size: 1.8rem;
            margin-bottom: 6px;
        }

        .stat-card .stat-number {
            font-size: clamp(1.8rem, 3vw, 2.5rem);
            font-weight: 800;
            margin: 0;
        }

        .stat-card .stat-label {
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-card.danger .stat-number { color: var(--accent-red); }
        .stat-card.success .stat-number { color: var(--accent-green); }
        .stat-card.info .stat-number { color: var(--accent-cyan); }
        .stat-card.warning .stat-number { color: var(--accent-orange); }

        /* ===== Finding Items ===== */
        .finding-item {
            background: var(--bg-secondary);
            border-left: 4px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 12px;
            transition: var(--transition);
        }

        .finding-item:hover {
            background: var(--bg-card-hover);
        }

        .finding-item.critical { border-left-color: var(--accent-red); }
        .finding-item.high { border-left-color: var(--accent-orange); }
        .finding-item.medium { border-left-color: var(--accent-cyan); }
        .finding-item.info { border-left-color: var(--text-muted); }

        .finding-item .badge-severity {
            font-size: 0.7rem;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 20px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-critical { background: var(--accent-red); color: white; }
        .badge-high { background: var(--accent-orange); color: #1a1a2e; }
        .badge-medium { background: var(--accent-cyan); color: #1a1a2e; }
        .badge-info { background: var(--text-muted); color: white; }

        .finding-item .file-path {
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
            word-break: break-all;
        }

        .finding-item .context-code {
            background: var(--bg-primary);
            border-radius: 6px;
            padding: 10px 14px;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            overflow-x: auto;
            margin-top: 8px;
            max-height: 120px;
            overflow-y: auto;
        }

        .finding-item .context-code .highlight {
            background: rgba(255, 171, 64, 0.2);
            border-left: 3px solid var(--accent-orange);
            padding-left: 8px;
        }

        /* ===== Author Profile ===== */
        .author-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-card);
            padding: 24px;
            text-align: center;
            transition: var(--transition);
        }

        .author-card:hover {
            border-color: var(--accent-purple);
            transform: translateY(-4px);
        }

        .author-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 3px solid var(--accent-purple);
            padding: 3px;
            margin: 0 auto 16px;
            object-fit: cover;
            background: var(--bg-secondary);
        }

        .author-card .author-name {
            font-weight: 700;
            font-size: 1.3rem;
            margin-bottom: 4px;
        }

        .author-card .author-role {
            color: var(--accent-cyan);
            font-size: 0.85rem;
            font-weight: 500;
        }

        .author-card .author-bio {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin: 12px 0;
        }

        .author-social {
            display: flex;
            justify-content: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .author-social a {
            color: var(--text-secondary);
            font-size: 1.2rem;
            transition: var(--transition);
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            text-decoration: none;
        }

        .author-social a:hover {
            color: var(--accent-cyan);
            border-color: var(--accent-cyan);
            transform: translateY(-2px);
        }

        /* ===== Report Cards ===== */
        .report-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px 20px;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: space-between;
            text-decoration: none;
            color: var(--text-primary);
        }

        .report-card:hover {
            border-color: var(--accent-blue);
            transform: translateX(4px);
            color: var(--text-primary);
        }

        .report-card .report-icon {
            font-size: 1.5rem;
            margin-right: 12px;
        }

        .report-card .report-info {
            flex: 1;
        }

        .report-card .report-name {
            font-weight: 600;
            font-size: 0.9rem;
        }

        .report-card .report-meta {
            color: var(--text-muted);
            font-size: 0.75rem;
        }

        /* ===== Improvement Suggestions ===== */
        .suggestion-item {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 12px;
            border-left: 4px solid var(--accent-cyan);
            transition: var(--transition);
        }

        .suggestion-item:hover {
            background: var(--bg-card-hover);
        }

        .suggestion-item .suggestion-icon {
            font-size: 1.2rem;
            margin-right: 12px;
            color: var(--accent-cyan);
        }

        .suggestion-item .suggestion-title {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .suggestion-item .suggestion-desc {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 4px;
        }

        /* ===== Responsive ===== */
        @media (max-width: 768px) {
            .hero-section {
                padding: 20px 0 10px 0;
            }
            
            .card-glass .card-header {
                padding: 16px;
            }
            
            .card-glass .card-body {
                padding: 16px;
            }
            
            .stat-card {
                padding: 12px 16px;
            }
            
            .finding-item {
                padding: 12px 16px;
            }
            
            .author-avatar {
                width: 80px;
                height: 80px;
            }
            
            .navbar-custom .brand {
                font-size: 1.1rem;
            }
        }

        @media (max-width: 480px) {
            .hero-section .hero-icon {
                font-size: 2.5rem;
            }
            
            .btn-scan {
                font-size: 0.9rem;
                padding: 10px 20px;
            }
            
            .finding-item .file-path {
                font-size: 0.7rem;
            }
        }

        /* ===== Animations ===== */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .animate-fade-in {
            animation: fadeInUp 0.5s ease forwards;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .scanning .spinner-border {
            animation: pulse 1s ease-in-out infinite;
        }

        /* ===== VirusTotal Badge ===== */
        .vt-badge {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid rgba(0, 212, 255, 0.2);
            border-radius: 20px;
            padding: 4px 14px;
            font-size: 0.7rem;
            font-weight: 600;
            color: var(--accent-cyan);
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        /* ===== Loading Skeleton ===== */
        .skeleton {
            background: linear-gradient(90deg, var(--bg-card) 25%, var(--bg-card-hover) 50%, var(--bg-card) 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 8px;
        }

        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        /* ===== Tooltip ===== */
        .tooltip-custom {
            position: relative;
            cursor: help;
        }

        .tooltip-custom:hover::after {
            content: attr(data-tip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-card);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            white-space: nowrap;
            border: 1px solid var(--border-color);
            z-index: 100;
        }

        /* ===== Empty State ===== */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
        }

        .empty-state .empty-icon {
            font-size: 4rem;
            color: var(--text-muted);
            margin-bottom: 16px;
        }

        .empty-state h5 {
            color: var(--text-secondary);
        }

        /* Toast Notification */
        .toast-container {
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: 9999;
        }
    </style>
</head>
<body>

<!-- ===== Animated Background ===== -->
<div class="bg-animated"></div>

<!-- ===== Toast Container ===== -->
<div class="toast-container" id="toastContainer"></div>

<!-- ===== Navbar ===== -->
<nav class="navbar-custom">
    <div class="container">
        <div class="d-flex align-items-center justify-content-between">
            <a href="#" class="brand">
                <i class="fas fa-shield-alt"></i> WebShell<span style="-webkit-text-fill-color: var(--accent-cyan);">Scanner</span>
                <span class="nav-badge">v2.0</span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <span class="vt-badge d-none d-sm-inline-flex">
                    <i class="fas fa-shield-virus"></i> VirusTotal Ready
                </span>
                <a href="#author" class="text-secondary text-decoration-none d-none d-md-block">
                    <i class="fas fa-user-circle fs-5"></i>
                </a>
                <a href="#improvements" class="text-secondary text-decoration-none d-none d-md-block">
                    <i class="fas fa-lightbulb fs-5"></i>
                </a>
            </div>
        </div>
    </div>
</nav>

<!-- ===== Main Container ===== -->
<div class="container py-4">

    <!-- ===== Hero Section ===== -->
    <div class="hero-section animate-fade-in">
        <div class="hero-icon">
            <i class="fas fa-shield-halved"></i>
        </div>
        <h1>Advanced WebShell Scanner</h1>
        <p class="subtitle">
            Enterprise-grade security scanning for webshells, backdoors, and malicious code patterns By Orji, Cyrus Ebere, MCPN
        </p>
		
        <div class="d-flex justify-content-center gap-3 mt-3 flex-wrap">
            <span class="vt-badge"><i class="fas fa-check-circle"></i> 30+ Signatures</span>
            <span class="vt-badge"><i class="fas fa-chart-line"></i> Real-time Reports</span>
            <span class="vt-badge"><i class="fas fa-cloud-upload-alt"></i> VT Integration</span>
        </div>
    </div>

    <!-- ===== Scanner Form ===== -->
    <div class="row justify-content-center mt-4">
        <div class="col-lg-10 col-xl-8">
            <div class="card-glass">
                <div class="card-body">
                    <form method="POST" action="" id="scanForm">
                        <div class="row g-3">
                            <div class="col-12">
                                <label class="form-label fw-semibold text-secondary">
                                    <i class="fas fa-folder-open me-2"></i> Target Directory
                                </label>
                                <div class="input-group-custom d-flex">
                                    <span class="input-group-text">
                                        <i class="fas fa-folder"></i>
                                    </span>
                                    <input type="text" class="form-control" name="scan_path" 
                                           placeholder="Enter path (e.g., public_html, celeb, or . for root)" 
                                           value="<?= $postedPath ?>"
                                           id="scanPath"
                                           autofocus>
                                </div>
                                <div class="mt-2 d-flex flex-wrap gap-2">
                                    <small class="text-muted">
                                        <i class="fas fa-root me-1"></i> Root: <?= htmlspecialchars($_SERVER['DOCUMENT_ROOT']) ?>
                                    </small>
                                    <span class="text-muted">|</span>
                                    <small class="text-muted">Quick:</small>
                                    <span class="badge bg-secondary example-badge" onclick="setPath('.')" style="cursor:pointer;">
                                        <i class="fas fa-home"></i> .
                                    </span>
                                    <span class="badge bg-secondary example-badge" onclick="setPath('celeb')" style="cursor:pointer;">
                                        <i class="fas fa-folder"></i> celeb
                                    </span>
                                    <span class="badge bg-secondary example-badge" onclick="setPath('public_html')" style="cursor:pointer;">
                                        <i class="fas fa-folder"></i> public_html
                                    </span>
                                </div>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn-scan" id="scanBtn">
                                    <i class="fas fa-play me-2"></i>
                                    <span id="scanBtnText">Start Deep Scan</span>
                                    <span class="spinner-border spinner-border-sm ms-2 d-none" id="scanSpinner" role="status"></span>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <?php if (isset($error) && $error !== null): ?>
        <div class="row mt-4">
            <div class="col-12">
                <div class="alert alert-danger d-flex align-items-center" role="alert">
                    <i class="fas fa-exclamation-triangle fs-4 me-3"></i>
                    <div>
                        <strong>Scan Error</strong><br>
                        <?= $error ?>
                    </div>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- ===== Scan Results ===== -->
    <?php if ($scanResult !== null && isset($scanResult['findings'])): 
        $findings = $scanResult['findings'];
        $metadata = $scanResult['scan_metadata'] ?? [];
        $summary = $metadata['finding_summary'] ?? [];
        $totalFindings = $metadata['total_findings'] ?? 0;
        $filesScanned = $metadata['files_scanned'] ?? 0;
        $totalSize = $metadata['total_size_scanned'] ?? 'N/A';
        $duration = $metadata['duration'] ?? 'N/A';
        
        $criticalCount = $summary['critical'] ?? 0;
        $highCount = $summary['high'] ?? 0;
        $mediumCount = $summary['medium'] ?? 0;
        $infoCount = $summary['info'] ?? 0;
        
        $hasFindings = $totalFindings > 0;
    ?>
        
        <!-- ===== Stats Dashboard ===== -->
        <div class="row mt-5 g-3 animate-fade-in">
            <div class="col-6 col-md-3">
                <div class="stat-card info">
                    <div class="stat-icon"><i class="fas fa-file-code"></i></div>
                    <p class="stat-number"><?= $filesScanned ?></p>
                    <p class="stat-label">Files Scanned</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card warning">
                    <div class="stat-icon"><i class="fas fa-hdd"></i></div>
                    <p class="stat-number" style="font-size:clamp(1.2rem,2vw,2rem);"><?= $totalSize ?></p>
                    <p class="stat-label">Total Size</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card success">
                    <div class="stat-icon"><i class="fas fa-clock"></i></div>
                    <p class="stat-number" style="font-size:clamp(1.2rem,2vw,2rem);"><?= $duration ?></p>
                    <p class="stat-label">Duration</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card <?= $hasFindings ? 'danger' : 'success' ?>">
                    <div class="stat-icon"><i class="fas fa-bug"></i></div>
                    <p class="stat-number"><?= $totalFindings ?></p>
                    <p class="stat-label">Findings</p>
                </div>
            </div>
        </div>

        <!-- ===== Severity Summary ===== -->
        <?php if ($hasFindings): ?>
        <div class="row mt-3 g-2 animate-fade-in">
            <div class="col-6 col-md-3">
                <div class="stat-card" style="border-color:var(--accent-red);">
                    <p class="stat-number" style="color:var(--accent-red);"><?= $criticalCount ?></p>
                    <p class="stat-label" style="color:var(--accent-red);">Critical</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" style="border-color:var(--accent-orange);">
                    <p class="stat-number" style="color:var(--accent-orange);"><?= $highCount ?></p>
                    <p class="stat-label" style="color:var(--accent-orange);">High</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" style="border-color:var(--accent-cyan);">
                    <p class="stat-number" style="color:var(--accent-cyan);"><?= $mediumCount ?></p>
                    <p class="stat-label" style="color:var(--accent-cyan);">Medium</p>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" style="border-color:var(--text-muted);">
                    <p class="stat-number" style="color:var(--text-muted);"><?= $infoCount ?></p>
                    <p class="stat-label" style="color:var(--text-muted);">Info</p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- ===== Findings List ===== -->
        <div class="row mt-4 animate-fade-in">
            <div class="col-12">
                <div class="card-glass">
                    <div class="card-header d-flex justify-content-between align-items-center flex-wrap">
                        <span><i class="fas fa-list-ul me-2"></i> Detailed Findings</span>
                        <span class="badge bg-secondary"><?= count($findings) ?> items</span>
                    </div>
                    <div class="card-body">
                        <?php if ($hasFindings): ?>
                            <?php foreach ($findings as $finding): 
                                $severity = $finding['severity'] ?? 'info';
                                $severityClass = match($severity) {
                                    'critical' => 'critical',
                                    'high' => 'high',
                                    'medium' => 'medium',
                                    default => 'info'
                                };
                                $badgeClass = match($severity) {
                                    'critical' => 'badge-critical',
                                    'high' => 'badge-high',
                                    'medium' => 'badge-medium',
                                    default => 'badge-info'
                                };
                            ?>
                                <div class="finding-item <?= $severityClass ?>">
                                    <div class="d-flex justify-content-between align-items-start flex-wrap gap-2">
                                        <div class="d-flex align-items-center gap-2 flex-wrap">
                                            <span class="badge-severity <?= $badgeClass ?>"><?= strtoupper($severity) ?></span>
                                            <span class="fw-semibold" style="font-size:0.9rem;">
                                                <?= htmlspecialchars($finding['message'] ?? 'Unknown issue') ?>
                                            </span>
                                        </div>
                                        <?php if (isset($finding['risk_score'])): ?>
                                            <span class="badge bg-dark">
                                                <i class="fas fa-fire me-1"></i> <?= $finding['risk_score'] ?>/10
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <div class="file-path mt-1">
                                        <i class="fas fa-file me-1"></i> <?= htmlspecialchars($finding['file'] ?? 'Unknown') ?>
                                        <?php if (isset($finding['line'])): ?>
                                            <span class="text-muted">| Line <?= $finding['line'] ?></span>
                                        <?php endif; ?>
                                        <?php if (isset($finding['file_size'])): ?>
                                            <span class="text-muted">| <?= $finding['file_size'] ?></span>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <?php if (isset($finding['context']) && !empty($finding['context'])): ?>
                                        <div class="context-code">
                                            <?php foreach ($finding['context'] as $line): 
                                                $lineNum = $line['line'] ?? '?';
                                                $content = $line['content'] ?? '';
                                                $isHighlighted = (isset($finding['line']) && $lineNum == $finding['line']);
                                            ?>
                                                <div class="<?= $isHighlighted ? 'highlight' : '' ?>">
                                                    <span style="color:var(--text-muted);"><?= $lineNum ?>.</span> 
                                                    <?= $content ?>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>
                                    
                                    <div class="mt-2 d-flex gap-2 flex-wrap">
                                        <?php if (isset($finding['vt_results'])): ?>
                                            <span class="badge bg-info">
                                                <i class="fas fa-shield-virus me-1"></i> VT: <?= $finding['vt_results']['positives'] ?? 0 ?>/<?= $finding['vt_results']['total'] ?? 0 ?>
                                            </span>
                                        <?php endif; ?>
                                        <span class="badge bg-dark">
                                            <i class="far fa-clock me-1"></i> <?= $finding['timestamp'] ?? '' ?>
                                        </span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">
                                <div class="empty-icon"><i class="fas fa-check-circle" style="color:var(--accent-green);"></i></div>
                                <h5>Clean Scan!</h5>
                                <p class="text-secondary">No suspicious patterns detected in the scanned files.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- ===== Reports ===== -->
        <?php if (!empty($reportFiles)): ?>
        <div class="row mt-4 animate-fade-in">
            <div class="col-12">
                <div class="card-glass">
                    <div class="card-header">
                        <i class="fas fa-download me-2"></i> Download Reports
                    </div>
                    <div class="card-body">
                        <div class="row g-2">
                            <?php foreach ($reportFiles as $format => $file): 
                                $icon = match($format) {
                                    'html' => 'fa-file-code',
                                    'json' => 'fa-file-code',
                                    'csv' => 'fa-file-csv',
                                    default => 'fa-file'
                                };
                                $color = match($format) {
                                    'html' => 'text-primary',
                                    'json' => 'text-warning',
                                    'csv' => 'text-success',
                                    default => 'text-secondary'
                                };
                            ?>
                                <div class="col-12 col-sm-6 col-md-4">
                                    <a href="<?= $file ?>" class="report-card" download>
                                        <div>
                                            <i class="fas <?= $icon ?> <?= $color ?> report-icon"></i>
                                        </div>
                                        <div class="report-info">
                                            <div class="report-name"><?= strtoupper($format) ?> Report</div>
                                            <div class="report-meta">
                                                <?php 
                                                    $size = filesize($file);
                                                    echo $size > 1024 ? round($size/1024, 1) . ' KB' : $size . ' B';
                                                ?>
                                            </div>
                                        </div>
                                        <i class="fas fa-chevron-right text-muted"></i>
                                    </a>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>
    <?php endif; ?>

    <!-- ===== Previous Reports ===== -->
    <?php if (!empty($availableReports)): ?>
    <div class="row mt-4 animate-fade-in">
        <div class="col-12">
            <div class="card-glass">
                <div class="card-header">
                    <i class="fas fa-history me-2"></i> Previous Scans
                </div>
                <div class="card-body">
                    <div class="row g-2">
                        <?php 
                        usort($availableReports, function($a, $b) {
                            return filemtime($b) - filemtime($a);
                        });
                        foreach (array_slice($availableReports, 0, 10) as $report): 
                            $reportName = basename($report);
                            $reportType = pathinfo($report, PATHINFO_EXTENSION);
                            $reportTime = date('M d, Y H:i', filemtime($report));
                            $icon = match($reportType) {
                                'html' => 'fa-file-code',
                                'json' => 'fa-file-code',
                                'csv' => 'fa-file-csv',
                                default => 'fa-file'
                            };
                        ?>
                            <div class="col-12 col-sm-6 col-md-4 col-lg-3">
                                <a href="<?= $report ?>" class="report-card" target="_blank">
                                    <div>
                                        <i class="fas <?= $icon ?> text-secondary report-icon"></i>
                                    </div>
                                    <div class="report-info">
                                        <div class="report-name" style="font-size:0.8rem;"><?= htmlspecialchars($reportName) ?></div>
                                        <div class="report-meta"><?= $reportTime ?></div>
                                    </div>
                                    <i class="fas fa-external-link-alt text-muted" style="font-size:0.8rem;"></i>
                                </a>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- ===== Author Profile Section ===== -->
    <div class="row mt-5" id="author">
        <div class="col-12">
            <div class="card-glass">
                <div class="card-header">
                    <i class="fas fa-user-astronaut me-2"></i> About the Developer
                </div>
                <div class="card-body">
                    <div class="row align-items-center g-4">
                        <div class="col-md-4 col-lg-3 text-center">
                            <img src="cyrus.png" 
                                 alt="Author" 
                                 class="author-avatar">
                            <h5 class="author-name">Orji, Cyrus Ebere, MCPN</h5>
                            <p class="author-role"><i class="fas fa-shield-alt me-1"></i> Cyber Security Expert</p>
                            <div class="author-social mt-3">
                                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                                <a href="#" title="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
                                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
                                <a href="mailto:cyrus.orji@imopoly.edu.ng" title="Email"><i class="fas fa-envelope"></i></a>
                            </div>
                        </div>
                        <div class="col-md-8 col-lg-9">
                            <h6 class="fw-bold"><i class="fas fa-code me-2" style="color:var(--accent-cyan);"></i> Passionate about Security</h6>
                            <p class="text-secondary" style="font-size:0.95rem;">
                           Orji, Cyrus Ebere is a Chartered IT Practitioner, Microsoft Certified Innovative Educator and a Lecturer in the Department of Computer Science Technology, Imo State Polytechnic Nigeria, he received his HND in Computer Engineering Technology from Imo State Polytechnic Owerri in 2012, Post Graduate Diploma in Education in 2022 and B.Sc. degree in Computer Science from Paul University Awka in 2024, and has completed M.Sc. degree in Computer Science from Paul University Awka in 2025. He is currently pursuing M.Sc in Cyber Security at Wrexham University North Wales United Kingdom. His research interests include cryptographic implementations, web security, Defensive and Offensive Security. He is a Member of Computer Professionals Registration Council of Nigeria (CPN), Member of Nigeria Computer Society (NCS), Member Cyber Security Expert Association of Nigeria (CSEAN) and Member Computer Educators Association of Nigeria (CEAN) respectfully. He is married to Mrs. Chidimma Orji and the marriage is blessed with four children.
                            </p>
                            <div class="d-flex flex-wrap gap-3 mt-3">
                                <div>
                                    <span class="badge bg-primary"><i class="fas fa-certificate me-1"></i> OSCP</span>
                                    <span class="badge bg-info ms-1"><i class="fas fa-certificate me-1"></i> CEH</span>
                                    <span class="badge bg-success ms-1"><i class="fas fa-certificate me-1"></i> AWS Security</span>
                                </div>
                            </div>
                            <div class="mt-3">
                                <small class="text-muted">
                                    <i class="fas fa-heart me-1" style="color:var(--accent-red);"></i> 
                                    Open Source Advocate • 
                                    <i class="fas fa-shield-halved me-1" style="color:var(--accent-cyan);"></i> 
                                    Bug Bounty Hunter
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===== Improvements / Suggestions ===== -->
    <div class="row mt-4" id="improvements">
        <div class="col-12">
            <div class="card-glass">
                <div class="card-header">
                    <i class="fas fa-lightbulb me-2" style="color:var(--accent-orange);"></i> Suggested Improvements
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon"><i class="fas fa-cloud-upload-alt"></i></span>
                                    <div>
                                        <div class="suggestion-title">VirusTotal API Integration</div>
                                        <div class="suggestion-desc">
                                            <span class="badge bg-success me-1">✓ Done</span>
                                            Send suspicious files to VirusTotal for multi-engine scanning.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item" style="border-left-color:var(--accent-orange);">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon" style="color:var(--accent-orange);"><i class="fas fa-robot"></i></span>
                                    <div>
                                        <div class="suggestion-title">AI/ML Detection</div>
                                        <div class="suggestion-desc">
                                            Implement machine learning to detect obfuscated webshells using 
                                            TensorFlow PHP or external API.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item" style="border-left-color:var(--accent-green);">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon" style="color:var(--accent-green);"><i class="fas fa-bolt"></i></span>
                                    <div>
                                        <div class="suggestion-title">Real-time Monitoring</div>
                                        <div class="suggestion-desc">
                                            Add file watcher to automatically scan new/modified files 
                                            in real-time using inotify.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item" style="border-left-color:var(--accent-purple);">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon" style="color:var(--accent-purple);"><i class="fas fa-chart-pie"></i></span>
                                    <div>
                                        <div class="suggestion-title">Advanced Analytics Dashboard</div>
                                        <div class="suggestion-desc">
                                            Visual dashboard with charts showing scan history, 
                                            threat trends, and severity distribution.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item" style="border-left-color:var(--accent-cyan);">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon" style="color:var(--accent-cyan);"><i class="fas fa-bell"></i></span>
                                    <div>
                                        <div class="suggestion-title">Alert & Notification System</div>
                                        <div class="suggestion-desc">
                                            Email/Slack/Telegram alerts when critical threats are detected 
                                            during automated scans.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="suggestion-item" style="border-left-color:var(--accent-red);">
                                <div class="d-flex align-items-start">
                                    <span class="suggestion-icon" style="color:var(--accent-red);"><i class="fas fa-trash-restore"></i></span>
                                    <div>
                                        <div class="suggestion-title">Quarantine & Recovery</div>
                                        <div class="suggestion-desc">
                                            Isolate suspicious files automatically and provide 
                                            one-click recovery/removal options.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===== Footer ===== -->
    <footer class="mt-5 pt-4 border-top border-secondary" style="border-color:var(--border-color) !important;">
        <div class="row g-3">
            <div class="col-md-6">
                <p style="color:white;">
                    <i class="fas fa-shield-alt me-1" style="color:white;"></i>
                    WebShell Scanner v2.0 • Built with  in PHP 8.3 By Orji, Cyrus Ebere
                </p>
            </div>
            <div class="col-md-6 text-md-end">
                <p class="" style="color:white;">
                    <a href="#" style="color:white;" onclick="showSecurityNotice(); return false;">
                        <i class="fas fa-lock me-1"></i> Security Notice
                    </a>
                    <a href="https://github.com/yourusername/webshell-scanner" target="_blank" style="color:white;">
                        <i class="fab fa-github me-1"></i> GitHub
                    </a>
                </p>
            </div>
        </div>
    </footer>
</div>

<!-- ===== JavaScript ===== -->
<script>
    // ===== Set Path Helper =====
    function setPath(path) {
        document.getElementById('scanPath').value = path;
        document.getElementById('scanPath').focus();
    }

    // ===== Show Toast Notification =====
    function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const colors = {
            info: 'bg-primary',
            success: 'bg-success',
            warning: 'bg-warning',
            danger: 'bg-danger'
        };
        
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white ${colors[type] || colors.info} border-0 show`;
        toast.role = 'alert';
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        `;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 5000);
    }

    // ===== Security Notice =====
    function showSecurityNotice() {
        alert('🔒 Security Notice\n\n' +
              'This tool is designed By Orji, Cyrus Ebere for legitimate security auditing only.\n\n' +
              '✓ Always obtain proper authorization before scanning\n' +
              '✓ Use only on systems you own or have permission to test\n' +
              '✓ Report findings responsibly\n\n' +
              'Unauthorized use may violate laws and regulations.');
    }

    // ===== Form Submit Handler =====
    document.getElementById('scanForm').addEventListener('submit', function(e) {
        const btn = document.getElementById('scanBtn');
        const btnText = document.getElementById('scanBtnText');
        const spinner = document.getElementById('scanSpinner');
        
        btnText.textContent = 'Scanning...';
        spinner.classList.remove('d-none');
        btn.disabled = true;
        btn.classList.add('opacity-75');
        
        // Show scanning toast
        showToast('🔍 Starting deep scan... This may take a moment.', 'info');
    });

    // ===== Keyboard Shortcuts =====
    document.addEventListener('keydown', function(e) {
        // Ctrl+Enter to submit
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const form = document.getElementById('scanForm');
            if (document.activeElement === document.getElementById('scanPath')) {
                form.dispatchEvent(new Event('submit'));
            }
        }
    });

    // ===== Auto-focus on load =====
    document.addEventListener('DOMContentLoaded', function() {
        const input = document.getElementById('scanPath');
        if (input && !input.value) {
            setTimeout(() => input.focus(), 300);
        }
    });

    // ===== Copy file path to clipboard =====
    document.querySelectorAll('.file-path').forEach(el => {
        el.addEventListener('click', function() {
            const text = this.textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
                showToast('📋 Path copied to clipboard!', 'success');
            }).catch(() => {
                // Fallback
                const range = document.createRange();
                range.selectNode(this);
                window.getSelection().removeAllRanges();
                window.getSelection().addRange(range);
                document.execCommand('copy');
                showToast('📋 Path copied!', 'success');
            });
        });
        el.style.cursor = 'pointer';
    });
</script>

<!-- Bootstrap 5 JS Bundle -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
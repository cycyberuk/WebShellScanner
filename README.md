# WebShellScanner
Enterprise-grade security scanning for webshells, backdoors, and malicious code patterns 

# 🔍 WebShellScanner v2.0

**Enterprise-Grade Static Analysis Tool for PHP WebShell Detection**

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/yourusername/webshell-scanner)
[![PHP Version](https://img.shields.io/badge/PHP-8.3-777bb4.svg)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/yourusername/webshell-scanner/pulls)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Detection Patterns](#detection-patterns)
- [VirusTotal Integration](#virustotal-integration)
- [Report Formats](#report-formats)
- [Performance](#performance)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Citation](#citation)

---

## 📖 Overview

**WebShellScanner** is a professional-grade static analysis tool designed for detecting malicious PHP WebShells, backdoors, and suspicious code patterns. Built with PHP 8.3 and featuring a modern dark theme interface, it provides comprehensive security scanning for web applications, incident response, and continuous integration pipelines.

### Why WebShellScanner?

| Feature | Benefit |
|---------|---------|
| **30+ Detection Patterns** | Comprehensive coverage of known WebShell signatures |
| **Severity Classification** | Critical, High, Medium, Info categories for prioritized response |
| **Real-Time Performance** | 240 files/second with <50MB memory usage |
| **Multi-Format Reports** | HTML, JSON, and CSV export for different stakeholders |
| **VirusTotal Integration** | Multi-engine validation for increased confidence |
| **Dark Theme UI** | Professional, eye-friendly interface for extended use |

---

## 🚀 Key Features

### Detection Capabilities

| Category | Detection | Examples |
|----------|-----------|----------|
| **Critical** | Code Execution | `eval()`, `assert()`, `create_function()` |
| **Critical** | System Commands | `system()`, `shell_exec()`, `exec()`, `passthru()` |
| **Critical** | Obfuscation | `base64_decode()`, `gzinflate()`, `str_rot13()` |
| **Critical** | File Manipulation | `file_put_contents()`, `fwrite()`, `chmod()` |
| **High** | Dynamic Execution | `call_user_func()`, `call_user_func_array()` |
| **High** | Remote Includes | `include($_GET)`, `require($_POST)` |
| **Medium** | Obfuscation Patterns | Encoding chains, error suppression |
| **Info** | Information Disclosure | `phpinfo()`, server variable access |

### Severity Scoring

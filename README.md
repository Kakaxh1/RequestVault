<h1 align="center">RequestVault</h1>

<p align="center">
  <b>A Local-First HTTP Traffic Collection, Multi-Language Replay Generator, Response Diffing, and Evidence-Export Extension for Burp Suite & Caido</b>
</p>

<p align="center">
  <a href="https://github.com/Kakaxh1"><img src="https://img.shields.io/badge/Author-Kakaxh1-181717.svg?style=flat&logo=github" alt="Author" /></a>
  <a href="https://github.com/Kakaxh1/RequestVault"><img src="https://img.shields.io/badge/Repository-Kakaxh1%2FRequestVault-2ea44f.svg?style=flat&logo=github" alt="Repository" /></a>
  <a href="https://github.com/Kakaxh1/RequestVault/releases"><img src="https://img.shields.io/badge/Release-v1.0.0-blue.svg?style=flat&logo=github" alt="Download Release" /></a>
  <img src="https://img.shields.io/badge/Burp%20Suite-Community%20%7C%20Pro-orange.svg" alt="Burp Suite" />
  <img src="https://img.shields.io/badge/Caido-Desktop%20%7C%20Web-purple.svg" alt="Caido" />
  <img src="https://img.shields.io/badge/Java-17%2B-red.svg" alt="Java 17+" />
  <img src="https://img.shields.io/badge/TypeScript-5.4%2B-3178c6.svg" alt="TypeScript" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
</p>

---

## Overview

**RequestVault** is a local-first HTTP traffic collection, analysis, multi-language replay code generator, response diffing, and forensic evidence-export tool built for penetration testers, security engineers, and red teams.

RequestVault is available in two native editions:
1. **Burp Suite Edition**: Written in Java using the official PortSwigger Montoya API.
2. **Caido Edition**: Written in TypeScript using the official Caido Plugin SDK.

> **Core Design Principle:**  
> *Capture traffic once, preserve original raw evidence in memory, and empower the tester to filter, analyze, compare, replay across multiple languages, and selectively export application flows into audit-ready VAPT artifacts without ever manually reopening hundreds of HTTP history entries.*

---

## Direct Release Downloads

Download the ready-to-use binaries from [GitHub Releases](https://github.com/Kakaxh1/RequestVault/releases/tag/v1.0.0):

| Platform | Download Artifact | File Type | Compatibility |
| :--- | :--- | :--- | :--- |
| **Burp Suite** | [RequestVault.jar](https://github.com/Kakaxh1/RequestVault/releases/download/v1.0.0/RequestVault.jar) | Java Fat JAR | Burp Suite Community & Pro (2023.12+) |
| **Caido** | [requestvault-caido.zip](https://github.com/Kakaxh1/RequestVault/releases/download/v1.0.0/requestvault-caido.zip) | Caido Plugin ZIP | Caido Desktop & Web (0.45+) |

---

## Platform Editions Matrix

| Feature | Burp Suite Edition | Caido Edition |
| :--- | :--- | :--- |
| **Technology** | Java 17+, Montoya API | TypeScript, Caido Plugin SDK |
| **Interface** | Swing Native Burp Tab | Caido Navigation Sidebar Page |
| **Packaging** | Fat JAR (`RequestVault.jar`) | Plugin ZIP (`requestvault-caido.zip`) |
| **Top-Level "Copy as cURL"** | Yes (Proxy History, Logger, Repeater) | Yes (HTTP History, Intercept, Editor) |
| **Replay Script Generators** | cURL, Python, Fetch, PowerShell, Raw HTTP | cURL, Python, Fetch, PowerShell, Raw HTTP |
| **Domain Hierarchy Tree** | Yes (Apex & Subdomain Grouping) | Yes (Apex & Subdomain Grouping) |
| **Granular Filters** | Status, MIME, Time, Auth Endpoints | Status, MIME, Time, Auth Endpoints |
| **Forensic Search** | Full-Text, Regex, Inverted Match | Full-Text, Regex, Inverted Match |
| **Response Diffing** | Split-Pane Access Control Diff | Side-by-Side Diff with Status Alerts |
| **Multi-Format Exports** | HTML, Markdown, JSON, CSV, RAW, HAR | HTML, Markdown, JSON, CSV, HAR |
| **Credential Redaction** | Yes (Non-Destructive) | Yes (Non-Destructive) |
| **SHA-256 Manifest** | `evidence-manifest.json` | `evidence-manifest.json` |

---

## Table of Contents

- [Overview](#overview)
- [Direct Release Downloads](#direct-release-downloads)
- [Platform Editions Matrix](#platform-editions-matrix)
- [Key Features](#key-features)
  - [1. Multi-Language Exploit & Replay Generators](#1-multi-language-exploit--replay-generators)
  - [2. Top-Level Context Menu Shortcuts](#2-top-level-context-menu-shortcuts)
  - [3. Auto-Capture & Historical Ingestion](#3-auto-capture--historical-ingestion)
  - [4. Hierarchical Domain & Subdomain Tree](#4-hierarchical-domain--subdomain-tree)
  - [5. Granular Selection & Range Filtering](#5-granular-selection--range-filtering)
  - [6. Smart Filters](#6-smart-filters)
  - [7. Advanced Traffic Search](#7-advanced-traffic-search)
  - [8. Side-by-Side Response Diffing](#8-side-by-side-response-diffing)
  - [9. Multi-Format Evidence Packs](#9-multi-format-evidence-packs)
  - [10. Non-Destructive Redaction & Cryptographic Integrity](#10-non-destructive-redaction--cryptographic-integrity)
- [Installation Guide](#installation-guide)
  - [Installing in Burp Suite](#installing-in-burp-suite)
  - [Installing in Caido](#installing-in-caido)
- [Step-by-Step Usage Workflows](#step-by-step-usage-workflows)
- [Right-Click Context Menus](#right-click-context-menus)
- [Building from Source](#building-from-source)
- [Author & Maintainer](#author--maintainer)
- [License](#license)

---

## Key Features

### 1. Multi-Language Exploit & Replay Generators
Convert captured transactions into standalone, copy-pasteable replay scripts across 5 major execution formats:
- **cURL**: Single and multi-step bash commands formatted with HTTP method `-X`, custom headers `-H`, payload `--data-raw`, and `-k` (insecure SSL bypass for self-signed certificates). Special characters and single quotes are safely escaped for bash execution.
- **Python (`requests`)**: Production-ready Python 3 scripts with `urllib3.disable_warnings()`, `verify=False`, session management (`requests.Session()`) for multi-step stateful workflows, and response status/body inspection.
- **JavaScript (`fetch`)**: Modern asynchronous Fetch API snippets ready to paste directly into browser DevTools console or execute under Node.js runtime.
- **PowerShell (`Invoke-RestMethod`)**: Native Windows PowerShell snippets utilizing hashtable headers (`$headers = @{...}`), raw body here-strings, and `-SkipCertificateCheck`.
- **Raw HTTP (RFC 7230)**: Exact wire-format HTTP request blocks with CRLF delimiters ready for netcat (`nc`), Burp Repeater, or raw socket testing.
- **Multi-Step Flow Chaining**: Highlight multiple requests in sequence; RequestVault stitches them into a coherent sequential execution script with step-by-step progress logging.

### 2. Top-Level Context Menu Shortcuts
Quickly copy replay commands without opening submenus:
- **Proxy HTTP History / Tables**: Right-click any row -> **"Copy this request as cURL"**.
- **Request Editors**: Right-click directly inside the request text editor -> **"Copy this request as cURL"**.
- Also includes quick actions for Python, JavaScript Fetch, PowerShell, Raw HTTP, and sending traffic into RequestVault.

### 3. Auto-Capture & Historical Ingestion
- **Automatic History Ingestion**: Reads existing Burp or Caido proxy history in background workers without freezing the UI.
- **Live Interceptor**: Captures and pairs real-time requests and responses as traffic passes through the proxy.
- **Scope Awareness**: Filter capture strictly to in-scope targets or capture across all hostnames.

### 4. Hierarchical Domain & Subdomain Tree
- Automatically groups hostnames by their apex domain (e.g. `example.com` -> `api.example.com`, `auth.example.com`).
- Check or uncheck parent domains or individual subdomains to filter table views instantaneously.
- Search input to filter domains as your engagement scope expands.

### 5. Granular Selection & Range Filtering
- **1st-Column Checkboxes (`Select`)**: Check or uncheck individual transactions directly in the table.
- **Sequence Numbers (`#`)**: Every request/response transaction receives an immutable chronological sequence number (`#1`, `#2`, `#3`...).
- **Number Range Selection**:
  - `From: [10]` `To: [50]` -> Click **`Select Range`** to check those transactions.
  - Click **`Filter Range`** to isolate those numbers in the view.
- **API / Path Filter**: Enter keywords or API prefixes (e.g. `/api/v1/auth`, `users`) and click **`Select Matching`**.

### 6. Smart Filters
Isolate security-critical requests and responses with rapid multi-attribute filtering:
- **Status Categories & Ranges**: Filter by standard categories (`2xx Success`, `3xx Redirection`, `4xx Client Error`, `5xx Server Error`, `Auth Failures 401/403`) or enter custom ranges (e.g. `200, 302, 401-404, 5xx`).
- **MIME Type Categories**: Categorize traffic by data type:
  - `JSON (application/json)`
  - `HTML (text/html)`
  - `XML (application/xml, text/xml)`
  - `Plain Text (text/plain)`
  - `Scripts & Stylesheets (js, css)`
  - `Binary & Media (images, pdf, octet-stream)`
- **Time Range Windows**: Instantly filter traffic captured during specific testing windows:
  - `All Time`, `Last 5 Minutes`, `Last 15 Minutes`, `Last 1 Hour`, `Last 24 Hours`.
- **Authentication Endpoints Filter**: One-click filter checkbox targeting authentication-critical surfaces:
  - Path keywords (`/login`, `/token`, `/oauth`, `/auth`, `/session`, `/jwt`, `/saml`, `/register`, `/sso`, `/mfa`).
  - Session and credential headers (`Authorization`, `Bearer`, `Cookie`, `Set-Cookie`, `x-api-key`).

### 7. Advanced Traffic Search
Perform deep, full-text forensic inspection across captured traffic:
- **Search Scopes**: `Everywhere`, `URL & Path`, `Headers`, `Request Body`, `Response Body`, `Method`, and `Status`.
- **Search Modifiers**: `Match Case`, `Regex` pattern matching, and `Invert (NOT)` reverse matching.

### 8. Side-by-Side Response Diffing
Compare any two responses (e.g. Authenticated vs Anonymous, Admin vs User, Baseline vs Tampered):
- Select 2 rows and click **`Compare (2)`**.
- Visual indicators for:
  - Status code mismatches (`200 OK` vs `403 Forbidden`) with access control alert banners.
  - Content length / byte size deltas.
  - Added, removed, or modified HTTP headers.
  - Line-by-line body diff highlighting.
  - JSONPath field-level diffs (`$.user.role: "user" -> "admin"`).

### 9. Multi-Format Evidence Packs
Export single files or complete audit directories:
| Format | Extension | Description |
| :--- | :--- | :--- |
| **HTML Report** | `.html` | Clean, self-contained interactive report with badges and expandable bodies |
| **Markdown** | `.md` | VAPT-ready audit documentation with summary tables and syntax-highlighted blocks |
| **JSON** | `.json` | Comprehensive structure with metadata, base64/plain bodies, timestamps, and hashes |
| **CSV** | `.csv` | Flat tabular spreadsheet for scoping, logging, and triage |
| **RAW Stream** | `.txt` / `.bin` | Complete wire-format HTTP streams preserving exact HTTP delimiter bytes |
| **HAR 1.2** | `.har` | Standard HTTP Archive for import into Postman, Insomnia, DevTools, or OWASP ZAP |

### 10. Non-Destructive Redaction & Cryptographic Integrity
- **Non-Destructive Redaction**: Automatically redacts sensitive fields on **exported copies only**; raw in-memory evidence is never altered:
  - Authorization headers (`Bearer <REDACTED>`, `Basic <REDACTED>`)
  - Cookies (`PHPSESSID`, `JSESSIONID`, `token`, `session`)
  - API Keys (`x-api-key`, `apikey`, `secret`)
  - Request body credentials (`password=...`, `"token":"..."`)
- **Evidence Manifest (`evidence-manifest.json`)**:
  - Calculates **SHA-256** checksums of all exported files and individual records.
  - Guarantees chain of custody and artifact integrity for client deliverables.

---

## Installation Guide

### Installing in Burp Suite

1. **Download the Extension JAR**:
   - [Download RequestVault.jar (v1.0.0)](https://github.com/Kakaxh1/RequestVault/releases/download/v1.0.0/RequestVault.jar)
2. **Open Burp Suite**:
   - Go to the **Extensions** tab -> **Installed** subtab.
3. **Add Extension**:
   - Click **Add**.
   - Select **Extension type**: `Java`.
   - Select **Extension file (.jar)**: choose `RequestVault.jar`.
4. **Complete Installation**:
   - Click **Next** until installed. A new **RequestVault** tab will appear in Burp Suite's top navigation bar.

### Installing in Caido

1. **Download the Plugin ZIP**:
   - [Download requestvault-caido.zip (v1.0.0)](https://github.com/Kakaxh1/RequestVault/releases/download/v1.0.0/requestvault-caido.zip)
2. **Open Caido**:
   - Click on **Plugins** in the left navigation sidebar.
3. **Install from File**:
   - In the top right corner, click **Install from File** (or drag and drop the `.zip` archive).
   - Select `requestvault-caido.zip`.
4. **Complete Installation**:
   - **RequestVault** appears immediately in Caido's navigation sidebar and in right-click context menus.

---

## Step-by-Step Usage Workflows

### Scenario 1: One-Click cURL Replay from History
1. In Burp Suite Proxy HTTP History or Caido HTTP History, right-click any request.
2. Click **`Copy this request as cURL`**.
3. Paste directly into your terminal:
   ```bash
   curl -i -s -k -X POST "https://target.example/api/v1/resource" \
     -H "Host: target.example" \
     -H "Authorization: Bearer <TOKEN>" \
     --data-raw '{"action":"test"}'
   ```

### Scenario 2: Bulk Export Evidence for an Audit Report
1. In the **RequestVault** tab, verify captured records.
2. In the **Domain Tree** (left), check your target domain.
3. Filter rows using the Path or Status filters.
4. Check the boxes of the key vulnerability findings.
5. Click **`Export Evidence...`**:
   - Choose destination format: `HTML Report`, `Markdown`, `JSON`, `CSV`, or `HAR`.
   - Check `Apply Redaction (mask tokens, passwords, cookies)`.
   - Check `Generate SHA-256 Cryptographic Evidence Manifest`.
   - Click **Export / Download**.

### Scenario 3: Bypassing Access Control (IDOR / Privilege Escalation Diff)
1. Send both the low-privilege request and high-privilege request to RequestVault.
2. Check both records in the table (or highlight both rows).
3. Click **`Compare (2)`** on the action bar.
4. RequestVault displays the side-by-side comparison:
   - Status code transition alerts (`200 OK` vs `403 Forbidden`).
   - Header modifications and body deltas highlighted line-by-line.

---

## Right-Click Context Menus

| Location | Action | What it does |
| :--- | :--- | :--- |
| **Proxy History / Tables** | `Copy this request as cURL` | Generates and copies ready-to-run cURL command |
| **Proxy History / Tables** | `Send to RequestVault` | Ingests selected request/response pairs into the vault |
| **Proxy / Logger** | `RequestVault: Copy as Python` | Generates standalone Python `requests` script |
| **Proxy / Logger** | `RequestVault: Copy as JavaScript Fetch` | Generates modern async `fetch` snippet |
| **Proxy / Logger** | `RequestVault: Copy as PowerShell` | Generates PowerShell `Invoke-RestMethod` script |
| **Proxy / Logger** | `RequestVault: Copy as Raw HTTP` | Generates RFC 7230 raw HTTP request stream |
| **Proxy / Logger** | `RequestVault: One-Click Copy (JSON/CSV/HTML/MD)` | Copies selected transactions in requested evidence format |
| **Request Editor Pane** | `Copy this request as cURL` | Copies current editor request as cURL |
| **Request Editor Pane** | `RequestVault: Copy Replay Code` | Submenu for Python, Fetch, PowerShell, and Raw HTTP |
| **RequestVault Table** | `Copy this request as cURL` | Directly copies highlighted row as cURL |
| **RequestVault Table** | `Copy Replay Code` | Multi-language generator for table selections |

---

## Building from Source

### Clone the Repository
```bash
git clone https://github.com/Kakaxh1/RequestVault.git
cd RequestVault
```

### Building the Burp Suite Extension (Java)
```powershell
# Windows automated build script
cmd /c build.bat

# Or using Gradle
gradle build
```
Output fat JAR: `build/libs/RequestVault.jar`

### Building the Caido Extension (TypeScript)
```bash
cd Caido/RequestVault-Caido
npm install
npm run typecheck
node build.js
```
Output plugin ZIP: `Caido/RequestVault-Caido/dist/requestvault-caido.zip`

### Running Automated Test Suites
```powershell
# Burp Suite Java Unit Tests (106 tests)
javac -cp "lib/*;build/classes" -d build/classes/test src/test/java/requestvault/export/ReplayCodeGeneratorTest.java src/test/java/requestvault/analysis/TrafficFilterAndPresetTest.java src/test/java/requestvault/analysis/ResponseDiffTest.java
java -cp "build/classes;build/classes/test;lib/*" requestvault.export.ReplayCodeGeneratorTest
java -cp "build/classes;build/classes/test;lib/*" requestvault.analysis.TrafficFilterAndPresetTest
java -cp "build/classes;build/classes/test;lib/*" requestvault.analysis.ResponseDiffTest

# Caido Plugin Unit Tests (28 tests)
cd Caido/RequestVault-Caido
node test/test.js
```

---

## Author & Maintainer

**Kakaxh1**
- GitHub Profile: [https://github.com/Kakaxh1](https://github.com/Kakaxh1)
- Project Repository: [https://github.com/Kakaxh1/RequestVault](https://github.com/Kakaxh1/RequestVault)
- Website: [https://bhavymorvadiya.netlify.app/](https://bhavymorvadiya.netlify.app/)

If you find RequestVault useful in your penetration testing, bug bounty, or application security workflows, please consider giving the repository a star on GitHub.

---

## License

This project is licensed under the **MIT License**. Free for commercial and personal penetration testing engagements.

---

<p align="center">
  Developed by <a href="https://bhavymorvadiya.netlify.app/">bhavymorvadiya.netlify.app</a>
</p>

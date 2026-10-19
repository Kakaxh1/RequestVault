# RequestVault

<p align="center">
  <b>A Local-First HTTP Traffic Collection, Analysis, and Evidence-Export Extension for Burp Suite</b>
</p>

<p align="center">
  <a href="https://github.com/Kakaxh1"><img src="https://img.shields.io/badge/Author-Kakaxh1-181717.svg?style=flat&logo=github" alt="Author" /></a>
  <a href="https://github.com/Kakaxh1/RequestVault"><img src="https://img.shields.io/badge/Repository-Kakaxh1%2FRequestVault-2ea44f.svg?style=flat&logo=github" alt="Repository" /></a>
  <img src="https://img.shields.io/badge/Burp%20Suite-Community%20%7C%20Pro-orange.svg" alt="Burp Suite" />
  <img src="https://img.shields.io/badge/Montoya%20API-2023.12.1-blue.svg" alt="Montoya API" />
  <img src="https://img.shields.io/badge/Java-17%2B-red.svg" alt="Java 17+" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen.svg" alt="Build Status" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
</p>

---

## Overview

**RequestVault** is a local-first HTTP traffic collection, analysis, and evidence-export tool built for penetration testers, security engineers, and red teams.

> **Core Design Principle:**  
> *Capture traffic once, preserve the original raw evidence, and empower the tester to filter, analyze, compare, and selectively export application flows into audit-ready VAPT artifacts without ever manually reopening hundreds of HTTP history entries.*

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
  - [1. Auto-Capture & Historical Sync](#1-auto-capture--historical-sync)
  - [2. Hierarchical Domain & Subdomain Tree](#2-hierarchical-domain--subdomain-tree)
  - [3. Granular Selection & Range Filtering](#3-granular-selection--range-filtering)
  - [4. One-Click Clipboard Copy](#4-one-click-clipboard-copy)
  - [5. Multi-Format Evidence Packs](#5-multi-format-evidence-packs)
  - [6. Redaction & Cryptographic Integrity](#6-redaction--cryptographic-integrity)
  - [7. Side-by-Side Response Diffing](#7-side-by-side-response-diffing)
- [Installation Guide](#installation-guide)
- [Step-by-Step Usage Workflows](#step-by-step-usage-workflows)
- [Sample Output Previews](#sample-output-previews)
- [Right-Click Context Menus](#right-click-context-menus)
- [Building from Source](#building-from-source)
- [Author & Maintainer](#author--maintainer)
- [License](#license)

---

## Key Features

### 1. Auto-Capture & Historical Sync
- **Automatic History Ingestion**: Reads existing Burp Proxy HTTP history on startup in a background worker without freezing Burp.
- **Live Interceptor**: Captures and pairs real-time requests and responses as traffic passes through the proxy.
- **Live Toggle**: Enable or disable real-time capture anytime (`Live Capture ON/OFF`) directly from the action bar.
- **Burp Ecosystem Integration**: Send traffic directly to RequestVault from **Proxy HTTP History**, **Logger**, **Target Site Map**, or **Repeater**.

### 2. Hierarchical Domain & Subdomain Tree
- **Tree Visualization**: Automatically groups hostnames by their apex domain (e.g. `example.com` -> `api.example.com`, `auth.example.com`).
- **Interactive Checkboxes**: Filter all table entries by checking or unchecking parent domains or individual subdomains.
- **Search Bar**: Quick-filter domain names as your engagement grows.
- **Bulk Controls**: One-click **Select All**, **Deselect All**, and **Refresh** buttons.

### 3. Granular Selection & Range Filtering
- **1st-Column Checkboxes (`Select`)**: Check or uncheck individual transactions directly in the table.
- **Sequence Numbers (`#`)**: Every request/response transaction receives an immutable chronological sequence number (`#1`, `#2`, `#3`...).
- **Number Range Selection**:
  - `From: [10]` `To: [50]` -> Click **`Select Range`** to check those transactions.
  - Click **`Filter Range`** to isolate those numbers in the view.
- **API / Path Filter**:
  - Enter keywords or API prefixes (e.g. `/api/v1/auth`, `users`).
  - Click **`Select Matching`** to check all matching records in one action.
- **Selection Dropdown**: Toggle view between `Show: All Records`, `Selected Only`, or `Unselected Only`.

### 4. One-Click Clipboard Copy
Quickly paste clean evidence into JIRA tickets, Slack, Obsidian, or vulnerability reports:
- **`Copy as... ▼` Toolbar Dropdown**:
  - **Copy as JSON**: Formatted array with headers, body, timestamp, and hashes.
  - **Copy as CSV**: Tabular summary ready for Excel/Sheets.
  - **Copy as HTML**: Standalone styled report ready for email or documentation.
  - **Copy as Markdown**: Formatted with HTTP code blocks for bug reports.
- **Table Right-Click**: Right-click highlighted rows -> `Copy as JSON/CSV/HTML/Markdown`.
- **Burp Native Menus**: Right-click items in Burp Proxy or Logger -> `RequestVault: One-Click Copy (X)`.

### 5. Multi-Format Evidence Packs
Export single files or complete audit directories:
| Format | Extension | Description |
| :--- | :--- | :--- |
| **JSON** | `.json` | Comprehensive structure with metadata, base64/plain bodies, timestamps, and hashes |
| **CSV** | `.csv` | Flat tabular spreadsheet for scoping, logging, and triage |
| **HTML Report** | `.html` | Clean, self-contained interactive report with badges and expandable bodies |
| **RAW Stream** | `.txt` / `.bin` | Complete wire-format HTTP streams preserving exact HTTP delimiter bytes |
| **HAR 1.2** | `.har` | Standard HTTP Archive for import into Postman, Insomnia, DevTools, or OWASP ZAP |
| **Markdown** | `.md` | VAPT-ready audit documentation with summary tables and syntax-highlighted blocks |

### 6. Redaction & Cryptographic Integrity
- **Non-Destructive Redaction**: Automatically redacts sensitive fields on **exported copies only**; raw in-memory evidence is never altered:
  - Authorization headers (`Bearer <REDACTED>`, `Basic <REDACTED>`)
  - Cookies (`PHPSESSID`, `JSESSIONID`, `token`, `session`)
  - API Keys (`x-api-key`, `apikey`, `secret`)
  - Request body credentials (`password=...`, `"token":"..."`)
- **Evidence Manifest (`evidence-manifest.json`)**:
  - Calculates **SHA-256** checksums of all exported files and individual records.
  - Guarantees chain of custody and artifact integrity for client deliverables.

### 7. Side-by-Side Response Diffing
Compare any two responses (e.g. Authenticated vs Anonymous, Admin vs User, Baseline vs Tampered):
- Select 2 rows or click **`Compare (2)`**.
- Visual indicators for:
  - Status code mismatches (`200 OK` vs `403 Forbidden`)
  - Content length / byte size deltas
  - Added, removed, or modified HTTP headers
  - Line-by-line body diff highlighting

---

## Installation Guide

### Prerequisites
- **Burp Suite**: Community or Professional (2023.12+ recommended)
- **Java**: Java 17 or higher (bundled with modern Burp installations)

### Installing the Extension

1. **Locate the JAR file**:
   ```
   build/libs/RequestVault.jar
   ```
2. **Open Burp Suite**:
   - Navigate to the **Extensions** tab at the top.
   - Click on the **Installed** subtab.
3. **Add Extension**:
   - Click the **Add** button.
   - Under **Extension Details**:
     - **Extension type**: Select `Java`.
     - **Extension file (.jar)**: Click *Select file...* and choose `RequestVault.jar`.
4. **Complete Installation**:
   - Click **Next**.
   - Ensure the output tab displays:
     ```
     [RequestVault] Extension registered successfully!
     [RequestVault] UI tab initialized.
     [RequestVault] Context menus registered.
     ```
   - Click **Close**.
5. **Start Using**:
   - A new **RequestVault** tab is now visible in Burp Suite's main navigation bar.

---

## Step-by-Step Usage Workflows

### Scenario 1: Bulk Export Evidence for an Audit Report
1. In the **RequestVault** tab, verify captured records.
2. In the **Domain Tree** (left), check your target domain (e.g. `target.example`).
3. Set **Scope** to `Requests + Responses`.
4. Check **Exclude static assets** to omit images, fonts, and stylesheets.
5. In the table, check the boxes of the key vulnerability findings.
6. Click **`Export Evidence...`**:
   - Choose destination folder.
   - Select formats: `HTML Report`, `Markdown`, `JSON`, and `SHA-256 Manifest`.
   - Check `Apply Redaction (mask tokens, passwords, cookies)`.
   - Click **Export**.

### Scenario 2: One-Click Markdown Copy for Bug Bounty Reports
1. Filter by API path: enter `/api/v1/user` in the **API / Path** box.
2. Click **`Select Matching`** to check all matching rows.
3. Click **`Copy as... ▼`** -> **`Copy as Markdown`**.
4. Paste directly into your HackerOne / Bugcrowd report or GitHub issue.

### Scenario 3: Bypassing Access Control (IDOR / Privilege Escalation Diff)
1. Send both the low-privilege request and high-privilege request to RequestVault.
2. Check both records in the table (or highlight both rows).
3. Click **`Compare (2)`** on the action bar.
4. RequestVault automatically switches to the **Response Comparison** tab:
   - Status code differences are flagged in red/green.
   - Header modifications and body deltas are highlighted side-by-side.

---

## Sample Output Previews

### Markdown Export Sample (`export.md`)

````markdown
# Burp Traffic Export

**Project:** Target Application VAPT  
**Target:** `https://target.example`  
**Export Date:** 2026-10-19  
**Total Requests:** 2  

---

## REQUEST NO. 1

**Method:** GET  
**URL:** `https://target.example/api/profile`  
**Status:** 200 OK  

### Request 1
```http
GET /api/profile HTTP/1.1
Host: target.example
Authorization: Bearer <REDACTED>
Accept: application/json
```

### Response 1
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 101,
  "username": "tester",
  "role": "user"
}
```
````

### Evidence Manifest Sample (`evidence-manifest.json`)

```json
{
  "exportTimestamp": "2026-10-19T11:55:00Z",
  "totalRecords": 2,
  "redacted": true,
  "files": [
    {
      "fileName": "report.html",
      "sha256": "4b92c4b8b6c03d15b02f8319f7e8a9324a91929d2b273b40d3989c89495b4109"
    },
    {
      "fileName": "traffic.json",
      "sha256": "a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2"
    }
  ]
}
```

---

## Right-Click Context Menus

RequestVault embeds natively into Burp Suite's right-click menus:

| Location | Action | What it does |
| :--- | :--- | :--- |
| **Proxy HTTP History** | `Send to RequestVault` | Ingests selected request/response pairs into the vault |
| **Proxy / Logger** | `RequestVault: One-Click Copy (JSON)` | Immediately copies selected transactions as JSON |
| **Proxy / Logger** | `RequestVault: One-Click Copy (CSV)` | Immediately copies selected transactions as CSV |
| **Proxy / Logger** | `RequestVault: One-Click Copy (HTML)` | Immediately copies selected transactions as HTML |
| **Proxy / Logger** | `RequestVault: Compare 2 Responses` | Directly launches the diff tab with the 2 highlighted messages |
| **RequestVault Table** | `Copy as JSON / CSV / HTML / Markdown` | Copies table selection to clipboard in requested format |

---

## Building from Source

### Clone the Repository
```bash
git clone https://github.com/Kakaxh1/RequestVault.git
cd RequestVault
```

### Option 1: Windows One-Click Build Script
Run the automated packaging script from the project root:
```powershell
cmd /c build.bat
```

### Option 2: Gradle
If you have Gradle installed on your system:
```bash
gradle build
```

The output fat JAR will be generated at:
```
build/libs/RequestVault.jar
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

# RequestVault for Caido

**RequestVault** is a local-first HTTP traffic collection, analysis, multi-language replay code generator, response diffing, and forensic evidence-export plugin built for the **Caido** web security auditing toolkit.

---

## Overview

RequestVault extends Caido with advanced VAPT evidence collection and exploit script generation workflows:

- **Multi-Language Replay & Exploit Code Generators**: Instantly convert captured transactions from Caido's HTTP History, Intercept, or Replay into ready-to-run scripts in **cURL**, **Python (`requests`)**, **JavaScript (`fetch`)**, **PowerShell (`Invoke-RestMethod`)**, and **Raw HTTP (RFC 7230)**.
- **Top-Level Context Menus**: Right-click any request in Caido to immediately execute **"RequestVault: Copy this request as cURL"** or send items into the vault.
- **Dedicated RequestVault Workspace**: Built directly into Caido's navigation sidebar with apex domain grouping, granular sequence numbering, and full-text forensic search.
- **Side-by-Side Response Diffing**: Compare two responses (e.g. Authenticated vs Anonymous, Admin vs User, Baseline vs Tampered) with visual status alerts, header deltas, and body line diffs.
- **Multi-Format Evidence Packs**: Export captured flows into interactive standalone HTML reports, Markdown bug bounty dossiers, JSON evidence, CSV triage summaries, HAR 1.2 archives, and SHA-256 integrity manifests with non-destructive credential redaction.

---

## Table of Contents

- [Key Features](#key-features)
  - [1. Multi-Language Exploit & Replay Generators](#1-multi-language-exploit--replay-generators)
  - [2. Top-Level Context Menu Shortcuts](#2-top-level-context-menu-shortcuts)
  - [3. Dedicated Caido Sidebar Workspace](#3-dedicated-caido-sidebar-workspace)
  - [4. Hierarchical Domain & Subdomain Tree](#4-hierarchical-domain--subdomain-tree)
  - [5. Granular Multi-Attribute Filtering](#5-granular-multi-attribute-filtering)
  - [6. Deep Full-Text & Regex Traffic Search](#6-deep-full-text--regex-traffic-search)
  - [7. Side-by-Side Response Diffing](#7-side-by-side-response-diffing)
  - [8. Multi-Format Evidence Packs & Redaction](#8-multi-format-evidence-packs--redaction)
  - [9. Cryptographic Evidence Integrity (SHA-256)](#9-cryptographic-evidence-integrity-sha-256)
- [Installation Guide](#installation-guide)
- [Building from Source](#building-from-source)
- [Author & Maintainer](#author--maintainer)
- [License](#license)

---

## Key Features

### 1. Multi-Language Exploit & Replay Generators
Convert single requests or multi-step attack chains into copy-pasteable execution scripts:
- **cURL**: Single and chained bash commands with `-X <METHOD>`, custom headers `-H`, payload `--data-raw`, and `-k` (insecure SSL bypass). Quotes are safely escaped for bash execution.
- **Python (`requests`)**: Formatted scripts with `urllib3.disable_warnings()`, `verify=False`, session management (`requests.Session()`) for multi-step flows, and status code/body inspection.
- **JavaScript (`fetch`)**: Modern asynchronous Fetch API snippets ready to run in browser DevTools console or Node.js.
- **PowerShell (`Invoke-RestMethod`)**: Native Windows PowerShell snippets utilizing `$headers = @{...}` hashtables, body here-strings, and `-SkipCertificateCheck`.
- **Raw HTTP (RFC 7230)**: Exact wire-format HTTP request blocks with CRLF delimiters ready for netcat (`nc`) or socket replay.

### 2. Top-Level Context Menu Shortcuts
Integrates natively into Caido's right-click context menus:
| Location | Action | Description |
| :--- | :--- | :--- |
| **HTTP History Table** | `RequestVault: Copy this request as cURL` | Copies ready-to-run cURL command to clipboard |
| **HTTP History Table** | `RequestVault: Copy as Python (requests)` | Copies Python requests script to clipboard |
| **HTTP History Table** | `RequestVault: Copy as JavaScript (fetch)` | Copies modern fetch snippet to clipboard |
| **HTTP History Table** | `RequestVault: Copy as PowerShell` | Copies PowerShell Invoke-RestMethod snippet |
| **HTTP History Table** | `RequestVault: Copy as Raw HTTP` | Copies raw RFC 7230 request text |
| **HTTP History Table** | `RequestVault: Send to RequestVault` | Ingests selected request/response pairs into the vault |
| **Request Editor Pane** | `RequestVault: Copy this request as cURL` | Available directly in active request editor |
| **Request Editor Pane** | `RequestVault: Send to RequestVault` | Sends current draft/full request to the vault |

### 3. Dedicated Caido Sidebar Workspace
- Accessible via the **RequestVault** shield icon in Caido's navigation sidebar (`/requestvault`).
- Provides a centralized view of all captured engagement evidence without cluttering proxy history.
- Includes a live capture synchronization engine that pulls requests and responses via Caido's local GraphQL API.

### 4. Hierarchical Domain & Subdomain Tree
- Automatically groups hosts by apex domain (e.g. `example.com` -> `api.example.com`, `auth.example.com`).
- Interactive checkboxes allow rapid scoping to isolate specific targets during multi-target assessments.

### 5. Granular Multi-Attribute Filtering
- **Status Categories**: Filter by `2xx Success`, `3xx Redirection`, `4xx Client Error`, `5xx Server Error`, or `Auth Failures (401/403)`.
- **MIME Categories**: `JSON`, `HTML`, `XML`, `Plain Text`, `Scripts/CSS`, and `Binary/Media`.
- **Time Windows**: Filter by `All Time`, `Last 5 Minutes`, `Last 15 Minutes`, `Last 1 Hour`, or `Last 24 Hours`.
- **Authentication Endpoints Filter**: Detects authentication endpoints (`/login`, `/token`, `/oauth`, `/auth`, `/session`) and credential headers (`Authorization`, `Bearer`, `Cookie`, `x-api-key`).

### 6. Deep Full-Text & Regex Traffic Search
- Comprehensive search engine supporting exact match, case sensitivity, regex patterns, and inverted match (`NOT`).
- Search scopes: `Everywhere`, `URL & Path`, `Headers`, `Request Body`, `Response Body`, `Method`, and `Status`.

### 7. Side-by-Side Response Diffing
- Compare any two responses (e.g. Low Privilege vs High Privilege, Authenticated vs Unauthenticated):
  - Status code mismatch alerts (e.g. `200 OK` vs `403 Forbidden`).
  - Content length / byte size deltas.
  - Header additions, deletions, and modifications.
  - Line-by-line body diffing with color indicators.

### 8. Multi-Format Evidence Packs & Redaction
- Export captured flows into multiple deliverable formats:
  - **Interactive HTML Report**: Self-contained styled report with badges, expandable bodies, and summary tables.
  - **Markdown VAPT Dossier**: Formatted markdown documentation with syntax-highlighted HTTP blocks.
  - **Structured JSON Evidence**: Machine-readable JSON output with timestamps, sizes, and integrity hashes.
  - **CSV Triage Spreadsheet**: Tabular summary for project tracking and scope reviews.
  - **HAR 1.2 Archive**: Standard archive for interoperability with external tools.
- **Non-Destructive Redaction**: Automatically masks sensitive tokens (`Bearer <REDACTED>`), session cookies (`PHPSESSID`, `token`), API keys, and body passwords in exported files while preserving raw in-memory evidence.

### 9. Cryptographic Evidence Integrity (SHA-256)
- Automatically computes SHA-256 hashes for all requests and responses.
- Generates an `evidence-manifest.json` file for exported packages to establish proof of non-tampering and chain of custody.

---

## Installation Guide

### Installing into Caido

1. Obtain the compiled plugin archive:
   - File: `dist/requestvault-caido.zip`
2. Open your **Caido** desktop application or web interface.
3. In the left navigation, click on **Plugins**.
4. In the top right corner, click **Install from File** (or drag and drop the `.zip` archive).
5. Select `requestvault-caido.zip`.
6. Once installed, **RequestVault** will appear in the sidebar navigation and in all right-click context menus.

---

## Building from Source

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher

### Build Steps

1. Clone or navigate to the repository:
   ```bash
   cd Caido/RequestVault-Caido
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build and package the plugin:
   ```bash
   node build.js
   ```
   Or on Windows:
   ```cmd
   build.bat
   ```

4. Run automated unit tests:
   ```bash
   node test/test.js
   ```

5. The distributable package is generated at:
   ```text
   dist/requestvault-caido.zip
   ```

---

## Author & Maintainer

**Kakaxh1**
- GitHub Profile: [https://github.com/Kakaxh1](https://github.com/Kakaxh1)
- Project Repository: [https://github.com/Kakaxh1/RequestVault](https://github.com/Kakaxh1/RequestVault)
- Website: [https://bhavymorvadiya.netlify.app/](https://bhavymorvadiya.netlify.app/)

---

## License

This project is licensed under the **MIT License**. Free for commercial and personal penetration testing engagements.

---

<p align="center">
  Developed by <a href="https://bhavymorvadiya.netlify.app/">bhavymorvadiya.netlify.app</a>
</p>

/**
 * RequestVault for Caido - Interactive Web UI Application
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { type API as CaidoAPI } from "@caido/sdk-frontend";
import { Exporters } from "../export/Exporters";
import { ReplayCodeGenerator } from "../export/ReplayCodeGenerator";
import { TrafficStore } from "../storage/Store";
import { ExportOptions, FilterState, TrafficRecord } from "../types";
import { ResponseDiff } from "./ResponseDiff";

export class RequestVaultApp {
  private sdk: CaidoAPI;
  private store: TrafficStore;
  private root: HTMLElement;

  private selectedRecordIds: Set<string> = new Set();
  private activeRecord: TrafficRecord | null = null;
  private activeTab: "REQUEST" | "RESPONSE" | "METADATA" | "DIFF" = "REQUEST";

  private filterState: FilterState = {
    searchTerm: "",
    searchRegex: false,
    searchCaseSensitive: false,
    searchInvert: false,
    searchScope: "EVERYWHERE",
    statusCategory: "ALL",
    customStatusRange: "",
    mimeCategory: "ALL",
    customMime: "",
    timeRange: "ALL_TIME",
    apiPath: "",
    authEndpointsOnly: false,
    selectedOnly: false,
    selectedDomains: new Set()
  };

  constructor(sdk: CaidoAPI, store: TrafficStore) {
    this.sdk = sdk;
    this.store = store;
    this.root = document.createElement("div");
    this.root.className = "rv-container";

    this.store.subscribe(() => {
      this.render();
    });
  }

  public getRootElement(): HTMLElement {
    this.render();
    return this.root;
  }

  public render(): void {
    const displayed = this.store.filterRecords(this.filterState, this.selectedRecordIds);
    if (!this.activeRecord && displayed.length > 0) {
      this.activeRecord = displayed[0];
    }

    this.root.innerHTML = "";
    this.injectStyles();

    // 1. Top Action Toolbar
    const toolbar = this.createToolbar(displayed);
    this.root.appendChild(toolbar);

    // 2. Filter Bar
    const filterBar = this.createFilterBar();
    this.root.appendChild(filterBar);

    // 3. Main Workspace (Domain Tree + Traffic Table + Inspector)
    const mainWorkspace = document.createElement("div");
    mainWorkspace.className = "rv-workspace";

    const domainSidebar = this.createDomainTree();
    mainWorkspace.appendChild(domainSidebar);

    const rightContent = document.createElement("div");
    rightContent.className = "rv-right-content";

    const tablePanel = this.createTablePanel(displayed);
    rightContent.appendChild(tablePanel);

    const inspectorPanel = this.createInspectorPanel();
    rightContent.appendChild(inspectorPanel);

    mainWorkspace.appendChild(rightContent);
    this.root.appendChild(mainWorkspace);

    // 4. Status Bar & Footer
    const footer = this.createStatusBar(displayed.length);
    this.root.appendChild(footer);
  }

  // -------------------------------------------------------------
  // Toolbars & Action Controls
  // -------------------------------------------------------------
  private createToolbar(displayed: TrafficRecord[]): HTMLElement {
    const bar = document.createElement("div");
    bar.className = "rv-toolbar";

    // Logo & Title
    const brand = document.createElement("div");
    brand.className = "rv-brand";
    brand.innerHTML = `<strong>RequestVault</strong> <span class="rv-tag">Caido Edition v1.0.0</span>`;
    bar.appendChild(brand);

    const actions = document.createElement("div");
    actions.className = "rv-actions";

    // Export Evidence Button
    const exportBtn = document.createElement("button");
    exportBtn.className = "rv-btn rv-btn-primary";
    exportBtn.textContent = "Export Evidence...";
    exportBtn.onclick = () => this.showExportModal(displayed);
    actions.appendChild(exportBtn);

    // Copy Replay Code Dropdown
    const copySelect = document.createElement("select");
    copySelect.className = "rv-select";
    copySelect.innerHTML = `
      <option value="">Copy Replay Code ▼</option>
      <option value="CURL">cURL Command</option>
      <option value="PYTHON">Python (requests)</option>
      <option value="FETCH">JavaScript (fetch)</option>
      <option value="POWERSHELL">PowerShell</option>
      <option value="RAW">Raw HTTP (RFC 7230)</option>
      <option value="MARKDOWN">Markdown Bug Report</option>
      <option value="JSON">JSON Evidence</option>
      <option value="CSV">CSV Triage</option>
    `;
    copySelect.onchange = () => {
      const val = copySelect.value;
      if (!val) return;
      this.copyBatch(val, displayed);
      copySelect.value = "";
    };
    actions.appendChild(copySelect);

    // Import from Caido Proxy History
    const importBtn = document.createElement("button");
    importBtn.className = "rv-btn";
    importBtn.textContent = "Import Caido History";
    importBtn.onclick = () => this.importCaidoHistory();
    actions.appendChild(importBtn);

    // Compare (2)
    const compareBtn = document.createElement("button");
    compareBtn.className = "rv-btn";
    compareBtn.textContent = "Compare (2)";
    compareBtn.onclick = () => this.triggerCompare();
    actions.appendChild(compareBtn);

    // Clear
    const clearBtn = document.createElement("button");
    clearBtn.className = "rv-btn rv-btn-danger";
    clearBtn.textContent = "Clear";
    clearBtn.onclick = () => {
      if (confirm("Clear all captured records in RequestVault?")) {
        this.store.clear();
        this.selectedRecordIds.clear();
        this.activeRecord = null;
      }
    };
    actions.appendChild(clearBtn);

    bar.appendChild(actions);
    return bar;
  }

  private createFilterBar(): HTMLElement {
    const bar = document.createElement("div");
    bar.className = "rv-filter-bar";

    // Row 1: Search Input & Scope
    const searchGroup = document.createElement("div");
    searchGroup.className = "rv-filter-group";

    const searchInput = document.createElement("input");
    searchInput.type = "text";
    searchInput.className = "rv-input";
    searchInput.placeholder = "Search (full-text, endpoint, token, status)...";
    searchInput.value = this.filterState.searchTerm;
    searchInput.oninput = () => {
      this.filterState.searchTerm = searchInput.value;
      this.render();
    };
    searchGroup.appendChild(searchInput);

    const regexLabel = document.createElement("label");
    regexLabel.className = "rv-checkbox-label";
    const regexCheck = document.createElement("input");
    regexCheck.type = "checkbox";
    regexCheck.checked = this.filterState.searchRegex;
    regexCheck.onchange = () => { this.filterState.searchRegex = regexCheck.checked; this.render(); };
    regexLabel.appendChild(regexCheck);
    regexLabel.appendChild(document.createTextNode("Regex"));
    searchGroup.appendChild(regexLabel);

    const caseLabel = document.createElement("label");
    caseLabel.className = "rv-checkbox-label";
    const caseCheck = document.createElement("input");
    caseCheck.type = "checkbox";
    caseCheck.checked = this.filterState.searchCaseSensitive;
    caseCheck.onchange = () => { this.filterState.searchCaseSensitive = caseCheck.checked; this.render(); };
    caseLabel.appendChild(caseCheck);
    caseLabel.appendChild(document.createTextNode("Match Case"));
    searchGroup.appendChild(caseLabel);

    const invertLabel = document.createElement("label");
    invertLabel.className = "rv-checkbox-label";
    const invertCheck = document.createElement("input");
    invertCheck.type = "checkbox";
    invertCheck.checked = this.filterState.searchInvert;
    invertCheck.onchange = () => { this.filterState.searchInvert = invertCheck.checked; this.render(); };
    invertLabel.appendChild(invertCheck);
    invertLabel.appendChild(document.createTextNode("Invert (NOT)"));
    searchGroup.appendChild(invertLabel);

    bar.appendChild(searchGroup);

    // Row 2: Status, MIME, Time, Auth
    const filterRow2 = document.createElement("div");
    filterRow2.className = "rv-filter-row";

    // Status
    const statusSelect = document.createElement("select");
    statusSelect.className = "rv-select";
    statusSelect.innerHTML = `
      <option value="ALL">Status: All</option>
      <option value="2XX">2xx Success</option>
      <option value="3XX">3xx Redirection</option>
      <option value="4XX">4xx Client Error</option>
      <option value="5XX">5xx Server Error</option>
      <option value="AUTH_FAILURES">Auth Failures (401/403)</option>
    `;
    statusSelect.value = this.filterState.statusCategory;
    statusSelect.onchange = () => {
      this.filterState.statusCategory = statusSelect.value as FilterState["statusCategory"];
      this.render();
    };
    filterRow2.appendChild(statusSelect);

    // MIME
    const mimeSelect = document.createElement("select");
    mimeSelect.className = "rv-select";
    mimeSelect.innerHTML = `
      <option value="ALL">MIME: All Types</option>
      <option value="JSON">JSON (application/json)</option>
      <option value="HTML">HTML (text/html)</option>
      <option value="XML">XML</option>
      <option value="PLAIN_TEXT">Plain Text</option>
      <option value="SCRIPTS">Scripts / CSS</option>
      <option value="BINARY_MEDIA">Binary / Media</option>
    `;
    mimeSelect.value = this.filterState.mimeCategory;
    mimeSelect.onchange = () => {
      this.filterState.mimeCategory = mimeSelect.value as FilterState["mimeCategory"];
      this.render();
    };
    filterRow2.appendChild(mimeSelect);

    // Time
    const timeSelect = document.createElement("select");
    timeSelect.className = "rv-select";
    timeSelect.innerHTML = `
      <option value="ALL_TIME">Time: All</option>
      <option value="LAST_5_MIN">Last 5 Minutes</option>
      <option value="LAST_15_MIN">Last 15 Minutes</option>
      <option value="LAST_1_HOUR">Last 1 Hour</option>
      <option value="LAST_24_HOURS">Last 24 Hours</option>
    `;
    timeSelect.value = this.filterState.timeRange;
    timeSelect.onchange = () => {
      this.filterState.timeRange = timeSelect.value as FilterState["timeRange"];
      this.render();
    };
    filterRow2.appendChild(timeSelect);

    // Path
    const pathInput = document.createElement("input");
    pathInput.type = "text";
    pathInput.className = "rv-input";
    pathInput.placeholder = "Path filter (e.g. /api/v1)";
    pathInput.value = this.filterState.apiPath;
    pathInput.oninput = () => {
      this.filterState.apiPath = pathInput.value;
      this.render();
    };
    filterRow2.appendChild(pathInput);

    // Auth Endpoints Checkbox
    const authLabel = document.createElement("label");
    authLabel.className = "rv-checkbox-label";
    const authCheck = document.createElement("input");
    authCheck.type = "checkbox";
    authCheck.checked = this.filterState.authEndpointsOnly;
    authCheck.onchange = () => { this.filterState.authEndpointsOnly = authCheck.checked; this.render(); };
    authLabel.appendChild(authCheck);
    authLabel.appendChild(document.createTextNode("Auth Endpoints Only"));
    filterRow2.appendChild(authLabel);

    // Selected Only Checkbox
    const selLabel = document.createElement("label");
    selLabel.className = "rv-checkbox-label";
    const selCheck = document.createElement("input");
    selCheck.type = "checkbox";
    selCheck.checked = this.filterState.selectedOnly;
    selCheck.onchange = () => { this.filterState.selectedOnly = selCheck.checked; this.render(); };
    selLabel.appendChild(selCheck);
    selLabel.appendChild(document.createTextNode(`Selected Only (${this.selectedRecordIds.size})`));
    filterRow2.appendChild(selLabel);

    bar.appendChild(filterRow2);
    return bar;
  }

  // -------------------------------------------------------------
  // Domain Hierarchy Sidebar
  // -------------------------------------------------------------
  private createDomainTree(): HTMLElement {
    const sidebar = document.createElement("div");
    sidebar.className = "rv-domain-tree";

    const header = document.createElement("div");
    header.className = "rv-domain-header";
    header.innerHTML = `<strong>Domains & Hosts</strong>`;

    const btnGroup = document.createElement("div");
    btnGroup.style.display = "flex";
    btnGroup.style.gap = "4px";

    const allBtn = document.createElement("button");
    allBtn.className = "rv-btn-mini";
    allBtn.textContent = "All";
    allBtn.onclick = () => {
      this.filterState.selectedDomains.clear();
      this.render();
    };
    btnGroup.appendChild(allBtn);

    header.appendChild(btnGroup);
    sidebar.appendChild(header);

    const list = document.createElement("div");
    list.className = "rv-domain-list";

    const hierarchy = this.store.getDomainHierarchy();
    if (hierarchy.size === 0) {
      list.innerHTML = `<div class="rv-empty-hint">No captured hosts yet.</div>`;
    } else {
      for (const [apex, subdomains] of hierarchy.entries()) {
        const apexDiv = document.createElement("div");
        apexDiv.className = "rv-domain-apex";

        const apexLabel = document.createElement("label");
        apexLabel.className = "rv-checkbox-label";
        const apexCheck = document.createElement("input");
        apexCheck.type = "checkbox";
        const allChecked = Array.from(subdomains).every(s => this.filterState.selectedDomains.has(s));
        apexCheck.checked = allChecked && subdomains.size > 0;
        apexCheck.onchange = () => {
          if (apexCheck.checked) {
            subdomains.forEach(s => this.filterState.selectedDomains.add(s));
          } else {
            subdomains.forEach(s => this.filterState.selectedDomains.delete(s));
          }
          this.render();
        };
        apexLabel.appendChild(apexCheck);
        apexLabel.appendChild(document.createTextNode(apex));
        apexDiv.appendChild(apexLabel);

        const subList = document.createElement("div");
        subList.className = "rv-subdomain-list";

        for (const sub of subdomains) {
          const subItem = document.createElement("label");
          subItem.className = "rv-subdomain-item";
          const subCheck = document.createElement("input");
          subCheck.type = "checkbox";
          subCheck.checked = this.filterState.selectedDomains.has(sub);
          subCheck.onchange = () => {
            if (subCheck.checked) {
              this.filterState.selectedDomains.add(sub);
            } else {
              this.filterState.selectedDomains.delete(sub);
            }
            this.render();
          };
          subItem.appendChild(subCheck);
          subItem.appendChild(document.createTextNode(sub));
          subList.appendChild(subItem);
        }

        apexDiv.appendChild(subList);
        list.appendChild(apexDiv);
      }
    }

    sidebar.appendChild(list);
    return sidebar;
  }

  // -------------------------------------------------------------
  // Main Traffic Table
  // -------------------------------------------------------------
  private createTablePanel(records: TrafficRecord[]): HTMLElement {
    const panel = document.createElement("div");
    panel.className = "rv-table-panel";

    const table = document.createElement("table");
    table.className = "rv-table";

    // Table Header
    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");

    const selectTh = document.createElement("th");
    selectTh.style.width = "30px";
    const masterCheck = document.createElement("input");
    masterCheck.type = "checkbox";
    masterCheck.checked = records.length > 0 && records.every(r => this.selectedRecordIds.has(r.recordId));
    masterCheck.onchange = () => {
      if (masterCheck.checked) {
        records.forEach(r => this.selectedRecordIds.add(r.recordId));
      } else {
        records.forEach(r => this.selectedRecordIds.delete(r.recordId));
      }
      this.render();
    };
    selectTh.appendChild(masterCheck);
    headerRow.appendChild(selectTh);

    const cols = ["#", "Method", "Host", "Path", "Status", "Content-Type", "Size", "Time"];
    for (const c of cols) {
      const th = document.createElement("th");
      th.textContent = c;
      headerRow.appendChild(th);
    }
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Table Body
    const tbody = document.createElement("tbody");
    if (records.length === 0) {
      const emptyRow = document.createElement("tr");
      emptyRow.innerHTML = `<td colspan="9" class="rv-empty-table">No traffic records match active filters. Click "Import Caido History" to load proxy traffic.</td>`;
      tbody.appendChild(emptyRow);
    } else {
      for (const r of records) {
        const tr = document.createElement("tr");
        if (this.activeRecord && this.activeRecord.recordId === r.recordId) {
          tr.className = "rv-row-active";
        }

        // Checkbox cell
        const checkTd = document.createElement("td");
        const rowCheck = document.createElement("input");
        rowCheck.type = "checkbox";
        rowCheck.checked = this.selectedRecordIds.has(r.recordId);
        rowCheck.onclick = (e) => {
          e.stopPropagation();
          if (rowCheck.checked) {
            this.selectedRecordIds.add(r.recordId);
          } else {
            this.selectedRecordIds.delete(r.recordId);
          }
          this.render();
        };
        checkTd.appendChild(rowCheck);
        tr.appendChild(checkTd);

        // Sequence #
        const seqTd = document.createElement("td");
        seqTd.textContent = `#${r.sequenceNumber}`;
        tr.appendChild(seqTd);

        // Method
        const methodTd = document.createElement("td");
        const methodBadge = document.createElement("span");
        methodBadge.className = `rv-badge rv-method-${(r.method || "GET").toLowerCase()}`;
        methodBadge.textContent = r.method;
        methodTd.appendChild(methodBadge);
        tr.appendChild(methodTd);

        // Host
        const hostTd = document.createElement("td");
        hostTd.textContent = r.host;
        tr.appendChild(hostTd);

        // Path
        const pathTd = document.createElement("td");
        pathTd.className = "rv-path-cell";
        pathTd.textContent = r.path;
        pathTd.title = r.url;
        tr.appendChild(pathTd);

        // Status
        const statusTd = document.createElement("td");
        if (r.statusCode) {
          const statusBadge = document.createElement("span");
          statusBadge.className = `rv-badge rv-status-${Math.floor(r.statusCode / 100)}xx`;
          statusBadge.textContent = String(r.statusCode);
          statusTd.appendChild(statusBadge);
        } else {
          statusTd.textContent = "-";
        }
        tr.appendChild(statusTd);

        // MIME
        const mimeTd = document.createElement("td");
        mimeTd.textContent = r.contentType || "-";
        tr.appendChild(mimeTd);

        // Size
        const sizeTd = document.createElement("td");
        sizeTd.textContent = `${r.responseSize} B`;
        tr.appendChild(sizeTd);

        // Time
        const timeTd = document.createElement("td");
        timeTd.textContent = `${r.durationMs}ms`;
        tr.appendChild(timeTd);

        // Row Click: set as active record in inspector
        tr.onclick = () => {
          this.activeRecord = r;
          this.render();
        };

        tbody.appendChild(tr);
      }
    }

    table.appendChild(tbody);
    panel.appendChild(table);
    return panel;
  }

  // -------------------------------------------------------------
  // Inspector Pane (Request, Response, Metadata, Diff)
  // -------------------------------------------------------------
  private createInspectorPanel(): HTMLElement {
    const inspector = document.createElement("div");
    inspector.className = "rv-inspector";

    // Tab Headers
    const tabsBar = document.createElement("div");
    tabsBar.className = "rv-inspector-tabs";

    const tabs: { id: "REQUEST" | "RESPONSE" | "METADATA" | "DIFF"; label: string }[] = [
      { id: "REQUEST", label: "Request" },
      { id: "RESPONSE", label: "Response" },
      { id: "METADATA", label: "Metadata & Integrity" },
      { id: "DIFF", label: "Response Diff" }
    ];

    for (const t of tabs) {
      const btn = document.createElement("button");
      btn.className = `rv-tab-btn ${this.activeTab === t.id ? "rv-tab-active" : ""}`;
      btn.textContent = t.label;
      btn.onclick = () => {
        this.activeTab = t.id;
        this.render();
      };
      tabsBar.appendChild(btn);
    }

    // Quick Replay buttons on the right of the tab bar
    if (this.activeRecord) {
      const quickTools = document.createElement("div");
      quickTools.style.marginLeft = "auto";
      quickTools.style.display = "flex";
      quickTools.style.gap = "6px";

      const curlBtn = document.createElement("button");
      curlBtn.className = "rv-btn-mini";
      curlBtn.textContent = "Copy as cURL";
      curlBtn.onclick = () => {
        if (this.activeRecord) {
          const curl = ReplayCodeGenerator.toCurl(this.activeRecord);
          navigator.clipboard.writeText(curl);
          this.sdk.window.showToast("Copied active request as cURL command!", { variant: "success" });
        }
      };
      quickTools.appendChild(curlBtn);

      const pyBtn = document.createElement("button");
      pyBtn.className = "rv-btn-mini";
      pyBtn.textContent = "Copy as Python";
      pyBtn.onclick = () => {
        if (this.activeRecord) {
          const py = ReplayCodeGenerator.toPython(this.activeRecord);
          navigator.clipboard.writeText(py);
          this.sdk.window.showToast("Copied active request as Python script!", { variant: "success" });
        }
      };
      quickTools.appendChild(pyBtn);

      tabsBar.appendChild(quickTools);
    }

    inspector.appendChild(tabsBar);

    // Tab Content View
    const contentView = document.createElement("div");
    contentView.className = "rv-inspector-content";

    if (!this.activeRecord) {
      contentView.innerHTML = `<div class="rv-empty-hint">Select a traffic record above to inspect headers and payloads.</div>`;
    } else {
      switch (this.activeTab) {
        case "REQUEST": {
          const pre = document.createElement("pre");
          pre.className = "rv-code-viewer";
          const raw = ReplayCodeGenerator.toRawHttp(this.activeRecord);
          pre.textContent = raw;
          contentView.appendChild(pre);
          break;
        }
        case "RESPONSE": {
          const pre = document.createElement("pre");
          pre.className = "rv-code-viewer";
          const lines: string[] = [
            `HTTP/1.1 ${this.activeRecord.statusCode} ${this.activeRecord.statusReason || ""}`,
            ...(this.activeRecord.responseHeaders || []),
            "",
            this.activeRecord.responseBody || ""
          ];
          pre.textContent = lines.join("\n");
          contentView.appendChild(pre);
          break;
        }
        case "METADATA": {
          const pre = document.createElement("pre");
          pre.className = "rv-code-viewer";
          const metaText = [
            "=== EVIDENCE METADATA & INTEGRITY ===",
            "",
            `Record #:        #${this.activeRecord.sequenceNumber}`,
            `Record ID:       ${this.activeRecord.recordId}`,
            `Full URL:        ${this.activeRecord.url}`,
            `Target Host:     ${this.activeRecord.host}:${this.activeRecord.port} (${this.activeRecord.isTls ? "HTTPS" : "HTTP"})`,
            `Method & Path:   ${this.activeRecord.method} ${this.activeRecord.path}`,
            `Status Code:     ${this.activeRecord.statusCode} ${this.activeRecord.statusReason || ""}`,
            `Content-Type:    ${this.activeRecord.contentType || "-"}`,
            `Request Size:    ${this.activeRecord.requestSize} bytes`,
            `Response Size:   ${this.activeRecord.responseSize} bytes`,
            `Duration:        ${this.activeRecord.durationMs} ms`,
            `Captured At:     ${new Date(this.activeRecord.timestamp).toISOString()}`,
            `Source Tool:     ${this.activeRecord.sourceTool}`,
            "",
            "--- CRYPTOGRAPHIC HASHES (SHA-256) ---",
            `Request Hash:    ${this.activeRecord.requestHash || "-"}`,
            `Response Hash:   ${this.activeRecord.responseHash || "-"}`
          ].join("\n");
          pre.textContent = metaText;
          contentView.appendChild(pre);
          break;
        }
        case "DIFF": {
          const diffContainer = document.createElement("div");
          diffContainer.className = "rv-diff-view";

          const selectedRecords = this.store.getAll().filter(r => this.selectedRecordIds.has(r.recordId));
          if (selectedRecords.length !== 2) {
            diffContainer.innerHTML = `
              <div class="rv-empty-hint">
                To compare responses side-by-side, please check exactly <strong>2</strong> records in the table above.
              </div>
            `;
          } else {
            const diff = ResponseDiff.compare(selectedRecords[0], selectedRecords[1]);
            diffContainer.appendChild(this.renderDiffUI(diff));
          }
          contentView.appendChild(diffContainer);
          break;
        }
      }
    }

    inspector.appendChild(contentView);
    return inspector;
  }

  private renderDiffUI(diff: ReturnType<typeof ResponseDiff.compare>): HTMLElement {
    const wrap = document.createElement("div");

    // Header overview banner
    const banner = document.createElement("div");
    banner.className = `rv-diff-banner ${diff.statusMatch ? "rv-diff-match" : "rv-diff-mismatch"}`;
    banner.innerHTML = `
      <strong>Status:</strong> #${diff.recordA.sequenceNumber} (${diff.statusA}) vs #${diff.recordB.sequenceNumber} (${diff.statusB}) |
      <strong>Delta:</strong> ${diff.sizeDiff > 0 ? "+" : ""}${diff.sizeDiff} B
    `;
    wrap.appendChild(banner);

    // Security signals
    if (diff.securitySignals.length > 0) {
      const sigBox = document.createElement("div");
      sigBox.className = "rv-diff-signals";
      for (const s of diff.securitySignals) {
        const sigItem = document.createElement("div");
        sigItem.textContent = `[SIGNAL] ${s}`;
        sigBox.appendChild(sigItem);
      }
      wrap.appendChild(sigBox);
    }

    // Body Diff Lines
    const diffLines = document.createElement("div");
    diffLines.className = "rv-diff-lines";
    for (const line of diff.bodyDiffLines.slice(0, 100)) {
      const dRow = document.createElement("div");
      dRow.className = `rv-diff-line rv-diff-${line.type.toLowerCase()}`;
      dRow.textContent = `${line.type === "ADD" ? "+" : line.type === "REMOVE" ? "-" : " "} ${line.text}`;
      diffLines.appendChild(dRow);
    }
    wrap.appendChild(diffLines);

    return wrap;
  }

  // -------------------------------------------------------------
  // Status Bar & Footer
  // -------------------------------------------------------------
  private createStatusBar(displayedCount: number): HTMLElement {
    const bar = document.createElement("div");
    bar.className = "rv-status-bar";

    const left = document.createElement("div");
    left.innerHTML = `
      <span>Domains: <strong>${this.store.getDomainHierarchy().size}</strong></span> |
      <span>Requests: <strong>${displayedCount}</strong></span> |
      <span>Selected: <strong>${this.selectedRecordIds.size}</strong></span>
    `;
    bar.appendChild(left);

    const right = document.createElement("div");
    right.innerHTML = `Developed by <a href="https://bhavymorvadiya.netlify.app/" target="_blank">bhavymorvadiya.netlify.app</a>`;
    bar.appendChild(right);

    return bar;
  }

  // -------------------------------------------------------------
  // Actions: Replay Copying, History Ingestion, Modals
  // -------------------------------------------------------------
  private copyBatch(format: string, displayed: TrafficRecord[]): void {
    const targets = this.selectedRecordIds.size > 0
      ? this.store.getAll().filter(r => this.selectedRecordIds.has(r.recordId))
      : displayed;

    if (targets.length === 0) {
      this.sdk.window.showToast("No traffic records to copy.", { variant: "warning" });
      return;
    }

    let text = "";
    switch (format) {
      case "CURL":
        text = ReplayCodeGenerator.toCurlMulti(targets);
        break;
      case "PYTHON":
        text = ReplayCodeGenerator.toPythonMulti(targets);
        break;
      case "FETCH":
        text = ReplayCodeGenerator.toFetchMulti(targets);
        break;
      case "POWERSHELL":
        text = ReplayCodeGenerator.toPowerShellMulti(targets);
        break;
      case "RAW":
        text = ReplayCodeGenerator.toRawHttpMulti(targets);
        break;
      case "MARKDOWN":
        text = Exporters.generateMarkdown(targets, { format: "MARKDOWN", redactSecrets: true, includeManifest: false, separateFiles: false });
        break;
      case "JSON":
        text = Exporters.generateJson(targets, { format: "JSON", redactSecrets: true, includeManifest: false, separateFiles: false });
        break;
      case "CSV":
        text = Exporters.generateCsv(targets);
        break;
    }

    navigator.clipboard.writeText(text);
    this.sdk.window.showToast(`Copied ${targets.length} record(s) to clipboard as ${format}!`, { variant: "success" });
  }

  private async importCaidoHistory(): Promise<void> {
    try {
      this.sdk.window.showToast("Loading requests from Caido HTTP History...", { variant: "info" });

      // Query Caido GraphQL for historical requests
      const res = await this.sdk.graphql.requestsByOffset({ limit: 100, offset: 0 });
      if (!res || !res.requestsByOffset || !res.requestsByOffset.edges) {
        this.sdk.window.showToast("No records returned from Caido proxy history.", { variant: "warning" });
        return;
      }

      let added = 0;
      for (const edge of res.requestsByOffset.edges) {
        const meta = edge.node;
        if (!meta) continue;

        let req: any = meta;
        try {
          const fullRes = await this.sdk.graphql.request({ id: meta.id });
          if (fullRes?.request) {
            req = fullRes.request;
          }
        } catch {
          // fallback to meta
        }

        const rawReq: string = req.raw || "";
        const rawResp: string = req.response?.raw || "";
        const port = req.port || (req.isTls ? 443 : 80);
        const protocol = req.isTls ? "https" : "http";
        const url = `${protocol}://${req.host}${port === 80 || port === 443 ? "" : ":" + port}${req.path || "/"}${req.query ? "?" + req.query : ""}`;

        const reqHash = await Exporters.calculateSha256(rawReq);
        const respHash = rawResp ? await Exporters.calculateSha256(rawResp) : "";

        // Parse headers from raw if available
        const reqLines = rawReq.split("\r\n");
        const reqHeaders: string[] = [];
        let bodyIdx = -1;
        for (let i = 1; i < reqLines.length; i++) {
          if (reqLines[i] === "") { bodyIdx = i + 1; break; }
          reqHeaders.push(reqLines[i]);
        }
        const reqBody = bodyIdx > 0 ? reqLines.slice(bodyIdx).join("\r\n") : "";

        const respLines = rawResp.split("\r\n");
        const respHeaders: string[] = [];
        let respBodyIdx = -1;
        for (let i = 1; i < respLines.length; i++) {
          if (respLines[i] === "") { respBodyIdx = i + 1; break; }
          respHeaders.push(respLines[i]);
        }
        const respBody = respBodyIdx > 0 ? respLines.slice(respBodyIdx).join("\r\n") : "";

        let contentType = "";
        for (const h of respHeaders) {
          if (h.toLowerCase().startsWith("content-type:")) {
            contentType = h.substring(13).trim();
            break;
          }
        }

        const record: TrafficRecord = {
          recordId: req.id,
          sequenceNumber: 0,
          timestamp: req.createdAt ? new Date(req.createdAt).getTime() : Date.now(),
          durationMs: req.response?.roundtripTime || 0,
          method: req.method || "GET",
          host: req.host || "",
          port: port,
          isTls: !!req.isTls,
          path: req.path || "/",
          query: req.query || "",
          url: url,
          requestHeaders: reqHeaders,
          requestBody: reqBody,
          statusCode: req.response?.statusCode || 0,
          statusReason: "",
          responseHeaders: respHeaders,
          responseBody: respBody,
          contentType: contentType,
          requestSize: new TextEncoder().encode(rawReq).length,
          responseSize: new TextEncoder().encode(rawResp).length,
          rawRequest: rawReq,
          rawResponse: rawResp,
          requestHash: reqHash,
          responseHash: respHash,
          sourceTool: "Caido Proxy",
          inScope: true
        };

        if (this.store.addRecord(record, true)) {
          added++;
        }
      }

      this.sdk.window.showToast(`Imported ${added} record(s) from Caido Proxy History.`, { variant: "success" });
    } catch (err) {
      console.error("Caido history import failed:", err);
      this.sdk.window.showToast("Failed to import history from Caido GraphQL API.", { variant: "error" });
    }
  }

  private triggerCompare(): void {
    const selected = this.store.getAll().filter(r => this.selectedRecordIds.has(r.recordId));
    if (selected.length !== 2) {
      this.sdk.window.showToast("Please check exactly 2 records in the table to compare responses.", { variant: "warning" });
      return;
    }
    this.activeTab = "DIFF";
    this.render();
  }

  private showExportModal(displayed: TrafficRecord[]): void {
    const targets = this.selectedRecordIds.size > 0
      ? this.store.getAll().filter(r => this.selectedRecordIds.has(r.recordId))
      : displayed;

    if (targets.length === 0) {
      this.sdk.window.showToast("No traffic records to export.", { variant: "warning" });
      return;
    }

    const modalOverlay = document.createElement("div");
    modalOverlay.className = "rv-modal-overlay";

    const modalCard = document.createElement("div");
    modalCard.className = "rv-modal-card";

    modalCard.innerHTML = `
      <div class="rv-modal-header">
        <h3>Export Evidence Package (${targets.length} Records)</h3>
        <button class="rv-btn-close">&times;</button>
      </div>
      <div class="rv-modal-body">
        <label>Export Format:</label>
        <select class="rv-select" id="rv-export-fmt">
          <option value="HTML">Interactive HTML Report (.html)</option>
          <option value="MARKDOWN">Markdown VAPT Dossier (.md)</option>
          <option value="JSON">Structured JSON Evidence (.json)</option>
          <option value="CSV">Triage Spreadsheet (.csv)</option>
          <option value="HAR">Standard HAR 1.2 Archive (.har)</option>
        </select>

        <div style="margin-top: 16px;">
          <label class="rv-checkbox-label">
            <input type="checkbox" id="rv-redact-chk" checked />
            Apply Non-Destructive Secret Redaction (Mask tokens, passwords, cookies)
          </label>
        </div>

        <div style="margin-top: 8px;">
          <label class="rv-checkbox-label">
            <input type="checkbox" id="rv-manifest-chk" checked />
            Generate SHA-256 Cryptographic Evidence Manifest
          </label>
        </div>
      </div>
      <div class="rv-modal-footer">
        <button class="rv-btn" id="rv-cancel-btn">Cancel</button>
        <button class="rv-btn rv-btn-primary" id="rv-download-btn">Download Evidence</button>
      </div>
    `;

    modalOverlay.appendChild(modalCard);
    document.body.appendChild(modalOverlay);

    const close = () => { document.body.removeChild(modalOverlay); };
    modalCard.querySelector(".rv-btn-close")!.addEventListener("click", close);
    modalCard.querySelector("#rv-cancel-btn")!.addEventListener("click", close);

    modalCard.querySelector("#rv-download-btn")!.addEventListener("click", async () => {
      const fmt = (modalCard.querySelector("#rv-export-fmt") as HTMLSelectElement).value as ExportOptions["format"];
      const redact = (modalCard.querySelector("#rv-redact-chk") as HTMLInputElement).checked;
      const manifest = (modalCard.querySelector("#rv-manifest-chk") as HTMLInputElement).checked;

      const opts: ExportOptions = { format: fmt, redactSecrets: redact, includeManifest: manifest, separateFiles: false };

      let output = "";
      let filename = `evidence-${new Date().toISOString().split("T")[0]}`;

      switch (fmt) {
        case "HTML":
          output = Exporters.generateHtml(targets, opts);
          filename += ".html";
          break;
        case "MARKDOWN":
          output = Exporters.generateMarkdown(targets, opts);
          filename += ".md";
          break;
        case "JSON":
          output = Exporters.generateJson(targets, opts);
          filename += ".json";
          break;
        case "CSV":
          output = Exporters.generateCsv(targets);
          filename += ".csv";
          break;
        case "HAR":
          output = Exporters.generateHar(targets, opts);
          filename += ".har";
          break;
      }

      this.downloadBlob(output, filename);

      if (manifest) {
        const manifestContent = await Exporters.generateManifest(targets, filename, output);
        this.downloadBlob(manifestContent, `evidence-manifest-${filename}.json`);
      }

      this.sdk.window.showToast(`Exported ${filename} successfully!`, { variant: "success" });
      close();
    });
  }

  private downloadBlob(content: string, filename: string): void {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // -------------------------------------------------------------
  // Theme & Styles
  // -------------------------------------------------------------
  private injectStyles(): void {
    if (document.getElementById("rv-injected-styles")) return;
    const style = document.createElement("style");
    style.id = "rv-injected-styles";
    style.textContent = `
      .rv-container {
        display: flex;
        flex-direction: column;
        height: 100%;
        width: 100%;
        background: #0f1319;
        color: #d1d7e0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        box-sizing: border-box;
      }
      .rv-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 16px;
        background: #161b22;
        border-bottom: 1px solid #30363d;
      }
      .rv-brand { font-size: 14px; }
      .rv-tag {
        font-size: 10px;
        background: #21262d;
        color: #ff7a45;
        padding: 2px 6px;
        border-radius: 4px;
        margin-left: 6px;
      }
      .rv-actions { display: flex; align-items: center; gap: 8px; }
      .rv-btn {
        background: #21262d;
        color: #c9d1d9;
        border: 1px solid #30363d;
        padding: 5px 12px;
        border-radius: 4px;
        font-size: 12px;
        cursor: pointer;
      }
      .rv-btn:hover { background: #30363d; }
      .rv-btn-primary { background: #238636; color: white; border-color: #2ea043; }
      .rv-btn-primary:hover { background: #2ea043; }
      .rv-btn-danger { background: #da3633; color: white; border-color: #f85149; }
      .rv-btn-mini {
        background: #21262d;
        color: #c9d1d9;
        border: 1px solid #30363d;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        cursor: pointer;
      }
      .rv-select, .rv-input {
        background: #0d1117;
        color: #c9d1d9;
        border: 1px solid #30363d;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
      }
      .rv-filter-bar {
        padding: 8px 16px;
        background: #12161c;
        border-bottom: 1px solid #30363d;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .rv-filter-group { display: flex; align-items: center; gap: 12px; }
      .rv-filter-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
      .rv-checkbox-label {
        font-size: 12px;
        display: flex;
        align-items: center;
        gap: 4px;
        cursor: pointer;
        user-select: none;
      }
      .rv-workspace {
        display: flex;
        flex: 1;
        min-height: 0;
      }
      .rv-domain-tree {
        width: 220px;
        border-right: 1px solid #30363d;
        background: #11141a;
        display: flex;
        flex-direction: column;
      }
      .rv-domain-header {
        padding: 8px 12px;
        background: #161b22;
        border-bottom: 1px solid #30363d;
        font-size: 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      .rv-domain-list {
        padding: 8px;
        overflow-y: auto;
        flex: 1;
      }
      .rv-domain-apex { margin-bottom: 8px; }
      .rv-subdomain-list { margin-left: 16px; margin-top: 4px; }
      .rv-subdomain-item { display: flex; align-items: center; gap: 4px; font-size: 11px; margin-bottom: 2px; }
      .rv-right-content {
        display: flex;
        flex-direction: column;
        flex: 1;
        min-width: 0;
      }
      .rv-table-panel {
        flex: 1;
        overflow-y: auto;
        border-bottom: 1px solid #30363d;
      }
      .rv-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
        text-align: left;
      }
      .rv-table th {
        background: #161b22;
        padding: 6px 8px;
        border-bottom: 1px solid #30363d;
        position: sticky;
        top: 0;
        z-index: 1;
      }
      .rv-table td {
        padding: 6px 8px;
        border-bottom: 1px solid #21262d;
        white-space: nowrap;
      }
      .rv-table tr:hover { background: #161b22; cursor: pointer; }
      .rv-row-active { background: #1c2129 !important; border-left: 3px solid #ff7a45; }
      .rv-path-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; }
      .rv-badge {
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 10px;
        font-weight: bold;
      }
      .rv-method-get { background: #1f6feb; color: white; }
      .rv-method-post { background: #238636; color: white; }
      .rv-method-put { background: #d29922; color: white; }
      .rv-method-delete { background: #da3633; color: white; }
      .rv-status-2xx { background: #238636; color: white; }
      .rv-status-3xx { background: #8957e5; color: white; }
      .rv-status-4xx { background: #d29922; color: white; }
      .rv-status-5xx { background: #da3633; color: white; }
      .rv-inspector {
        height: 280px;
        display: flex;
        flex-direction: column;
        background: #0d1117;
      }
      .rv-inspector-tabs {
        display: flex;
        background: #161b22;
        border-bottom: 1px solid #30363d;
        padding: 0 8px;
        align-items: center;
      }
      .rv-tab-btn {
        background: transparent;
        color: #8b949e;
        border: none;
        border-bottom: 2px solid transparent;
        padding: 8px 14px;
        font-size: 12px;
        cursor: pointer;
      }
      .rv-tab-active { color: #f0f6fc; border-bottom-color: #ff7a45; }
      .rv-inspector-content {
        flex: 1;
        overflow: auto;
        padding: 8px;
      }
      .rv-code-viewer {
        margin: 0;
        font-family: Consolas, monospace;
        font-size: 11px;
        line-height: 1.4;
        white-space: pre-wrap;
        word-break: break-all;
      }
      .rv-diff-view { padding: 8px; }
      .rv-diff-banner {
        padding: 8px;
        border-radius: 4px;
        margin-bottom: 8px;
        font-size: 12px;
      }
      .rv-diff-match { background: #122818; border: 1px solid #238636; color: #3fb950; }
      .rv-diff-mismatch { background: #2c1517; border: 1px solid #da3633; color: #f85149; }
      .rv-diff-signals { margin-bottom: 8px; font-size: 11px; color: #e3b341; }
      .rv-diff-lines {
        background: #090d13;
        border: 1px solid #30363d;
        border-radius: 4px;
        font-family: Consolas, monospace;
        font-size: 11px;
        max-height: 180px;
        overflow: auto;
      }
      .rv-diff-line { padding: 2px 6px; }
      .rv-diff-add { background: rgba(46, 160, 67, 0.15); color: #3fb950; }
      .rv-diff-remove { background: rgba(248, 81, 73, 0.15); color: #f85149; }
      .rv-status-bar {
        padding: 4px 16px;
        background: #161b22;
        border-top: 1px solid #30363d;
        font-size: 11px;
        display: flex;
        justify-content: space-between;
      }
      .rv-status-bar a { color: #58a6ff; text-decoration: none; }
      .rv-empty-hint, .rv-empty-table {
        color: #8b949e;
        padding: 24px;
        text-align: center;
        font-size: 12px;
      }
      .rv-modal-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
      }
      .rv-modal-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        width: 480px;
        padding: 16px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.5);
      }
      .rv-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #30363d;
        padding-bottom: 8px;
      }
      .rv-modal-header h3 { margin: 0; font-size: 14px; }
      .rv-btn-close {
        background: none;
        border: none;
        color: #8b949e;
        font-size: 18px;
        cursor: pointer;
      }
      .rv-modal-body { padding: 16px 0; font-size: 12px; }
      .rv-modal-footer {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
        border-top: 1px solid #30363d;
        padding-top: 12px;
      }
    `;
    document.head.appendChild(style);
  }
}

/**
 * RequestVault for Caido - Plugin Entrypoint
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { type API as CaidoAPI } from "@caido/sdk-frontend";
import { type CommandContext, type CommandContextRequest, type CommandContextRequestRow, type CommandContextResponse } from "@caido/sdk-frontend/src/types/types/commands";
import { Exporters } from "./export/Exporters";
import { Redactor } from "./export/Redactor";
import { ReplayCodeGenerator } from "./export/ReplayCodeGenerator";
import { TrafficStore } from "./storage/Store";
import { TrafficRecord } from "./types";
import { RequestVaultApp } from "./ui/App";

export function init(sdk: CaidoAPI): void {
  const store = new TrafficStore();
  const app = new RequestVaultApp(sdk, store);

  // -------------------------------------------------------------
  // Helper: Extract TrafficRecords from Command Context
  // -------------------------------------------------------------
  async function getRecordsFromContext(context: CommandContext): Promise<TrafficRecord[]> {
    const records: TrafficRecord[] = [];

    if (context.type === "RequestRowContext") {
      const rowContext = context as CommandContextRequestRow;
      if (rowContext.requests && rowContext.requests.length > 0) {
        for (const meta of rowContext.requests) {
          try {
            // Fetch complete request and response details via GraphQL
            const res = await sdk.graphql.request({ id: meta.id });
            const req = res?.request;
            if (req) {
              const fullRecord = await convertToTrafficRecord(req);
              records.push(fullRecord);
            }
          } catch (err) {
            console.error("Failed to fetch full request for ID:", meta.id, err);
          }
        }
      }
    } else if (context.type === "RequestContext") {
      const reqContext = context as CommandContextRequest;
      const req = reqContext.request;
      if (req) {
        const fullRecord = await convertToTrafficRecord(req);
        records.push(fullRecord);
      }
    } else if (context.type === "ResponseContext") {
      const respContext = context as CommandContextResponse;
      if (respContext.request) {
        const res = await sdk.graphql.request({ id: respContext.request.id });
        if (res?.request) {
          const fullRecord = await convertToTrafficRecord(res.request);
          records.push(fullRecord);
        }
      }
    }

    return records;
  }

  async function convertToTrafficRecord(req: any): Promise<TrafficRecord> {
    const rawReq = req.raw || "";
    const rawResp = req.response?.raw || "";
    const port = req.port || (req.isTls ? 443 : 80);
    const protocol = req.isTls ? "https" : "http";
    const url = `${protocol}://${req.host}${port === 80 || port === 443 ? "" : ":" + port}${req.path || "/"}${req.query ? "?" + req.query : ""}`;

    const reqLines = rawReq.split("\r\n");
    const reqHeaders: string[] = [];
    let reqBodyIdx = -1;
    for (let i = 1; i < reqLines.length; i++) {
      if (reqLines[i] === "") { reqBodyIdx = i + 1; break; }
      reqHeaders.push(reqLines[i]);
    }
    const reqBody = reqBodyIdx > 0 ? reqLines.slice(reqBodyIdx).join("\r\n") : "";

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

    const reqHash = await Exporters.calculateSha256(rawReq);
    const respHash = rawResp ? await Exporters.calculateSha256(rawResp) : "";

    return {
      recordId: req.id || String(Date.now()),
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
      sourceTool: "Caido",
      inScope: true
    };
  }

  // -------------------------------------------------------------
  // Command 1: Copy this request as cURL
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.copyCurl", {
    name: "RequestVault: Copy this request as cURL",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const curl = ReplayCodeGenerator.toCurlMulti(records);
      await navigator.clipboard.writeText(curl);
      sdk.window.showToast(`Copied ${records.length} request(s) to clipboard as cURL!`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 2: Copy as Python (requests)
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.copyPython", {
    name: "RequestVault: Copy as Python (requests)",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const py = ReplayCodeGenerator.toPythonMulti(records);
      await navigator.clipboard.writeText(py);
      sdk.window.showToast(`Copied ${records.length} request(s) to clipboard as Python script!`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 3: Copy as JavaScript (fetch)
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.copyFetch", {
    name: "RequestVault: Copy as JavaScript (fetch)",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const fetchCode = ReplayCodeGenerator.toFetchMulti(records);
      await navigator.clipboard.writeText(fetchCode);
      sdk.window.showToast(`Copied ${records.length} request(s) to clipboard as JavaScript Fetch!`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 4: Copy as PowerShell
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.copyPowerShell", {
    name: "RequestVault: Copy as PowerShell",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const ps = ReplayCodeGenerator.toPowerShellMulti(records);
      await navigator.clipboard.writeText(ps);
      sdk.window.showToast(`Copied ${records.length} request(s) to clipboard as PowerShell!`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 5: Copy as Raw HTTP
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.copyRaw", {
    name: "RequestVault: Copy as Raw HTTP (RFC 7230)",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const raw = ReplayCodeGenerator.toRawHttpMulti(records);
      await navigator.clipboard.writeText(raw);
      sdk.window.showToast(`Copied ${records.length} request(s) to clipboard as Raw HTTP!`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 6: Send to RequestVault
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.sendToVault", {
    name: "RequestVault: Send to RequestVault",
    group: "RequestVault",
    run: async (context: CommandContext) => {
      const records = await getRecordsFromContext(context);
      if (records.length === 0) {
        sdk.window.showToast("No active request selected.", { variant: "warning" });
        return;
      }
      const added = store.addRecords(records, true);
      sdk.window.showToast(`Sent ${added} new transaction(s) to RequestVault (${records.length - added} duplicates skipped).`, { variant: "success" });
    }
  });

  // -------------------------------------------------------------
  // Command 7: Open RequestVault Page
  // -------------------------------------------------------------
  sdk.commands.register("requestvault.openVault", {
    name: "RequestVault: Open Workspace",
    group: "RequestVault",
    run: () => {
      sdk.navigation.goTo("/requestvault");
    }
  });

  // Register in Command Palette
  sdk.commandPalette.register("requestvault.openVault");
  sdk.commandPalette.register("requestvault.copyCurl");
  sdk.commandPalette.register("requestvault.sendToVault");

  // -------------------------------------------------------------
  // Context Menu Integration (RequestRow & Request Editor)
  // -------------------------------------------------------------
  // 1. In Request Tables (HTTP History / Intercept)
  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.copyCurl",
    leadingIcon: "fas fa-terminal"
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.copyPython",
    leadingIcon: "fab fa-python"
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.copyFetch",
    leadingIcon: "fab fa-js"
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.copyPowerShell",
    leadingIcon: "fas fa-code"
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.copyRaw",
    leadingIcon: "fas fa-file-lines"
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "requestvault.sendToVault",
    leadingIcon: "fas fa-shield-halved"
  });

  // 2. In Request Editor Pane
  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.copyCurl",
    leadingIcon: "fas fa-terminal"
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.copyPython",
    leadingIcon: "fab fa-python"
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.copyFetch",
    leadingIcon: "fab fa-js"
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.copyPowerShell",
    leadingIcon: "fas fa-code"
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.copyRaw",
    leadingIcon: "fas fa-file-lines"
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "requestvault.sendToVault",
    leadingIcon: "fas fa-shield-halved"
  });

  // -------------------------------------------------------------
  // Navigation Page & Sidebar Integration
  // -------------------------------------------------------------
  sdk.navigation.addPage("/requestvault", {
    body: app.getRootElement()
  });

  sdk.sidebar.registerItem("RequestVault", "/requestvault", {
    icon: "fas fa-shield-halved"
  });
}

export { ReplayCodeGenerator, Redactor, Exporters, TrafficStore };

/**
 * RequestVault for Caido - Response Diffing Engine & Visualizer
 * Compares two responses (e.g. Authenticated vs Anonymous, Admin vs User, Baseline vs Tampered)
 *
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { DiffResult, TrafficRecord } from "../types";

export class ResponseDiff {

  public static compare(recordA: TrafficRecord, recordB: TrafficRecord): DiffResult {
    const statusA = recordA.statusCode || 0;
    const statusB = recordB.statusCode || 0;
    const statusMatch = statusA === statusB;
    const sizeDiff = (recordB.responseSize || 0) - (recordA.responseSize || 0);

    const securitySignals: string[] = [];

    // Access Control Transitions
    if ((statusA === 200 && statusB === 403) || (statusA === 403 && statusB === 200)) {
      securitySignals.push(`Access Control Transition: #${recordA.sequenceNumber} (${statusA}) vs #${recordB.sequenceNumber} (${statusB})`);
    } else if ((statusA === 200 && statusB === 401) || (statusA === 401 && statusB === 200)) {
      securitySignals.push(`Authentication Transition: #${recordA.sequenceNumber} (${statusA}) vs #${recordB.sequenceNumber} (${statusB})`);
    }

    if (Math.abs(sizeDiff) > 500) {
      securitySignals.push(`Significant Body Size Delta: ${sizeDiff > 0 ? "+" : ""}${sizeDiff} bytes`);
    }

    // 1. Header Diff
    const mapA = this.parseHeaders(recordA.responseHeaders || []);
    const mapB = this.parseHeaders(recordB.responseHeaders || []);
    const allHeaderKeys = new Set<string>([...mapA.keys(), ...mapB.keys()]);

    const headerDiffs: DiffResult["headerDiffs"] = [];
    const secHeaders = new Set(["set-cookie", "authorization", "x-frame-options", "content-security-policy", "access-control-allow-origin", "strict-transport-security"]);

    for (const k of allHeaderKeys) {
      const valA = mapA.get(k);
      const valB = mapB.get(k);
      const isSec = secHeaders.has(k.toLowerCase());

      if (valA !== undefined && valB === undefined) {
        headerDiffs.push({ name: k, type: "REMOVED", valueA: valA, securityRelevant: isSec });
      } else if (valA === undefined && valB !== undefined) {
        headerDiffs.push({ name: k, type: "ADDED", valueB: valB, securityRelevant: isSec });
      } else if (valA !== valB) {
        headerDiffs.push({ name: k, type: "MODIFIED", valueA: valA, valueB: valB, securityRelevant: isSec });
      } else {
        headerDiffs.push({ name: k, type: "UNCHANGED", valueA: valA, valueB: valB, securityRelevant: isSec });
      }
    }

    // 2. Body Diff
    const linesA = (recordA.responseBody || "").split("\n");
    const linesB = (recordB.responseBody || "").split("\n");
    const bodyDiffLines = this.computeLineDiff(linesA, linesB);

    return {
      recordA,
      recordB,
      statusMatch,
      statusA,
      statusB,
      sizeDiff,
      headerDiffs,
      bodyDiffLines,
      securitySignals
    };
  }

  private static parseHeaders(headers: string[]): Map<string, string> {
    const map = new Map<string, string>();
    for (const h of headers) {
      const idx = h.indexOf(":");
      if (idx > 0) {
        const k = h.substring(0, idx).trim();
        const v = h.substring(idx + 1).trim();
        map.set(k, v);
      }
    }
    return map;
  }

  private static computeLineDiff(a: string[], b: string[]): DiffResult["bodyDiffLines"] {
    const diffs: DiffResult["bodyDiffLines"] = [];
    const max = Math.max(a.length, b.length);

    for (let i = 0; i < max; i++) {
      const lineA = a[i];
      const lineB = b[i];

      if (lineA !== undefined && lineB === undefined) {
        diffs.push({ type: "REMOVE", text: lineA });
      } else if (lineA === undefined && lineB !== undefined) {
        diffs.push({ type: "ADD", text: lineB });
      } else if (lineA === lineB) {
        diffs.push({ type: "EQUAL", text: lineA });
      } else {
        diffs.push({ type: "REMOVE", text: lineA });
        diffs.push({ type: "ADD", text: lineB });
      }
    }
    return diffs;
  }
}


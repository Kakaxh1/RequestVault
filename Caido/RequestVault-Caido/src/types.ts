/**
 * RequestVault for Caido - Core Type Definitions
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

export interface TrafficRecord {
  recordId: string;
  sequenceNumber: number;
  timestamp: number;
  durationMs: number;
  method: string;
  host: string;
  port: number;
  isTls: boolean;
  path: string;
  query: string;
  url: string;
  requestHeaders: string[];
  requestBody: string;
  statusCode: number;
  statusReason: string;
  responseHeaders: string[];
  responseBody: string;
  contentType: string;
  requestSize: number;
  responseSize: number;
  rawRequest: string;
  rawResponse: string;
  requestHash: string;
  responseHash: string;
  sourceTool: string;
  inScope: boolean;
}

export type ScopeFilter = 'ALL' | 'REQUESTS_ONLY' | 'RESPONSES_ONLY';

export type TimeRangeMode = 'ALL_TIME' | 'LAST_5_MIN' | 'LAST_15_MIN' | 'LAST_1_HOUR' | 'LAST_24_HOURS';

export type MimeCategory = 'ALL' | 'JSON' | 'HTML' | 'XML' | 'PLAIN_TEXT' | 'SCRIPTS' | 'BINARY_MEDIA';

export type StatusCategory = 'ALL' | '2XX' | '3XX' | '4XX' | '5XX' | 'AUTH_FAILURES' | 'CUSTOM';

export interface FilterState {
  searchTerm: string;
  searchRegex: boolean;
  searchCaseSensitive: boolean;
  searchInvert: boolean;
  searchScope: 'EVERYWHERE' | 'URL_PATH' | 'HEADERS' | 'REQ_BODY' | 'RESP_BODY' | 'METHOD' | 'STATUS';
  statusCategory: StatusCategory;
  customStatusRange: string;
  mimeCategory: MimeCategory;
  customMime: string;
  timeRange: TimeRangeMode;
  apiPath: string;
  authEndpointsOnly: boolean;
  selectedOnly: boolean;
  selectedDomains: Set<string>;
}

export interface ExportOptions {
  format: 'HTML' | 'MARKDOWN' | 'JSON' | 'CSV' | 'HAR' | 'RAW';
  redactSecrets: boolean;
  includeManifest: boolean;
  separateFiles: boolean;
}

export interface DiffResult {
  recordA: TrafficRecord;
  recordB: TrafficRecord;
  statusMatch: boolean;
  statusA: number;
  statusB: number;
  sizeDiff: number;
  headerDiffs: {
    name: string;
    type: 'ADDED' | 'REMOVED' | 'MODIFIED' | 'UNCHANGED';
    valueA?: string;
    valueB?: string;
    securityRelevant: boolean;
  }[];
  bodyDiffLines: {
    type: 'ADD' | 'REMOVE' | 'EQUAL';
    text: string;
  }[];
  securitySignals: string[];
}

# -*- coding: utf-8 -*-
"""
Burp Suite Extension: Selective HTTP Flow Exporter
Allows users to select multiple HTTP requests in Proxy HTTP History, Logger,
or Target Site Map and export them sequentially (Request + Response pairs)
in chronological order to a clean Markdown/Text or JSON report.
"""

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JFileChooser, JOptionPane
from java.util import ArrayList
from java.io import File, FileWriter, BufferedWriter
import json
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Selective Flow Exporter")
        callbacks.registerContextMenuFactory(self)
        
        print("[-] Selective Flow Exporter loaded successfully.")
        print("[-] Right-click any selected request(s) in HTTP History / Logger -> 'Export Selected Flow'")

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return None

        menu_list = ArrayList()

        # Menu 1: Formatted Flow Document (.txt / .md)
        item_md = JMenuItem("Export Selected Flow (Markdown / Text)", actionPerformed=lambda event: self.export_flow(messages, "markdown"))
        menu_list.add(item_md)

        # Menu 2: JSON Structure (.json)
        item_json = JMenuItem("Export Selected Flow (JSON)", actionPerformed=lambda event: self.export_flow(messages, "json"))
        menu_list.add(item_json)

        # Menu 3: Raw HTTP Pairs (.txt)
        item_raw = JMenuItem("Export Selected Flow (Raw HTTP Stream)", actionPerformed=lambda event: self.export_flow(messages, "raw"))
        menu_list.add(item_raw)

        return menu_list

    def export_flow(self, messages, export_format):
        # Choose target file
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Flow Export")
        
        if export_format == "json":
            chooser.setSelectedFile(File("http_flow_export.json"))
        elif export_format == "markdown":
            chooser.setSelectedFile(File("http_flow_export.md"))
        else:
            chooser.setSelectedFile(File("http_flow_raw.txt"))

        ret = chooser.showSaveDialog(None)
        if ret != JFileChooser.APPROVE_OPTION:
            return

        target_file = chooser.getSelectedFile()

        try:
            writer = BufferedWriter(FileWriter(target_file))
            
            if export_format == "json":
                data = []
                for idx, msg in enumerate(messages, start=1):
                    parsed = self._parse_message(msg, idx)
                    data.append(parsed)
                writer.write(json.dumps(data, indent=2))
            elif export_format == "markdown":
                writer.write("# HTTP Flow Export\n\n")
                writer.write("Total Flows: {}\n\n".format(len(messages)))
                for idx, msg in enumerate(messages, start=1):
                    parsed = self._parse_message(msg, idx)
                    writer.write(self._format_markdown(parsed))
            else: # raw
                for idx, msg in enumerate(messages, start=1):
                    parsed = self._parse_message(msg, idx)
                    writer.write(self._format_raw(parsed))

            writer.flush()
            writer.close()

            JOptionPane.showMessageDialog(None, "Successfully exported {} transactions to:\n{}".format(len(messages), target_file.getAbsolutePath()), "Export Completed", JOptionPane.INFORMATION_MESSAGE)

        except Exception as e:
            self._callbacks.printError("Export failed: " + str(e))
            JOptionPane.showMessageDialog(None, "Error exporting flow: " + str(e), "Export Error", JOptionPane.ERROR_MESSAGE)

    def _parse_message(self, message_info, index):
        req_bytes = message_info.getRequest()
        res_bytes = message_info.getResponse()

        http_service = message_info.getHttpService()
        protocol = http_service.getProtocol() if http_service else "http"
        host = http_service.getHost() if http_service else ""
        port = http_service.getPort() if http_service else 80

        # Parse Request
        req_data = {
            "method": "",
            "url": "",
            "headers": [],
            "body": ""
        }
        if req_bytes:
            req_info = self._helpers.analyzeRequest(message_info)
            req_data["method"] = req_info.getMethod()
            req_data["url"] = str(req_info.getUrl())
            req_data["headers"] = list(req_info.getHeaders())
            
            body_offset = req_info.getBodyOffset()
            req_body_bytes = req_bytes[body_offset:]
            req_data["body"] = self._helpers.bytesToString(req_body_bytes)

        # Parse Response
        res_data = {
            "status_code": 0,
            "headers": [],
            "body": ""
        }
        if res_bytes:
            res_info = self._helpers.analyzeResponse(res_bytes)
            res_data["status_code"] = res_info.getStatusCode()
            res_data["headers"] = list(res_info.getHeaders())
            
            res_offset = res_info.getBodyOffset()
            res_body_bytes = res_bytes[res_offset:]
            res_data["body"] = self._helpers.bytesToString(res_body_bytes)

        return {
            "step": index,
            "host": host,
            "port": port,
            "protocol": protocol,
            "request": req_data,
            "response": res_data
        }

    def _pretty_json(self, text):
        try:
            trimmed = text.strip()
            if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
                parsed = json.loads(trimmed)
                return json.dumps(parsed, indent=2)
        except:
            pass
        return text

    def _format_markdown(self, item):
        out = []
        step = item["step"]
        req = item["request"]
        res = item["response"]

        out.append("## Step {}: {} {}\n".format(step, req.get("method", ""), req.get("url", "")))
        out.append("**Target Host:** `{}:{} ({})`\n".format(item["host"], item["port"], item["protocol"]))
        
        # Request
        out.append("### Request\n")
        out.append("```http\n")
        out.append("\n".join(req.get("headers", [])))
        out.append("\n```\n")
        
        req_body = req.get("body", "")
        if req_body:
            out.append("**Request Body:**\n")
            pretty_req = self._pretty_json(req_body)
            lang = "json" if pretty_req != req_body else "text"
            out.append("```{}\n{}\n```\n".format(lang, pretty_req))
        else:
            out.append("_No request body_\n\n")

        # Response
        out.append("### Response (Status: {})\n".format(res.get("status_code", "N/A")))
        if res.get("headers"):
            out.append("```http\n")
            out.append("\n".join(res.get("headers", [])))
            out.append("\n```\n")
        
        res_body = res.get("body", "")
        if res_body:
            out.append("**Response Body:**\n")
            pretty_res = self._pretty_json(res_body)
            lang = "json" if pretty_res != res_body else "text"
            out.append("```{}\n{}\n```\n".format(lang, pretty_res))
        else:
            out.append("_No response body_\n\n")

        out.append("\n---\n\n")
        return "".join(out)

    def _format_raw(self, item):
        out = []
        step = item["step"]
        req = item["request"]
        res = item["response"]

        divider = "=" * 80
        out.append("{}\n# STEP {}: {} {}\n{}\n\n".format(divider, step, req.get("method", ""), req.get("url", ""), divider))
        
        # Request
        out.append("--- REQUEST ---\n")
        out.append("\n".join(req.get("headers", [])))
        out.append("\n\n")
        out.append(req.get("body", ""))
        out.append("\n\n")

        # Response
        out.append("--- RESPONSE (Status: {}) ---\n".format(res.get("status_code", "N/A")))
        out.append("\n".join(res.get("headers", [])))
        out.append("\n\n")
        out.append(res.get("body", ""))
        out.append("\n\n\n")

        return "".join(out)

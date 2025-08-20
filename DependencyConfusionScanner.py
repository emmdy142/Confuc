# DependencyConfusionScanner.py
#
# Advanced Burp Suite Extension for Dependency Confusion Testing
# Compatible with Jython (for Burp Suite Extender API)
# MIT License

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue
from burp import ITab
from java.awt import Component, BorderLayout
from javax.swing import JPanel, JTable, JScrollPane, JButton, JLabel, JTextArea, JCheckBox
from javax.swing.table import DefaultTableModel
import json
import re
import threading

# Import custom modules (bundled in Jython package)
from parsers import DependencyParsers
from registry import RegistryChecker
from config import ConfigManager

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Advanced Dependency Confusion Scanner")
        self._config = ConfigManager("confusion_config.json")

        # GUI Setup
        self._panel = JPanel(BorderLayout())
        self._table_model = DefaultTableModel(["Dependency", "File Type", "Source URL", "Risk Level"], 0)
        self._table = JTable(self._table_model)
        self._panel.add(JScrollPane(self._table), BorderLayout.CENTER)
        self._status_label = JLabel("Status: Monitoring HTTP traffic...")
        self._panel.add(self._status_label, BorderLayout.SOUTH)
        self._settings_area = JTextArea(str(self._config.config), 6, 80)
        self._settings_area.setEditable(False)
        self._panel.add(self._settings_area, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)

        # Set up scanning
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        self._findings = []
        self._lock = threading.Lock()

    # ITab methods
    def getTabCaption(self):
        return "Dependency Confusion"

    def getUiComponent(self):
        return self._panel

    # IHttpListener method
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._config.config.get("real_time_monitoring", True):
            return
        if messageIsRequest:
            return
        try:
            response = messageInfo.getResponse()
            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()
            mime_type = analyzed.getInferredMimeType()
            url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
            body_offset = analyzed.getBodyOffset()
            body_bytes = response[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            file_type = self._detect_file_type(headers, url, mime_type, body)
            if file_type:
                dependencies = DependencyParsers.parse(file_type, body)
                if dependencies:
                    for dep in dependencies:
                        finding = self._analyze_dependency(dep, file_type, url)
                        if finding:
                            self._add_finding(finding)
        except Exception as e:
            self._callbacks.printOutput("Error in processHttpMessage: %%s" %% str(e))

    # IScannerCheck method
    def doPassiveScan(self, baseRequestResponse):
        try:
            response = baseRequestResponse.getResponse()
            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()
            mime_type = analyzed.getInferredMimeType()
            url = str(self._helpers.analyzeRequest(baseRequestResponse).getUrl())
            body_offset = analyzed.getBodyOffset()
            body_bytes = response[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            file_type = self._detect_file_type(headers, url, mime_type, body)
            issues = []
            if file_type:
                dependencies = DependencyParsers.parse(file_type, body)
                for dep in dependencies:
                    finding = self._analyze_dependency(dep, file_type, url)
                    if finding:
                        issues.append(self._report_issue(baseRequestResponse, finding))
                        self._add_finding(finding)
            return issues if issues else None
        except Exception as e:
            self._callbacks.printOutput("Error in doPassiveScan: %%s" %% str(e))
        return None

    # Utility: file type detection
    def _detect_file_type(self, headers, url, mime_type, body):
        ext_map = self._config.config.get("file_types", {})
        for ext, ftype in ext_map.items():
            if url.endswith(ext):
                return ftype
        # Fallback: look for patterns
        if "package.json" in url or '"dependencies"' in body:
            return "package_json"
        if url.endswith(".js") or mime_type == "script":
            return "javascript"
        if url.endswith(".md"):
            return "markdown"
        if "require(" in body or "import " in body:
            return "javascript"
        for pattern, ftype in ext_map.items():
            if pattern in url:
                return ftype
        return None

    # Dependency analysis logic
    def _analyze_dependency(self, dep, file_type, url):
        registry = RegistryChecker(self._config)
        validation = registry.check(dep)
        risk = "High" if validation["confusable"] else "Low"
        return {
            "dependency": dep,
            "file_type": file_type,
            "source_url": url,
            "risk_level": risk,
            "details": validation
        }

    # Add finding to table, avoid duplicates
    def _add_finding(self, finding):
        with self._lock:
            if finding not in self._findings:
                self._findings.append(finding)
                self._table_model.addRow([
                    finding["dependency"],
                    finding["file_type"],
                    finding["source_url"],
                    finding["risk_level"
                ])

    # Report finding as Burp issue
    def _report_issue(self, baseRequestResponse, finding):
        class ScanIssue(IScanIssue):
            def __init__(self, finding, baseRequestResponse):
                self.finding = finding
                self.baseRequestResponse = baseRequestResponse
            def getUrl(self):
                return baseRequestResponse.getHttpService()
            def getIssueName(self):
                return "Potential Dependency Confusion: %%s" %% self.finding["dependency"]
            def getIssueType(self):
                return 0x08000000  # custom type
            def getSeverity(self):
                return self.finding["risk_level"]
            def getConfidence(self):
                return "Firm"
            def getIssueBackground(self):
                return "Dependency confusion occurs when private dependencies are referenced by public names. This issue highlights a potential risk."
            def getRemediationBackground(self):
                return "Consider using scoped/private registries, and verifying all dependencies are published/private."
            def getIssueDetail(self):
                return json.dumps(self.finding)
            def getHttpMessages(self):
                return [baseRequestResponse]
            def getHttpService(self):
                return baseRequestResponse.getHttpService()
        return ScanIssue(finding, baseRequestResponse)

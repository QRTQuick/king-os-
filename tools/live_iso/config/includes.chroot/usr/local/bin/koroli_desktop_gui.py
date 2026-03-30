#!/usr/bin/env python3
"""KOROLI Desktop Scanner GUI

Windows XP/Vista-inspired network-enabled scanner UI.
- Responsive threading (UI never blocks)
- Website/API checks
- DNS/TLS/HTTP metadata
- Basic safety heuristics
"""

from __future__ import annotations

import concurrent.futures
import json
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import tkinter as tk
from tkinter import ttk


@dataclass
class ScanResult:
    ok: bool
    lines: list[str]


class KoroliScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("KOROLI Secure Desktop - XP/Vista Style")
        self.root.geometry("1120x720")
        self.root.minsize(920, 600)
        self.root.configure(bg="#355C99")

        self.msg_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.worker: threading.Thread | None = None

        self._init_style()
        self._build_shell()
        self._poll_queue()

    def _init_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("Vista.TFrame", background="#E9EEF7")
        style.configure("Panel.TLabelframe", background="#EEF3FB", foreground="#1A2C4A")
        style.configure("Panel.TLabelframe.Label", background="#EEF3FB", foreground="#1A2C4A")
        style.configure("WinTitle.TLabel", background="#1D5DAA", foreground="white", font=("Segoe UI", 11, "bold"))
        style.configure("Section.TLabel", background="#EEF3FB", foreground="#2E4A77", font=("Segoe UI", 10, "bold"))
        style.configure("Body.TLabel", background="#EEF3FB", foreground="#1E2A3F", font=("Segoe UI", 9))

        style.configure("Action.TButton", font=("Segoe UI", 9, "bold"), padding=(10, 6))
        style.map("Action.TButton", background=[("active", "#F0F6FF")])

        style.configure("Status.TLabel", background="#CED8EA", foreground="#20395F", font=("Segoe UI", 9))

    def _build_shell(self) -> None:
        # Faux desktop gradient bars
        top_bar = tk.Frame(self.root, bg="#2D63B7", height=32)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)
        tk.Label(top_bar, text="KOROLI Desktop", bg="#2D63B7", fg="white", font=("Segoe UI", 10, "bold")).pack(
            side="left", padx=12
        )

        container = ttk.Frame(self.root, style="Vista.TFrame", padding=10)
        container.pack(fill="both", expand=True)

        window = tk.Frame(container, bg="#A6B7D4", bd=1, relief="solid")
        window.pack(fill="both", expand=True)

        title = ttk.Label(window, style="WinTitle.TLabel", text="  KOROLI NETWORK SCANNER")
        title.pack(fill="x")

        body = ttk.Frame(window, style="Vista.TFrame", padding=10)
        body.pack(fill="both", expand=True)

        # Top controls
        controls = ttk.LabelFrame(body, text="Scanner Controls", style="Panel.TLabelframe", padding=10)
        controls.pack(fill="x", pady=(0, 10))

        ttk.Label(controls, text="Mode", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.mode_var = tk.StringVar(value="Website")
        self.mode_combo = ttk.Combobox(
            controls,
            textvariable=self.mode_var,
            values=["Website", "API"],
            state="readonly",
            width=14,
        )
        self.mode_combo.grid(row=0, column=1, sticky="w", padx=(0, 16))

        ttk.Label(controls, text="Target URL", style="Section.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.url_var = tk.StringVar(value="https://example.com")
        self.url_entry = ttk.Entry(controls, textvariable=self.url_var, width=68)
        self.url_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        self.scan_btn = ttk.Button(controls, text="Scan", style="Action.TButton", command=self.start_scan)
        self.scan_btn.grid(row=0, column=4, sticky="e")

        self.clear_btn = ttk.Button(controls, text="Clear", style="Action.TButton", command=self.clear_output)
        self.clear_btn.grid(row=0, column=5, sticky="e", padx=(8, 0))

        controls.columnconfigure(3, weight=1)

        self.progress = ttk.Progressbar(controls, mode="indeterminate")
        self.progress.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(10, 0))

        # Main split
        split = tk.PanedWindow(body, orient="horizontal", sashrelief="ridge", sashwidth=6, bd=0, bg="#D5DFEF")
        split.pack(fill="both", expand=True)

        left = ttk.LabelFrame(split, text="Scan Output", style="Panel.TLabelframe", padding=8)
        right = ttk.LabelFrame(split, text="Risk Summary", style="Panel.TLabelframe", padding=8)
        split.add(left, minsize=560)
        split.add(right, minsize=260)

        self.output = tk.Text(
            left,
            wrap="word",
            bg="#F8FBFF",
            fg="#20314B",
            insertbackground="#20314B",
            relief="sunken",
            bd=1,
            font=("Consolas", 10),
        )
        self.output.pack(fill="both", expand=True)

        self.summary = tk.Text(
            right,
            wrap="word",
            bg="#FFFFFF",
            fg="#22304B",
            relief="sunken",
            bd=1,
            font=("Segoe UI", 10),
            width=36,
        )
        self.summary.pack(fill="both", expand=True)

        # Taskbar-like status
        status_bar = ttk.Label(self.root, style="Status.TLabel", anchor="w")
        status_bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready")
        status_bar.configure(textvariable=self.status_var, padding=(10, 5))

        self.write_output("KOROLI Desktop ready. Enter a URL and click Scan.\n")

    def write_output(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")

    def set_summary(self, lines: list[str]) -> None:
        self.summary.delete("1.0", "end")
        self.summary.insert("end", "\n".join(lines) + "\n")

    def clear_output(self) -> None:
        self.output.delete("1.0", "end")
        self.summary.delete("1.0", "end")
        self.status_var.set("Cleared")

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            self.status_var.set("Scan already in progress")
            return

        url = self.url_var.get().strip()
        mode = self.mode_var.get().strip()
        if not url:
            self.status_var.set("Enter a URL first")
            return

        self.status_var.set("Scanning...")
        self.scan_btn.configure(state="disabled")
        self.progress.start(10)
        self.write_output(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting {mode} scan for: {url}\n")

        self.worker = threading.Thread(target=self._scan_worker, args=(url, mode), daemon=True)
        self.worker.start()

    def _scan_worker(self, target: str, mode: str) -> None:
        try:
            result = self.scan_target(target, mode)
            self.msg_queue.put(("scan_done", result))
        except Exception as exc:  # defensive catch for UI thread safety
            self.msg_queue.put(("scan_error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "scan_done":
                    self._handle_scan_done(payload)
                elif kind == "scan_error":
                    self._handle_scan_error(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _handle_scan_done(self, result: ScanResult) -> None:
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        self.status_var.set("Scan finished" if result.ok else "Scan completed with warnings")
        self.write_output("\n" + "\n".join(result.lines) + "\n")

        summary_lines = [line for line in result.lines if line.startswith("[RISK]") or line.startswith("[VERDICT]")]
        if not summary_lines:
            summary_lines = ["[VERDICT] No summary available"]
        self.set_summary(summary_lines)

    def _handle_scan_error(self, error_text: str) -> None:
        self.progress.stop()
        self.scan_btn.configure(state="normal")
        self.status_var.set("Scan failed")
        self.write_output(f"\n[ERROR] {error_text}\n")
        self.set_summary(["[VERDICT] Scan failed", f"[ERROR] {error_text}"])

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return "https://" + url
        return url

    @staticmethod
    def _dns_check(host: str) -> tuple[list[str], int]:
        lines: list[str] = []
        risk = 0
        if not host:
            return ["[DNS] Missing host"], 20
        try:
            addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
            lines.append(f"[DNS] Resolved: {', '.join(addrs[:4])}")
        except Exception as exc:
            lines.append(f"[DNS] Resolution failed: {exc}")
            risk += 15
        return lines, risk

    @staticmethod
    def _http_check(url: str) -> tuple[list[str], int, int | None, str, str]:
        lines: list[str] = []
        risk = 0
        status_code: int | None = None
        content_type = ""
        body_preview = ""

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "KoroliDesktopScanner/1.0",
                "Accept": "application/json,text/html,*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status_code = resp.getcode()
                content_type = resp.headers.get("Content-Type", "")
                server_hdr = resp.headers.get("Server", "")
                raw = resp.read(1200)
                body_preview = raw.decode("utf-8", errors="replace")

            lines.append(f"[HTTP] Status: {status_code}")
            if server_hdr:
                lines.append(f"[HTTP] Server: {server_hdr}")
            if content_type:
                lines.append(f"[HTTP] Content-Type: {content_type}")
            if status_code and status_code >= 400:
                risk += 15
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            lines.append(f"[HTTP] Error status: {exc.code}")
            risk += 20
        except Exception as exc:
            lines.append(f"[HTTP] Request failed: {exc}")
            risk += 25

        return lines, risk, status_code, content_type, body_preview

    @staticmethod
    def _tls_check(parsed: urllib.parse.ParseResult, host: str) -> tuple[list[str], int]:
        lines: list[str] = []
        risk = 0
        if parsed.scheme != "https" or not host:
            return lines, risk
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()

            lines.append(f"[TLS] Protocol: {proto}")
            if cipher:
                lines.append(f"[TLS] Cipher: {cipher[0]}")
            if cert:
                not_after = cert.get("notAfter", "")
                subject = cert.get("subject", "")
                lines.append(f"[TLS] Cert expires: {not_after}")
                lines.append(f"[TLS] Subject: {subject}")
        except Exception as exc:
            lines.append(f"[TLS] Failed to inspect certificate: {exc}")
            risk += 10
        return lines, risk

    def scan_target(self, raw_url: str, mode: str) -> ScanResult:
        lines: list[str] = []
        risk = 0

        url = self._normalize_url(raw_url)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""

        lines.append(f"[TARGET] {url}")
        lines.append(f"[MODE] {mode}")

        if url.startswith("https://"):
            lines.append("[CHECK] HTTPS in use")
        else:
            lines.append("[CHECK] HTTP only (unencrypted)")
            risk += 30

        if "@" in url:
            lines.append("[CHECK] '@' present in URL")
            risk += 20

        if len(url) > 130:
            lines.append("[CHECK] Very long URL")
            risk += 10

        if any(k in url.lower() for k in ["login", "verify", "wallet", "reset-password"]):
            lines.append("[CHECK] Social-engineering keyword pattern")
            risk += 12

        if any(url.lower().endswith(tld) for tld in [".zip", ".click", ".top"]):
            lines.append("[CHECK] Suspicious TLD")
            risk += 12

        content_type = ""
        body_preview = ""
        with concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="koroli-scan") as pool:
            fut_dns = pool.submit(self._dns_check, host)
            fut_http = pool.submit(self._http_check, url)
            fut_tls = pool.submit(self._tls_check, parsed, host)

            dns_lines, dns_risk = fut_dns.result()
            http_lines, http_risk, _status_code, content_type, body_preview = fut_http.result()
            tls_lines, tls_risk = fut_tls.result()

        lines.extend(dns_lines)
        lines.extend(http_lines)
        lines.extend(tls_lines)
        risk += dns_risk + http_risk + tls_risk

        # API mode checks
        if mode.lower() == "api":
            if any(k in parsed.path.lower() for k in ["/api", "/v1", "/v2"]):
                lines.append("[API] Version/path markers found")
            else:
                lines.append("[API] Version/path markers not found")
                risk += 5

            q = urllib.parse.parse_qs(parsed.query)
            if any(k.lower() in {"token", "apikey", "key"} for k in q):
                lines.append("[API] Sensitive token-like query parameter found")
                risk += 15

            if content_type.lower().startswith("application/json") and body_preview:
                try:
                    data = json.loads(body_preview)
                    if isinstance(data, dict):
                        lines.append(f"[API] JSON keys sample: {', '.join(list(data.keys())[:8])}")
                    elif isinstance(data, list):
                        lines.append(f"[API] JSON array length preview: {len(data)}")
                except json.JSONDecodeError:
                    lines.append("[API] Response is not valid JSON")
                    risk += 5

        risk = max(0, min(100, risk))
        verdict = "LOW RISK"
        if risk >= 50:
            verdict = "HIGH RISK"
        elif risk >= 20:
            verdict = "MEDIUM RISK"

        lines.append(f"[RISK] {risk}/100")
        lines.append(f"[VERDICT] {verdict}")
        lines.append(f"[TIME] Completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        return ScanResult(ok=True, lines=lines)


def main() -> None:
    root = tk.Tk()
    app = KoroliScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

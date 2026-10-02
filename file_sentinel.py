"""Desktop interface for the HashHarbor integrity monitor."""

from __future__ import annotations

from collections.abc import Callable
import csv
from datetime import datetime
import os
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import cast

from filesentinel_core import ActivityLog, FileRecord, RansomwareDetector, changed_files, create_baseline, restore_baseline, scan_directory


class HashHarborApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("HashHarbor | File Integrity Monitor")
        self.geometry("900x680")
        self.minsize(680, 520)

        self.protected_path = tk.StringVar()
        self.vault_path = tk.StringVar()
        self.status_text = tk.StringVar(value="Choose a folder and create a trusted recovery baseline.")
        self.results: queue.Queue[tuple[str, object, Exception | None]] = queue.Queue()
        self.busy = False
        self.monitoring = False
        self.alerted = False
        self.root_folder: Path | None = None
        self.baseline_folder: Path | None = None
        self.previous_scan = {}
        self.detector = RansomwareDetector()
        local_app_data = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        self.activity_log = ActivityLog(local_app_data / "HashHarbor" / "activity.jsonl")
        try:
            self.audit_records = self.activity_log.read()
        except OSError:
            self.audit_records = []
        self.activity_filter = tk.StringVar()
        self.event_count = tk.StringVar()
        self.change_count = tk.StringVar()
        self.alert_count = tk.StringVar()

        self._build_interface()
        self._audit("APP_OPENED", details="HashHarbor started")
        self.after(150, self._collect_results)

    def _build_interface(self) -> None:
        container = ttk.Frame(self, padding=20)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="HASHHARBOR", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            container,
            text="File integrity monitoring with a separate recovery baseline",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(2, 18))

        tabs = ttk.Notebook(container)
        tabs.pack(fill="both", expand=True)
        monitor_tab = ttk.Frame(tabs, padding=(0, 0, 0, 8))
        admin_tab = ttk.Frame(tabs, padding=(14, 12))
        tabs.add(monitor_tab, text="Monitor")
        tabs.add(admin_tab, text="Admin")

        paths = ttk.LabelFrame(monitor_tab, text=" Folders ", padding=12)
        paths.pack(fill="x")
        self._path_row(paths, "Folder to protect", self.protected_path, self._choose_protected)
        self._path_row(paths, "Recovery vault", self.vault_path, self._choose_vault)

        controls = ttk.Frame(monitor_tab, padding=(0, 14, 0, 10))
        controls.pack(fill="x")
        self.baseline_button = ttk.Button(controls, text="Create trusted baseline", command=self._create_baseline)
        self.baseline_button.pack(side="left")
        self.start_button = ttk.Button(controls, text="Start monitoring", command=self._start_monitoring, state="disabled")
        self.start_button.pack(side="left", padx=(8, 0))
        self.stop_button = ttk.Button(controls, text="Stop", command=self._stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.restore_button = ttk.Button(controls, text="Restore baseline", command=self._restore, state="disabled")
        self.restore_button.pack(side="right")

        status = ttk.Frame(monitor_tab)
        status.pack(fill="x", pady=(0, 10))
        ttk.Label(status, text="STATUS", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(status, textvariable=self.status_text, wraplength=710).pack(side="left", padx=(10, 0))

        log_frame = ttk.LabelFrame(monitor_tab, text=" Activity ", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.log = ScrolledText(log_frame, height=14, wrap="word", state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)
        self._log("Ready. Choose a recovery vault outside the folder being monitored.")

        ttk.Label(
            monitor_tab,
            text="Burst detection is heuristic and does not stop ransomware. Keep the vault on a separate drive for stronger recovery.",
            wraplength=850,
        ).pack(anchor="w", pady=(10, 0))

        self._build_admin_tab(admin_tab)

    def _build_admin_tab(self, parent: ttk.Frame) -> None:
        heading = ttk.Frame(parent)
        heading.pack(fill="x", pady=(0, 12))
        title_group = ttk.Frame(heading)
        title_group.pack(side="left", fill="x", expand=True)
        ttk.Label(title_group, text="Activity audit", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(
            title_group,
            text="Persistent record of file activity detected by HashHarbor. Network traffic is not monitored.",
            wraplength=600,
        ).pack(anchor="w", pady=(2, 0))
        ttk.Button(heading, text="Export CSV", command=self._export_activity).pack(side="right", padx=(8, 0))

        summary = ttk.Frame(parent)
        summary.pack(fill="x", pady=(0, 12))
        for index, (label, value) in enumerate(
            (("ALL EVENTS", self.event_count), ("FILE CHANGES", self.change_count), ("BURST ALERTS", self.alert_count))
        ):
            summary.columnconfigure(index, weight=1)
            metric = ttk.LabelFrame(summary, text=label, padding=(10, 6))
            metric.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 8, 0))
            ttk.Label(metric, textvariable=value, font=("Segoe UI", 17, "bold")).pack(anchor="w")

        filter_row = ttk.Frame(parent)
        filter_row.pack(fill="x", pady=(0, 8))
        ttk.Label(filter_row, text="Filter activity").pack(side="left", padx=(0, 8))
        filter_entry = ttk.Entry(filter_row, textvariable=self.activity_filter)
        filter_entry.pack(side="left", fill="x", expand=True)
        self.activity_filter.trace_add("write", lambda *_: self._refresh_admin())

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True)
        columns = ("timestamp", "event", "path", "details")
        self.activity_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        self.activity_table.heading("timestamp", text="TIME")
        self.activity_table.heading("event", text="EVENT")
        self.activity_table.heading("path", text="FILE / FOLDER")
        self.activity_table.heading("details", text="DETAILS")
        self.activity_table.column("timestamp", width=155, minwidth=135, stretch=False)
        self.activity_table.column("event", width=130, minwidth=100, stretch=False)
        self.activity_table.column("path", width=260, minwidth=150)
        self.activity_table.column("details", width=300, minwidth=170)
        self.activity_table.tag_configure("alert", foreground="#a62d25")
        self.activity_table.grid(row=0, column=0, sticky="nsew")
        vertical_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.activity_table.yview)
        vertical_scroll.grid(row=0, column=1, sticky="ns")
        horizontal_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.activity_table.xview)
        horizontal_scroll.grid(row=1, column=0, sticky="ew")
        self.activity_table.configure(yscrollcommand=vertical_scroll.set, xscrollcommand=horizontal_scroll.set)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self._refresh_admin()

    def _filtered_activity(self) -> list[dict[str, str]]:
        query = self.activity_filter.get().strip().casefold()
        if not query:
            return list(self.audit_records)
        return [
            record
            for record in self.audit_records
            if query in " ".join(record.values()).casefold()
        ]

    def _refresh_admin(self) -> None:
        if not hasattr(self, "activity_table"):
            return
        changes = {"NEW", "CHANGED", "DELETED"}
        self.event_count.set(str(len(self.audit_records)))
        self.change_count.set(str(sum(record["event"] in changes for record in self.audit_records)))
        self.alert_count.set(str(sum(record["event"] == "BURST_ALERT" for record in self.audit_records)))
        self.activity_table.delete(*self.activity_table.get_children())
        for record in reversed(self._filtered_activity()):
            tags = ("alert",) if record["event"] == "BURST_ALERT" else ()
            self.activity_table.insert(
                "",
                "end",
                values=(record["timestamp"].replace("T", " "), record["event"], record["path"], record["details"]),
                tags=tags,
            )

    def _export_activity(self) -> None:
        destination = filedialog.asksaveasfilename(
            title="Export activity audit",
            defaultextension=".csv",
            initialfile=f"hashharbor-activity-{datetime.now():%Y%m%d-%H%M%S}.csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not destination:
            return
        try:
            with Path(destination).open("w", newline="", encoding="utf-8-sig") as file:
                writer = csv.DictWriter(file, fieldnames=("timestamp", "event", "path", "details"))
                writer.writeheader()
                writer.writerows(self._filtered_activity())
        except OSError as error:
            messagebox.showerror("HashHarbor", f"Could not export the activity log: {error}")
            return
        self._log(f"Exported {len(self._filtered_activity())} audit events to {destination}.")

    def _audit(self, event: str, path: str = "", details: str = "") -> None:
        try:
            record = self.activity_log.record(event, path, details)
        except OSError as error:
            self._log(f"AUDIT WRITE FAILED: {error}")
            return
        self.audit_records.append(record)
        self._refresh_admin()

    @staticmethod
    def _path_row(parent: ttk.LabelFrame, label: str, value: tk.StringVar, browse: Callable[[], None]) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=18).pack(side="left")
        ttk.Entry(row, textvariable=value).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse...", command=browse).pack(side="right")

    def _choose_protected(self) -> None:
        chosen = filedialog.askdirectory(title="Choose the folder to protect")
        if chosen:
            self.protected_path.set(chosen)

    def _choose_vault(self) -> None:
        chosen = filedialog.askdirectory(title="Choose a separate recovery vault")
        if chosen:
            self.vault_path.set(chosen)

    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _run_task(self, label: str, operation: Callable[[], object]) -> None:
        self.busy = True

        def run() -> None:
            try:
                self.results.put((label, operation(), None))
            except Exception as error:
                self.results.put((label, None, error))

        threading.Thread(target=run, daemon=True).start()

    def _create_baseline(self) -> None:
        if self.busy:
            return
        if not self.protected_path.get().strip() or not self.vault_path.get().strip():
            messagebox.showwarning("Choose folders", "Select both the folder to protect and a separate recovery vault.")
            return

        root = Path(self.protected_path.get().strip())
        vault = Path(self.vault_path.get().strip())
        self.status_text.set("Creating verified baseline copies. Large folders may take a while...")
        self._log("Creating trusted baseline...")
        self._run_task("baseline", lambda: self._make_baseline(root, vault))

    @staticmethod
    def _make_baseline(root: Path, vault: Path) -> tuple[Path, Path, dict[str, FileRecord]]:
        resolved_root = root.resolve(strict=True)
        baseline = create_baseline(resolved_root, vault)
        return resolved_root, baseline, scan_directory(resolved_root)

    def _start_monitoring(self) -> None:
        if self.root_folder is None or self.baseline_folder is None:
            return
        self.monitoring = True
        self.alerted = False
        self.detector = RansomwareDetector()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_text.set("Monitoring for file changes...")
        self._log("Monitoring started. Scans run every 2 seconds.")
        self._audit("MONITORING_STARTED", str(self.root_folder), "Folder monitoring started")
        self._monitor_tick()

    def _stop_monitoring(self) -> None:
        self.monitoring = False
        self.start_button.configure(state="normal" if self.baseline_folder else "disabled")
        self.stop_button.configure(state="disabled")
        self.status_text.set("Monitoring stopped.")
        self._log("Monitoring stopped.")
        self._audit("MONITORING_STOPPED", str(self.root_folder or ""), "Folder monitoring stopped")

    def _monitor_tick(self) -> None:
        if not self.monitoring or self.busy or self.root_folder is None:
            return
        root = self.root_folder
        self._run_task("scan", lambda: scan_directory(root))

    def _restore(self) -> None:
        if self.busy or self.root_folder is None or self.baseline_folder is None:
            return
        if not messagebox.askyesno(
            "Restore trusted baseline?",
            "This overwrites files that were present when the baseline was created. New files are left in place. Continue?",
            icon="warning",
        ):
            return
        self.monitoring = False
        self.stop_button.configure(state="disabled")
        self.status_text.set("Verifying recovery copies and restoring files...")
        root, baseline = self.root_folder, self.baseline_folder
        self._audit("RESTORE_STARTED", str(root), f"Baseline: {baseline}")
        self._run_task("restore", lambda: (restore_baseline(root, baseline), scan_directory(root)))

    def _collect_results(self) -> None:
        try:
            while True:
                label, value, error = self.results.get_nowait()
                self.busy = False
                if error is not None:
                    self.status_text.set(f"{label.capitalize()} failed.")
                    self._log(f"ERROR: {error}")
                    self._audit("ERROR", str(self.root_folder or ""), f"{label}: {error}")
                    messagebox.showerror("HashHarbor", str(error))
                    if label == "scan":
                        self.monitoring = False
                        self.start_button.configure(state="normal")
                        self.stop_button.configure(state="disabled")
                    continue

                if label == "baseline":
                    self.root_folder, self.baseline_folder, self.previous_scan = cast(
                        tuple[Path, Path, dict[str, FileRecord]], value
                    )
                    self.start_button.configure(state="normal")
                    self.restore_button.configure(state="normal")
                    self.status_text.set(f"Baseline ready: {len(self.previous_scan)} files protected.")
                    self._log(f"Baseline created at {self.baseline_folder} ({len(self.previous_scan)} files).")
                    self._audit(
                        "BASELINE_CREATED",
                        str(self.root_folder),
                        f"{len(self.previous_scan)} files; recovery copy at {self.baseline_folder}",
                    )
                elif label == "scan":
                    current = cast(dict[str, FileRecord], value)
                    changes = changed_files(self.previous_scan, current)
                    self.previous_scan = current
                    if changes:
                        now = time.monotonic()
                        suspicious = self.detector.add(changes, now)
                        for kind, relative in changes:
                            self._log(f"{kind}: {relative}")
                            self._audit(kind, str(self.root_folder / relative), "Detected during folder scan")
                        if suspicious and not self.alerted:
                            self.alerted = True
                            self.status_text.set("WARNING: unusually large burst of file changes detected.")
                            self._audit(
                                "BURST_ALERT",
                                str(self.root_folder),
                                f"At least {self.detector.threshold} changes within {self.detector.window_seconds:g} seconds",
                            )
                            messagebox.showwarning(
                                "Possible ransomware activity",
                                "A burst of file changes was detected. HashHarbor cannot stop the process. Disconnect the computer from networks or synced drives, then investigate before restoring.",
                            )
                    if self.monitoring:
                        self.after(2000, self._monitor_tick)
                elif label == "restore":
                    restored, snapshot = cast(tuple[int, dict[str, FileRecord]], value)
                    self.status_text.set(f"Restored {restored} baseline files.")
                    self._log(f"Restored {restored} files from the verified baseline.")
                    self.previous_scan = snapshot
                    self.start_button.configure(state="normal")
                    self._audit("RESTORE_COMPLETED", str(self.root_folder or ""), f"Restored {restored} files")
        except queue.Empty:
            pass
        self.after(150, self._collect_results)


if __name__ == "__main__":
    HashHarborApp().mainloop()
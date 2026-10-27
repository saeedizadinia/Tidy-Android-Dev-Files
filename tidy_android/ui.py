from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .deletion import DeletionResult, DeletionService
from .discovery import WindowsPathDiscovery
from .formatting import format_bytes
from .models import Category, CleanupCandidate, RiskLevel, ScanPolicy, ScanRoot
from .scanner import ScanCancelled, Scanner


class CleanupApp(tk.Tk):
    POLL_INTERVAL_MS = 100

    def __init__(self) -> None:
        super().__init__()
        self.title("Tidy Android Development Files")
        self.geometry("1280x760")
        self.minsize(980, 620)

        self.discovery = WindowsPathDiscovery()
        self.scanner: Scanner | None = None
        self.scan_cancel_event = threading.Event()
        self.messages: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.candidates: list[CleanupCandidate] = []
        self.visible_candidates: list[CleanupCandidate] = []
        self.custom_roots: list[Path] = []
        self.last_scan_roots: tuple[ScanRoot, ...] = ()
        self.sort_column = "risk"
        self.sort_reverse = False
        self.busy = False

        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="All categories")
        self.risk_var = tk.StringVar(value="All risks")
        self.stale_days_var = tk.StringVar(value="90")
        self.include_high_risk_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready. No files are selected.")
        self.selection_var = tk.StringVar(value="0 selected · 0 B")
        self.roots_var = tk.StringVar(value="No custom roots")
        self.details_var = tk.StringVar(
            value="Select a result to inspect its reason and timestamps."
        )

        self._build_ui()
        self._bind_events()
        self.after(self.POLL_INTERVAL_MS, self._poll_messages)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        controls = ttk.Frame(self, padding=(12, 12, 12, 8))
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)

        ttk.Label(controls, text="Search").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.search_var).grid(
            row=0, column=1, sticky="ew", padx=(6, 12)
        )
        ttk.Label(controls, text="Category").grid(row=0, column=2, sticky="w")
        self.category_combo = ttk.Combobox(
            controls,
            textvariable=self.category_var,
            values=("All categories", *(category.value for category in Category)),
            state="readonly",
            width=20,
        )
        self.category_combo.grid(row=0, column=3, padx=(6, 12))
        ttk.Label(controls, text="Risk").grid(row=0, column=4, sticky="w")
        self.risk_combo = ttk.Combobox(
            controls,
            textvariable=self.risk_var,
            values=("All risks", *(risk.value for risk in RiskLevel)),
            state="readonly",
            width=12,
        )
        self.risk_combo.grid(row=0, column=5, padx=(6, 0))

        ttk.Label(controls, text="Stale after").grid(row=1, column=0, sticky="w", pady=(10, 0))
        stale_frame = ttk.Frame(controls)
        stale_frame.grid(row=1, column=1, sticky="w", pady=(10, 0))
        ttk.Spinbox(
            stale_frame,
            from_=1,
            to=3650,
            width=7,
            textvariable=self.stale_days_var,
        ).pack(side="left")
        ttk.Label(stale_frame, text="days").pack(side="left", padx=(5, 14))
        ttk.Checkbutton(
            stale_frame,
            text="Show high-risk SDK, AVD, and configuration items",
            variable=self.include_high_risk_var,
        ).pack(side="left")

        roots_frame = ttk.Frame(controls)
        roots_frame.grid(row=1, column=2, columnspan=4, sticky="e", pady=(10, 0))
        ttk.Label(roots_frame, textvariable=self.roots_var).pack(side="left", padx=(0, 8))
        ttk.Button(roots_frame, text="Add root…", command=self._add_root).pack(side="left")
        ttk.Button(roots_frame, text="Clear roots", command=self._clear_roots).pack(
            side="left", padx=(6, 0)
        )

        table_frame = ttk.Frame(self, padding=(12, 0))
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("path", "category", "reason", "size", "age", "risk")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
        headings = {
            "path": "Path",
            "category": "Category",
            "reason": "Reason",
            "size": "Size",
            "age": "Age",
            "risk": "Risk",
        }
        widths = {
            "path": 410,
            "category": 135,
            "reason": 300,
            "size": 90,
            "age": 90,
            "risk": 80,
        }
        for column in columns:
            self.tree.heading(
                column,
                text=headings[column],
                command=lambda selected_column=column: self._sort_by(selected_column),
            )
            self.tree.column(
                column,
                width=widths[column],
                minwidth=45,
                stretch=column in {"path", "reason"},
                anchor="center" if column in {"size", "age", "risk"} else "w",
            )
        self.tree.tag_configure("high", foreground="#b42318")
        self.tree.tag_configure("medium", foreground="#9a6700")

        vertical = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        details = ttk.LabelFrame(self, text="Candidate details", padding=8)
        details.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 0))
        ttk.Label(
            details,
            textvariable=self.details_var,
            justify="left",
            wraplength=1200,
        ).pack(anchor="w")

        actions = ttk.Frame(self, padding=12)
        actions.grid(row=3, column=0, sticky="ew")
        actions.columnconfigure(8, weight=1)

        self.scan_button = ttk.Button(actions, text="Scan", command=self._start_scan)
        self.scan_button.grid(row=0, column=0)
        self.cancel_button = ttk.Button(
            actions, text="Cancel", command=self._cancel_scan, state="disabled"
        )
        self.cancel_button.grid(row=0, column=1, padx=(6, 12))
        ttk.Button(actions, text="Select safe", command=self._select_safe).grid(row=0, column=2)
        ttk.Button(actions, text="Clear selection", command=self._clear_selection).grid(
            row=0, column=3, padx=(6, 12)
        )
        ttk.Button(actions, text="Reveal", command=self._reveal_selected).grid(row=0, column=4)
        self.delete_button = ttk.Button(
            actions,
            text="Delete selected…",
            command=self._request_deletion,
            state="disabled",
        )
        self.delete_button.grid(row=0, column=5, padx=(6, 12))
        ttk.Label(actions, textvariable=self.selection_var).grid(
            row=0, column=6, padx=(0, 12)
        )
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=150)
        self.progress.grid(row=0, column=7)
        ttk.Label(actions, textvariable=self.status_var).grid(
            row=0, column=8, sticky="e", padx=(12, 0)
        )

    def _bind_events(self) -> None:
        self.search_var.trace_add("write", lambda *_args: self._refresh_table())
        self.category_var.trace_add("write", lambda *_args: self._refresh_table())
        self.risk_var.trace_add("write", lambda *_args: self._refresh_table())
        self.tree.bind("<<TreeviewSelect>>", self._on_selection_changed)

    def _start_scan(self) -> None:
        try:
            stale_days = int(self.stale_days_var.get())
            if stale_days < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid threshold", "Stale days must be a positive whole number.")
            return
        if self.busy:
            return

        self.busy = True
        self.candidates.clear()
        self.tree.selection_remove(self.tree.selection())
        self._refresh_table()
        self.scan_cancel_event = threading.Event()
        self.scanner = Scanner()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.delete_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Discovering Android development folders…")
        custom_roots = tuple(self.custom_roots)
        include_high_risk = self.include_high_risk_var.get()

        thread = threading.Thread(
            target=self._scan_worker,
            args=(stale_days, custom_roots, include_high_risk),
            daemon=True,
            name="android-cleanup-scan",
        )
        thread.start()

    def _scan_worker(
        self,
        stale_days: int,
        custom_roots: tuple[Path, ...],
        include_high_risk: bool,
    ) -> None:
        assert self.scanner is not None
        try:
            roots = self.discovery.discover(custom_roots)
            policy = ScanPolicy(
                stale_days=stale_days,
                roots=roots,
                include_high_risk=include_high_risk,
            )
            candidates = self.scanner.scan(
                policy,
                progress=lambda message: self.messages.put(("progress", message)),
                cancel_event=self.scan_cancel_event,
            )
        except ScanCancelled:
            self.messages.put(("scan_cancelled",))
        except Exception as error:  # keep worker failures visible in the GUI
            self.messages.put(("scan_failed", str(error)))
        else:
            self.messages.put(
                ("scan_complete", candidates, roots, tuple(self.scanner.last_errors))
            )

    def _cancel_scan(self) -> None:
        if self.busy:
            self.scan_cancel_event.set()
            self.status_var.set("Cancelling scan…")

    def _finish_busy_state(self) -> None:
        self.busy = False
        self.progress.stop()
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self._update_delete_button()

    def _poll_messages(self) -> None:
        try:
            while True:
                message = self.messages.get_nowait()
                kind = message[0]
                if kind == "progress":
                    self.status_var.set(str(message[1]))
                elif kind == "scan_complete":
                    self.candidates = list(message[1])
                    self.last_scan_roots = tuple(message[2])
                    errors = tuple(message[3])
                    self._finish_busy_state()
                    self._refresh_table()
                    suffix = f" ({len(errors)} paths could not be read)" if errors else ""
                    self.status_var.set(f"Found {len(self.candidates)} candidates{suffix}")
                    if errors:
                        self.details_var.set(
                            "Some paths could not be read. The scan continued safely. "
                            + " | ".join(errors[:3])
                        )
                elif kind == "scan_cancelled":
                    self._finish_busy_state()
                    self.status_var.set("Scan cancelled. Nothing was deleted.")
                elif kind == "scan_failed":
                    self._finish_busy_state()
                    self.status_var.set("Scan failed. Nothing was deleted.")
                    messagebox.showerror("Scan failed", str(message[1]))
                elif kind == "delete_complete":
                    self._handle_deletion_results(list(message[1]))
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(self.POLL_INTERVAL_MS, self._poll_messages)

    def _refresh_table(self) -> None:
        if not hasattr(self, "tree"):
            return
        selected_keys = {
            self._path_key(candidate.path) for candidate in self._selected_candidates()
        }
        search = self.search_var.get().strip().casefold()
        category = self.category_var.get()
        risk = self.risk_var.get()
        visible: list[CleanupCandidate] = []
        for candidate in self.candidates:
            haystack = " ".join(
                (str(candidate.path), candidate.category.value, " ".join(candidate.reasons))
            ).casefold()
            if search and search not in haystack:
                continue
            if category != "All categories" and candidate.category.value != category:
                continue
            if risk != "All risks" and candidate.risk.value != risk:
                continue
            visible.append(candidate)
        self.visible_candidates = self._sorted_candidates(visible)

        self.tree.delete(*self.tree.get_children())
        for index, candidate in enumerate(self.visible_candidates):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    str(candidate.path),
                    candidate.category.value,
                    "; ".join(candidate.reasons),
                    format_bytes(candidate.size_bytes),
                    f"{candidate.age_days} days",
                    candidate.risk.value,
                ),
                tags=(candidate.risk.value.casefold(),),
            )
        rows_to_restore = [
            str(index)
            for index, candidate in enumerate(self.visible_candidates)
            if self._path_key(candidate.path) in selected_keys
        ]
        if rows_to_restore:
            self.tree.selection_set(rows_to_restore)
        self._update_selection_state()

    def _sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self._refresh_table()

    def _sorted_candidates(self, candidates: list[CleanupCandidate]) -> list[CleanupCandidate]:
        key_functions = {
            "path": lambda item: os.path.normcase(str(item.path)),
            "category": lambda item: item.category.value,
            "reason": lambda item: item.reasons,
            "size": lambda item: item.size_bytes,
            "age": lambda item: item.age_days,
            "risk": lambda item: item.risk.rank,
        }
        return sorted(
            candidates,
            key=key_functions.get(self.sort_column, key_functions["path"]),
            reverse=self.sort_reverse,
        )

    def _select_safe(self) -> None:
        rows = [
            str(index)
            for index, candidate in enumerate(self.visible_candidates)
            if candidate.safe_to_bulk_select
        ]
        self.tree.selection_set(rows)
        self._update_selection_state()

    def _clear_selection(self) -> None:
        self.tree.selection_remove(self.tree.selection())
        self._update_selection_state()

    def _on_selection_changed(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        candidates = self._selected_candidates()
        if not candidates:
            self.details_var.set("Select a result to inspect its reason and timestamps.")
            self._update_selection_state()
            return
        candidate = candidates[0]
        modified = candidate.modified_at.astimezone().strftime("%Y-%m-%d %H:%M")
        newest = candidate.newest_modified_at.astimezone().strftime("%Y-%m-%d %H:%M")
        self.details_var.set(
            f"{candidate.kind.value} · {candidate.risk.value} risk · "
            f"Path modified {modified} · Newest content {newest} · "
            + "; ".join(candidate.reasons)
        )
        self._update_selection_state()

    def _update_selection_state(self) -> None:
        candidates = self._selected_candidates()
        total_size = sum(candidate.size_bytes for candidate in candidates)
        self.selection_var.set(
            f"{len(candidates)} selected · {format_bytes(total_size)}"
        )
        self._update_delete_button()

    def _update_delete_button(self) -> None:
        if not hasattr(self, "delete_button"):
            return
        state = "normal" if self.tree.selection() and not self.busy else "disabled"
        self.delete_button.configure(state=state)

    def _selected_candidates(self) -> list[CleanupCandidate]:
        selected: list[CleanupCandidate] = []
        for row in self.tree.selection():
            try:
                selected.append(self.visible_candidates[int(row)])
            except (ValueError, IndexError):
                continue
        return selected

    def _request_deletion(self) -> None:
        candidates = self._selected_candidates()
        if not candidates or self.busy:
            return
        mode = DeletionConfirmation(self, candidates).show()
        if mode is None:
            self.status_var.set("Deletion cancelled. Nothing was removed.")
            return

        self.busy = True
        self.scan_button.configure(state="disabled")
        self.delete_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(
            "Moving approved items to Recycle Bin…"
            if mode == "trash"
            else "Permanently deleting approved items…"
        )
        thread = threading.Thread(
            target=self._delete_worker,
            args=(tuple(candidates), mode),
            daemon=True,
            name="android-cleanup-delete",
        )
        thread.start()

    def _delete_worker(
        self, candidates: tuple[CleanupCandidate, ...], mode: str
    ) -> None:
        service = DeletionService(
            allowed_roots=(root.path for root in self.last_scan_roots),
            protected_paths=(root.path for root in self.last_scan_roots if root.protected),
            application_root=Path(__file__).resolve().parent.parent,
        )
        results = (
            service.send_to_trash(candidates)
            if mode == "trash"
            else service.delete_permanently(candidates)
        )
        self.messages.put(("delete_complete", tuple(results)))

    def _handle_deletion_results(self, results: list[DeletionResult]) -> None:
        self._finish_busy_state()
        succeeded = [result for result in results if result.succeeded]
        failed = [result for result in results if not result.succeeded]
        removed_keys = {self._path_key(result.candidate.path) for result in succeeded}
        self.candidates = [
            candidate
            for candidate in self.candidates
            if self._path_key(candidate.path) not in removed_keys
        ]
        self._refresh_table()
        self.status_var.set(
            f"Removed {len(succeeded)} approved item(s); {len(failed)} failed."
        )
        if failed:
            details = "\n".join(
                f"{result.candidate.path}: {result.message}" for result in failed[:10]
            )
            messagebox.showwarning("Some items were not removed", details)
        elif succeeded:
            messagebox.showinfo(
                "Cleanup complete", f"Successfully processed {len(succeeded)} approved item(s)."
            )

    def _add_root(self) -> None:
        selected = filedialog.askdirectory(title="Choose an Android project or development folder")
        if not selected:
            return
        path = Path(selected).resolve(strict=False)
        if path not in self.custom_roots:
            self.custom_roots.append(path)
        self._update_roots_label()

    def _clear_roots(self) -> None:
        self.custom_roots.clear()
        self._update_roots_label()

    def _update_roots_label(self) -> None:
        count = len(self.custom_roots)
        self.roots_var.set("No custom roots" if count == 0 else f"{count} custom root(s)")

    def _reveal_selected(self) -> None:
        rows = self.tree.selection()
        if not rows:
            messagebox.showinfo("Reveal", "Highlight a result row first.")
            return
        try:
            candidate = self.visible_candidates[int(rows[0])]
        except (ValueError, IndexError):
            return
        if not candidate.path.exists():
            messagebox.showwarning("Reveal", "That path no longer exists.")
            return
        subprocess.Popen(["explorer.exe", "/select,", str(candidate.path)])

    def _on_close(self) -> None:
        self.scan_cancel_event.set()
        self.destroy()

    @staticmethod
    def _path_key(path: Path) -> str:
        return os.path.normcase(str(path.resolve(strict=False)))


class DeletionConfirmation(tk.Toplevel):
    def __init__(self, parent: CleanupApp, candidates: list[CleanupCandidate]) -> None:
        super().__init__(parent)
        self.withdraw()
        self.parent = parent
        self.result: str | None = None
        self.mode_var = tk.StringVar(value="trash")
        self.acknowledge_var = tk.BooleanVar(value=False)
        self.title("Confirm cleanup")
        self.geometry("720x520")
        self.minsize(600, 430)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        total_size = sum(candidate.size_bytes for candidate in candidates)
        ttk.Label(
            self,
            text=f"Review {len(candidates)} selected item(s) — {format_bytes(total_size)} total",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(16, 8))
        ttk.Label(
            self,
            text="Only the paths listed below will be processed. Recycle Bin is recoverable and recommended.",
            wraplength=680,
        ).pack(anchor="w", padx=16, pady=(0, 8))

        list_frame = ttk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=16, pady=8)
        path_list = tk.Listbox(list_frame, selectmode=tk.BROWSE, exportselection=False)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=path_list.yview)
        path_list.configure(yscrollcommand=scrollbar.set)
        path_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for candidate in candidates:
            path_list.insert("end", f"[{candidate.risk.value}] {candidate.path}")

        choices = ttk.LabelFrame(self, text="Deletion method", padding=10)
        choices.pack(fill="x", padx=16, pady=(0, 8))
        ttk.Radiobutton(
            choices,
            text="Move to Recycle Bin (recommended)",
            variable=self.mode_var,
            value="trash",
            command=self._update_confirmation_state,
        ).pack(anchor="w")
        ttk.Radiobutton(
            choices,
            text="Delete permanently",
            variable=self.mode_var,
            value="permanent",
            command=self._update_confirmation_state,
        ).pack(anchor="w", pady=(5, 0))
        self.acknowledgement = ttk.Checkbutton(
            choices,
            text="I understand that permanent deletion cannot be undone.",
            variable=self.acknowledge_var,
            command=self._update_confirmation_state,
            state="disabled",
        )
        self.acknowledgement.pack(anchor="w", padx=(24, 0), pady=(5, 0))

        buttons = ttk.Frame(self)
        buttons.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(buttons, text="Cancel", command=self._cancel).pack(side="right")
        self.confirm_button = ttk.Button(
            buttons, text="Confirm cleanup", command=self._confirm
        )
        self.confirm_button.pack(side="right", padx=(0, 8))

    def show(self) -> str | None:
        self.deiconify()
        self.grab_set()
        self.wait_visibility()
        self.focus_set()
        self.wait_window()
        return self.result

    def _update_confirmation_state(self) -> None:
        permanent = self.mode_var.get() == "permanent"
        self.acknowledgement.configure(state="normal" if permanent else "disabled")
        if not permanent:
            self.acknowledge_var.set(False)
        can_confirm = not permanent or self.acknowledge_var.get()
        self.confirm_button.configure(state="normal" if can_confirm else "disabled")

    def _confirm(self) -> None:
        if self.mode_var.get() == "permanent" and not self.acknowledge_var.get():
            return
        self.result = self.mode_var.get()
        self.grab_release()
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()


def main() -> None:
    app = CleanupApp()
    app.mainloop()


if __name__ == "__main__":
    main()


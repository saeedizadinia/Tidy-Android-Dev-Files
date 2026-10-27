# Tidy Android Development Files

A Windows-first Tkinter application that finds stale, empty, generated, and
outdated Android Studio or Gradle data. Scan results are review-only: nothing is
selected or removed automatically.

## Run

```powershell
python -m pip install -e ".[dev]"
python -m tidy_android
```

In IntelliJ IDEA, run `app.py` directly.

The default stale threshold is 90 days. The application uses modification time
as a practical last-use signal because Windows access-time tracking is commonly
disabled. High-risk SDK, system-image, AVD, and configuration candidates are
clearly marked and excluded from **Select safe**.

Select rows directly in the results table. Use a normal click for one row,
Ctrl-click to toggle individual rows, or Shift-click to select a range. The
footer shows the selected item count and combined size.

Deletion always requires a confirmation dialog. Recycle Bin is the default;
permanent deletion requires a second acknowledgement.


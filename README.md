# HashHarbor

A Windows-friendly file integrity monitor and ransomware activity warning tool. HashHarbor creates a SHA-256 baseline, stores verified recovery copies in a separate folder, watches for new/changed/deleted files, and warns when many changes happen in a short period.

## Run

Requires Python 3.10 or newer. It uses only the Python standard library.

```powershell
python file_sentinel.py
```

To copy the project to a USB drive or another device, double-click `Copy-HashHarbor-to-device.bat` and select a destination folder. The copy excludes `.venv`, `.git`, editor settings, and Python cache files. Install Python 3.10 or newer on the other device before launching the app. To make a desktop shortcut, right-click the `.bat` file, choose **Show more options > Send to > Desktop (create shortcut)**, then use the shortcut from your desktop.

1. Select the folder to protect.
2. Select a separate recovery vault. For better resilience, use an external drive and disconnect it when it is not needed.
3. Choose **Create trusted baseline** and wait for the integrity-checked copy to finish.
4. Choose **Start monitoring**. The app checks the folder every two seconds.
5. **Restore baseline** overwrites files from the baseline after confirmation. Files created after the baseline are left in place.

The **Admin** tab shows a persistent audit history of monitoring starts/stops, baselines, restores, detected file changes, errors, and burst warnings. Filter the table or export its current filtered view to CSV. On Windows, the history is stored in `%LOCALAPPDATA%\HashHarbor\activity.jsonl`. File changes are detected by periodic scans; HashHarbor does not inspect network traffic.

The vault and protected folder cannot contain one another. Create a new baseline in an empty vault folder when you intentionally want to refresh trusted copies.

## Important limits

This is a local monitor, not antivirus software. Burst detection is a simple heuristic and can produce false alarms; it does not terminate or block processes. Monitoring runs only while the app is open. A recovery vault on the same computer can still be affected by malware with access to it, so keep an offline or disconnected backup as well.

Run the focused core tests with:

```powershell
python -m unittest discover -s tests -v
```

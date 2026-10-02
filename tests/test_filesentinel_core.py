import tempfile
import unittest
from pathlib import Path

from filesentinel_core import (
    ActivityLog,
    FileRecord,
    RansomwareDetector,
    changed_files,
    create_baseline,
    restore_baseline,
    scan_directory,
)


class HashHarborCoreTests(unittest.TestCase):
    def test_activity_log_persists_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = ActivityLog(Path(temporary) / "history" / "activity.jsonl")

            written = log.record("CHANGED", "notes.txt", "Detected during scan")

            self.assertEqual(log.read(), [written])

    def test_activity_log_skips_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "activity.jsonl"
            log = ActivityLog(log_path)
            record = log.record("STARTED", details="Monitoring started")
            with log_path.open("a", encoding="utf-8") as file:
                file.write("not valid json\n")

            self.assertEqual(log.read(), [record])

    def test_detects_created_changed_and_deleted_files(self) -> None:
        previous = {
            "changed.txt": FileRecord(3, "old"),
            "deleted.txt": FileRecord(4, "gone"),
        }
        current = {
            "changed.txt": FileRecord(3, "new"),
            "created.txt": FileRecord(5, "added"),
        }

        self.assertEqual(
            changed_files(previous, current),
            [("CHANGED", "changed.txt"), ("NEW", "created.txt"), ("DELETED", "deleted.txt")],
        )

    def test_baseline_restores_original_file_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            protected = base / "protected"
            vault = base / "vault"
            protected.mkdir()
            (protected / "notes.txt").write_text("trusted", encoding="utf-8")
            (protected / "subfolder").mkdir()
            (protected / "subfolder" / "photo.bin").write_bytes(b"original")

            baseline = create_baseline(protected, vault)
            (protected / "notes.txt").write_text("encrypted", encoding="utf-8")
            (protected / "subfolder" / "photo.bin").unlink()

            self.assertEqual(restore_baseline(protected, baseline), 2)
            self.assertEqual((protected / "notes.txt").read_text(encoding="utf-8"), "trusted")
            self.assertEqual((protected / "subfolder" / "photo.bin").read_bytes(), b"original")

    def test_rejects_vault_inside_protected_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary) / "protected"
            protected.mkdir()
            with self.assertRaises(ValueError):
                create_baseline(protected, protected / "vault")

    def test_flags_a_change_burst_only_at_threshold(self) -> None:
        detector = RansomwareDetector(threshold=3, window_seconds=10)

        self.assertFalse(detector.add([("CHANGED", "a.txt")], now=100))
        self.assertFalse(detector.add([("DELETED", "b.txt")], now=101))
        self.assertTrue(detector.add([("NEW", "c.txt")], now=102))
        self.assertFalse(detector.add([("CHANGED", "d.txt")], now=111.1))

    def test_scans_nested_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "subfolder").mkdir()
            (root / "subfolder" / "notes.txt").write_text("content", encoding="utf-8")

            records = scan_directory(root)

            self.assertIn("subfolder/notes.txt", records)
            self.assertEqual(records["subfolder/notes.txt"].size, 7)


if __name__ == "__main__":
    unittest.main()
"""Git diff parser for ControlGate."""

from __future__ import annotations

import re

from controlgate.models import DiffFile, DiffHunk

# Regex patterns for parsing unified diff format
_DIFF_HEADER = re.compile(r"^diff --git a/(.*) b/(.*)")
_NEW_FILE = re.compile(r"^new file mode")
_DELETED_FILE = re.compile(r"^deleted file mode")
_RENAME_FROM = re.compile(r"^rename from (.*)")
_RENAME_TO = re.compile(r"^rename to (.*)")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_diff(diff_text: str) -> list[DiffFile]:
    """Parse unified diff text into a list of DiffFile objects.

    Args:
        diff_text: Raw output from `git diff` (unified diff format).

    Returns:
        A list of DiffFile objects with hunks containing added/removed lines.
    """
    files: list[DiffFile] = []
    current_file: DiffFile | None = None
    current_hunk: DiffHunk | None = None
    current_line_no = 0

    for raw_line in diff_text.splitlines():
        # New file diff header
        header_match = _DIFF_HEADER.match(raw_line)
        if header_match:
            current_file = DiffFile(path=header_match.group(2))
            files.append(current_file)
            current_hunk = None
            continue

        if current_file is None:
            continue

        # New file mode
        if _NEW_FILE.match(raw_line):
            current_file.is_new = True
            continue

        # Deleted file mode
        if _DELETED_FILE.match(raw_line):
            current_file.is_deleted = True
            continue

        # Rename detection
        rename_from = _RENAME_FROM.match(raw_line)
        if rename_from:
            current_file.is_renamed = True
            current_file.old_path = rename_from.group(1)
            continue

        rename_to = _RENAME_TO.match(raw_line)
        if rename_to:
            current_file.path = rename_to.group(1)
            continue

        # Hunk header
        hunk_match = _HUNK_HEADER.match(raw_line)
        if hunk_match:
            start_line = int(hunk_match.group(1))
            line_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
            current_hunk = DiffHunk(start_line=start_line, line_count=line_count)
            current_file.hunks.append(current_hunk)
            current_line_no = start_line
            continue

        if current_hunk is None:
            continue

        # Added line
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            current_hunk.added_lines.append((current_line_no, content))
            current_line_no += 1
            continue

        # Removed line
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:]
            current_hunk.removed_lines.append((current_line_no, content))
            # Removed lines don't increment the new-file line counter
            continue

        # Context line
        if raw_line.startswith(" "):
            content = raw_line[1:]
            current_hunk.context_lines.append((current_line_no, content))
            current_line_no += 1
            continue

        # No-newline-at-end-of-file marker — skip
        if raw_line.startswith("\\"):
            continue

        # Any other line (binary notice, index line, etc.) — skip
        current_line_no += 1

    return files

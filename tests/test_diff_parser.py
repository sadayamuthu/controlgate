"""Tests for the git diff parser."""

from controlgate.diff_parser import parse_diff

_SIMPLE_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,5 @@
+import os
+
+PASSWORD = "super_secret_123"
+DB_HOST = "localhost"
+DB_PORT = 5432
"""

_MULTI_FILE_DIFF = """\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+import hashlib

 DEBUG = True
diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -10,4 +10,6 @@
 def run():
     pass
+    print("running")
+    return True
"""

_RENAME_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
"""

_DELETE_DIFF = """\
diff --git a/removed.py b/removed.py
deleted file mode 100644
--- a/removed.py
+++ /dev/null
@@ -1,3 +0,0 @@
-import os
-print("hello")
-print("world")
"""


class TestParseDiff:
    def test_parse_new_file(self):
        files = parse_diff(_SIMPLE_DIFF)
        assert len(files) == 1
        f = files[0]
        assert f.path == "app.py"
        assert f.is_new is True
        assert len(f.hunks) == 1
        assert len(f.all_added_lines) == 5

    def test_added_line_content(self):
        files = parse_diff(_SIMPLE_DIFF)
        lines = files[0].all_added_lines
        assert any("PASSWORD" in line for _, line in lines)

    def test_parse_multi_file(self):
        files = parse_diff(_MULTI_FILE_DIFF)
        assert len(files) == 2
        assert files[0].path == "config.py"
        assert files[1].path == "main.py"

    def test_multi_file_added_lines(self):
        files = parse_diff(_MULTI_FILE_DIFF)
        config_lines = files[0].all_added_lines
        assert len(config_lines) == 1
        assert "hashlib" in config_lines[0][1]

        main_lines = files[1].all_added_lines
        assert len(main_lines) == 2

    def test_parse_rename(self):
        files = parse_diff(_RENAME_DIFF)
        assert len(files) == 1
        f = files[0]
        assert f.is_renamed is True
        assert f.old_path == "old_name.py"
        assert f.path == "new_name.py"

    def test_parse_delete(self):
        files = parse_diff(_DELETE_DIFF)
        assert len(files) == 1
        f = files[0]
        assert f.is_deleted is True
        assert len(f.hunks) == 1
        assert len(f.hunks[0].removed_lines) == 3

    def test_full_content(self):
        files = parse_diff(_SIMPLE_DIFF)
        content = files[0].full_content
        assert "PASSWORD" in content
        assert "DB_HOST" in content

    def test_empty_diff(self):
        files = parse_diff("")
        assert files == []

    def test_line_numbers(self):
        files = parse_diff(_SIMPLE_DIFF)
        lines = files[0].all_added_lines
        # Hunk starts at line 1, so lines should be 1-5
        line_nums = [n for n, _ in lines]
        assert line_nums == [1, 2, 3, 4, 5]

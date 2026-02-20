"""JSON verdict reporter for ControlGate."""

from __future__ import annotations

import json

from controlgate.models import Verdict


class JSONReporter:
    """Serialize a Verdict to JSON format."""

    def render(self, verdict: Verdict) -> str:
        """Render the verdict as a JSON string.

        Args:
            verdict: The verdict to serialize.

        Returns:
            A formatted JSON string matching the ControlGate verdict schema.
        """
        return json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False)

    def write(self, verdict: Verdict, output_path: str) -> None:
        """Write the verdict to a JSON file.

        Args:
            verdict: The verdict to serialize.
            output_path: Path to the output file.
        """
        from pathlib import Path

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(verdict), encoding="utf-8")

"""In-memory mock tools. Nothing here touches the real world."""

from __future__ import annotations

from typing import Any, Mapping

# Synthetic dummy files only. These paths are never opened on disk.
DUMMY_FILES: dict[str, str] = {
    "/workspace/docs/readme.md": (
        "# Docs\nHello from the mock filesystem.\n"
    ),
    "/workspace/docs/public/faq.md": "Frequently asked questions.\n",
    "/workspace/docs/confidential_notes.md": (
        "SYNTHETIC CONFIDENTIAL: dummy badge numbers D-1001, D-1002. "
        "This is not real personal data.\n"
    ),
    "/workspace/tmp/cache.bin": "temporary-bytes",
    "/workspace/hr/salaries.txt": (
        "SYNTHETIC PAYROLL: Alice 1, Bob 2. Not real salaries.\n"
    ),
    "/etc/passwd": "SYNTHETIC root:x:0:0:root:/root:/bin/sh\n",
}


class ToolExecutionError(RuntimeError):
    """Raised when a mock tool is asked to fail on purpose (for tests)."""


class MockToolRunner:
    """Pretend to run tools. Results stay inside this object.

    - read_file looks up a dict, not the disk
    - send_email appends to a list, no SMTP
    - delete_file marks a dummy file deleted; no real unlink
    - transfer_funds appends a ledger row, no bank call
    """

    def __init__(self, files: Mapping[str, str] | None = None) -> None:
        self.files: dict[str, str] = dict(files if files is not None else DUMMY_FILES)
        self.sent_emails: list[dict[str, Any]] = []
        self.transfers: list[dict[str, Any]] = []
        self.deleted_paths: list[str] = []
        self.deleted_contents: dict[str, str] = {}
        # Action names that should raise instead of running (used in tests).
        self._fail_actions: set[str] = set()

    def fail_on(self, action: str) -> None:
        """Next run of this action will raise ToolExecutionError."""

        self._fail_actions.add(action)

    def run(self, action: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Dispatch to a mock. Unknown names raise.

        The gateway must call this only after policy ALLOW (or human approve).
        """

        if action in self._fail_actions:
            self._fail_actions.discard(action)
            raise ToolExecutionError(f"Simulated failure in mock '{action}'.")

        handlers = {
            "read_file": self._read_file,
            "send_email": self._send_email,
            "delete_file": self._delete_file,
            "transfer_funds": self._transfer_funds,
        }
        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"No mock tool registered for '{action}'.")
        return handler(arguments)

    def _read_file(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        path = str(arguments["path"])
        if path in self.deleted_paths or path not in self.files:
            return {"status": "not_found", "path": path, "content": None}
        return {"status": "ok", "path": path, "content": self.files[path]}

    def _send_email(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = {
            "to": arguments["to"],
            "subject": arguments["subject"],
            "body": arguments["body"],
        }
        self.sent_emails.append(record)
        return {"status": "queued_mock", "email": record}

    def _delete_file(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        path = str(arguments["path"])
        existed = path in self.files and path not in self.deleted_paths
        if existed:
            self.deleted_contents[path] = self.files.pop(path)
        self.deleted_paths.append(path)
        return {"status": "deleted_mock", "path": path, "existed": existed}

    def _transfer_funds(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        record = {
            "amount": arguments["amount"],
            "to_account": arguments["to_account"],
        }
        self.transfers.append(record)
        return {"status": "posted_mock", "transfer": record}

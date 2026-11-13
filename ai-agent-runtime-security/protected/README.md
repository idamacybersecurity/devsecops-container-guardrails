# AI Agent Protected Tool Guardrails

This package contains a protected-mode candidate for the AI agent and its
automated unit tests. The original unprotected baseline source and Docker
image must remain unchanged.

## Protected-mode controls

When AGENT_MODE=protected:

- `read_file` accepts only existing regular files beneath the configured
  fixtures directory.
- File access uses directory-relative file descriptors and O_NOFOLLOW
  for directory components and the final file.
- The final file is opened with O_NONBLOCK and checked with fstat before
  reading. Symlinks, directories, FIFOs, and other non-regular files are
  denied.
- Parent-directory traversal and paths outside the fixtures directory
  are denied.
- `shell_execute` accepts only the exact commands `pwd` and `ls`.
  It does not invoke a shell. Other commands and shell syntax are denied.
- Guardrail denials are recorded as `guardrail_denied` and
  `tool_completed` events with `status=denied`.
- Audit-write failures raise an error in protected mode and stop the
  agent rather than silently continuing.

## Test coverage

The unit suite contains 15 tests covering:

- Approved fixture reads.
- External and private path denial.
- Parent traversal denial.
- Symlink escape, internal symlink, and symlinked-directory denial.
- FIFO rejection.
- Permitted diagnostic commands.
- Shell command and shell syntax restrictions.
- Denial audit records.
- Protected-mode audit-write failure.

Run from the project root after placing the files in their corresponding
directories:

    python3 -B -m unittest discover -s ai-agent-runtime-security/protected/tests -p 'test_*.py' -v

The tests use temporary synthetic fixtures and do not require Ollama.

## Security limitations

These are application-layer tool restrictions, not a complete container
security boundary. Retain Docker isolation: non-root execution, read-only
container filesystem, dropped capabilities, no-new-privileges, resource
limits, isolated networking, and no Docker socket.

The fixture directory must be a trusted, correctly mounted directory.
Audit fail-closed behavior does not guarantee persistence against every
possible storage or host failure.

The original baseline image must remain unchanged. Build a separate
protected image only after candidate validation and review.

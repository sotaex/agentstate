# Host protocol probe (U-47 / D6)

When a host (Qoder, TRAE, a new Claude Code / ZCode release, ...) changes its hook
contract, collect evidence instead of guessing:

1. Register the probe as the host's PreToolUse hook:
   {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
       {"type": "command", "command": "<python> <abs>/tools/probe_host.py --tag <host>", "timeout": 10}]}}]}
2. Trigger ONE tool call (any read or command) in that host.
3. Send us `.psl/probe/<host>-1.json` (it contains the raw stdin event, argv, cwd and
   env markers; the probe never blocks anything).

We diff the captured field layout against HOST_ADAPTERS and update the profile.
Schedule: re-run this after every host major update (see .github/workflows/verify.yml).

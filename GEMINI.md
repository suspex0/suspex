# suspex0 — Antigravity agent working rules

## Machines

The exec / terminal tool runs on the dev host only — never a lab target. Lab
machines are reached ONLY via `suspex0` MCP tools.

- Views are `'<machine>.<kind>'` (`lab2.kernel`, `DESKTOP-ABC.user`);
  `target_manage(action='use', machine='lab2')` sets this chat's focus
  machine, `name='lab2.kernel'` pins a call explicitly.
- >1 connected machine and no focus → target-touching calls fail
  `{ok:false, kind:'ambiguous_target'}` — set `use` or pass `name=`.
- Machine identity in responses is minimal (v0.30): a bare
  `target: '<machine>.<kind>'` view key appears only when more than one
  view is connected or the answer isn't your focus machine. Full machine
  metadata (trust/purpose/notes/endpoints) arrives ONCE per machine on
  first connect (`machine_info`) and on demand via
  `target_manage(action='machines')`. Machines are added/updated at
  runtime with `machines_register`/`machines_set` (persisted in
  `artifacts/targets.json`, no restart); actuator verbs on machines
  below `security.min_trust_actuator` need `force=true`.

## Commit messages

- NEVER add AI-generated attribution stamps ("Generated with …",
  "Co-Authored-By: …" or similar) to commit messages. Plain,
  conventional commits only — see `git log` for house style
  (`vX.YZ: summary` for release commits, `area: change` otherwise).

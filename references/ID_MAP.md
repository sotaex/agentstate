<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel rule id map (generated from rules/default.json v0.63.2 - do not edit by hand)

0.63.0 renamed every rule id. **The rename was an identity transformation.**
Same rules, same patterns, same severity, same decisions on the same input --
only the identifier strings changed. Each rule carries its old id in the
`legacy_id` field, and this table is generated from that field.

Old ids still appear in audit logs, evidence chains and documents written
before 0.63.0. Use this table to read them; nothing was invalidated by the
rename, but nothing was rewritten retroactively either.

## Translation table (37 rules)

| current id | legacy id | name | category | severity |
|---|---|---|---|---|
| `AN-001` | `SEC-01` | Sensitive file read (.env) | secrets | critical |
| `AN-002` | `SEC-02` | SSH key file read | secrets | critical |
| `AN-003` | `SEC-03` | Cloud credential file read | secrets | critical |
| `AN-004` | `SEC-04` | Wallet/keystore file read | secrets | critical |
| `AN-005` | `SEC-05` | Browser data read | secrets | critical |
| `AN-006` | `NET-01` | Shell network request | network | warning |
| `AN-007` | `NET-02` | Python network request | network | warning |
| `AN-008` | `NET-03` | Non-whitelisted domain connection | network | warning |
| `AN-009` | `DST-01` | File deletion | destructive | critical |
| `AN-010` | `DST-02` | Write outside project root | destructive | critical |
| `AN-011` | `DST-03` | Shell configuration modification | destructive | critical |
| `AN-012` | `DST-04` | Persistence mechanism | destructive | critical |
| `AN-013` | `DST-05` | Privilege escalation | destructive | warning |
| `AN-014` | `CTX-01` | Environment variable enumeration | context | warning |
| `AN-015` | `CTX-02` | Prompt injection pattern in instruction file | injection | critical |
| `AN-016` | `CTX-03` | Invisible Unicode characters | injection | critical |
| `AN-017` | `CTX-04` | Encoded payload | injection | warning |
| `AN-018` | `CTX-05` | Skill name mismatch | metadata | warning |
| `AN-019` | `DST-06` | Remote script piped to interpreter | destructive | critical |
| `AN-020` | `DST-07` | Irreversible git discard | destructive | critical |
| `AN-021` | `SEC-06` | Secret literal in content | secrets | critical |
| `AN-022` | `DST-08` | Permission/ownership destruction | destructive | critical |
| `AN-023` | `DST-09` | Alternate data stream write (file path) | destructive | critical |
| `AN-024` | `DST-10` | Alternate data stream write (command) | destructive | critical |
| `AN-025` | `CTX-07` | Inline base64-decode exec | injection | critical |
| `AN-026` | `SEC-07` | Clipboard read | secrets | critical |
| `AN-027` | `SEC-08` | Screen capture | secrets | warning |
| `AN-028` | `SEC-09` | IM/mail local store read | secrets | critical |
| `AN-029` | `SEC-10` | Input-method user dictionary read | secrets | warning |
| `AN-030` | `DST-11` | Write into cloud-sync directory | destructive | critical |
| `AN-031` | `NET-04` | Tunnel / covert channel | network | warning |
| `AN-032` | `MCP-01` | Write to MCP config file | supply_chain | warning |
| `AN-033` | `MCP-02` | Prompt injection in MCP tool description | supply_chain | warning |
| `AN-034` | `MCP-03` | Unaudited remote MCP server | supply_chain | warning |
| `AN-035` | `MCP-04` | Plaintext secret in MCP config env | supply_chain | warning |
| `AN-036` | `SEC-11` | Canary file read | canary | warning |
| `AN-037` | `SLOP-01` | Typosquatted package name in install command | supply_chain | warning |

## How to read an old record

- **old id -> current id**: look the old id up in the `legacy id` column, read the
  `current id` on the same row. That is the rule the product reports today.
- **current id -> old id**: read the `legacy id` column on the current id's row.
  This is what you need when comparing today's findings with a record written
  before 0.63.0.
- The mapping is **one-to-one in both directions**. If you find an old id that is
  not in the `legacy id` column, or a current id with no legacy id, that is a
  defect in this table -- not a rule that was retired.

  (A few judgements live outside the number space entirely: see the next section.)

## Judgements outside the number space

These are implemented in hook code and are **not** part of `AN-NNN`.
The rename could not reach them; they do not appear in the table above.
Listed so that someone grepping for an old id finds an answer, not nothing.

| id | in rule table? | 0.63.0 treatment | note |
|---|---|---|---|
| `OUT-01` | no | id kept as `OUT-01` (deliberately not collected) | 输出面：私有密钥/凭据出现在工具输出里（hooks/post_tool_use.py:605 起，PostToolUse）。★ 0.63.0：号未收编，保留旧号直到 channel 字段落地 |
| `DEV-01` | no | de-numbered (was `GOV-01`) | 套件治理：A1/A2 写入时刻拦截（_suite_gov_hit，同 ci/delivery_gate.py 双向同步）。★ 0.63.0 去号：原 GOV-01，不再占判据号段，改走 type:governance |
| `notice_budget` | no | de-numbered (was `BUDGET-01`) | 提醒预算：token 预算超阈值（_budget_hit）。★ 0.63.0 去号：原 BUDGET-01，已有专属 type notice_budget_*，此号永不回收 |

Not a table-outside judgement, but worth knowing: `AN-037` **is** in the table above (its id and legacy id are ordinary), but its verdict is decided by code rather than by the patterns listed for it. The row is still correct; do not read an empty pattern list as "never fires".

`in rule table? = no` means the judgement still runs and still lands in the
ledger's `rules_hit`, but its identifier is not one of the `AN-NNN` rules.
Why that happened: `DEV-01` and `notice_budget` had been borrowing a rule
number while not being rules, which made every count of "rules that fired"
quietly wrong. `OUT-01` is the other case -- its number is genuinely its own,
it just has not been collected into a shared range yet, so it keeps it.
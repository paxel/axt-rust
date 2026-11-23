# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker, plus one repo-specific label.

| Label in mattpocock/skills | Label in our tracker | Meaning                                                  |
|----------------------------|----------------------|----------------------------------------------------------|
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue                  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information                 |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent                  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation                            |
| `wontfix`                  | `wontfix`            | Will not be actioned                                     |
| —                          | `implemented`        | Code done and committed; open for review/QA, user closes |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

`implemented` is not a canonical role: the agent applies it once the work for an issue is committed, and leaves the issue open. The user reviews and closes it.

Edit the right-hand column to match whatever vocabulary you actually use.

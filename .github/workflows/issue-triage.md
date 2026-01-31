---
description: Automatically triage incoming issues by analyzing content, adding labels, and providing helpful responses
on:
  issues:
    types: [opened, edited]
roles: all
permissions:
  contents: read
  issues: read
  pull-requests: read
tools:
  github:
    toolsets: [default]
safe-outputs:
  add-comment:
    max: 1
  update-issue:
  noop:
  missing-tool:
    create-issue: true
---

{{#runtime-import agentics/issue-triage.md}}

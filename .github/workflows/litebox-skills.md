---
description: Autonomous agent that implements support for shell scripts, Node.js, and Python in LiteBox to run all Anthropic skills
on:
  schedule:
    - cron: "0 0,6,12,18 * * *"
permissions:
  contents: read
  issues: read
  pull-requests: read
tools:
  github:
    toolsets: [default]
  serena: ["rust"]
  web-fetch:
network:
  allowed:
    - github.com
    - api.github.com
    - raw.githubusercontent.com
safe-outputs:
  create-pull-request:
    title-prefix: "[litebox-skills] "
    reviewers: ["lpcox"]
    draft: false
  add-comment:
    max: 2
  noop:
  missing-tool:
    create-issue: true
---

{{#runtime-import agentics/litebox-skills.md}}

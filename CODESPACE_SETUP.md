# GitHub Codespace Setup Guide

This guide explains how to create and use a GitHub Codespace for the LiteBox repository with pre-installed MCP servers.

## Quick Start

**Can't see the branch?** Jump to [Troubleshooting: Can't See the Branch](#cant-see-the-branch-copilotadd-mcp-servers-to-devcontainer)

**Fastest method:**
```bash
gh codespace create --repo Vadiml1024/litebox --branch copilot/add-mcp-servers-to-devcontainer --web
```

Or go directly to the branch: https://github.com/Vadiml1024/litebox/tree/copilot/add-mcp-servers-to-devcontainer

## What is a GitHub Codespace?

GitHub Codespaces provides a complete, cloud-based development environment that runs in your browser or VS Code. It uses the `.devcontainer` configuration in this repository to automatically set up:

- **Rust toolchain** (nightly-2026-01-15)
- **Development tools** (MinGW, gdb, cargo-nextest)
- **Node.js and npm** for JavaScript tooling
- **MCP Servers** (github-mcp-server) for AI assistant integration
- **VS Code extensions** (rust-analyzer, LLDB debugger, TOML support)

## Creating a Codespace

### Method 1: GitHub Web UI (Recommended)

#### Step-by-Step Instructions:

1. **Navigate to the repository** on GitHub:
   - Go to: https://github.com/Vadiml1024/litebox

2. **Switch to the MCP servers branch**:
   - Click on the branch dropdown (currently showing "main" or another branch name)
   - Type `copilot/add-mcp-servers-to-devcontainer` in the search box
   - Click on the branch name when it appears
   - You should now see "copilot/add-mcp-servers-to-devcontainer" in the branch dropdown

3. **Start creating a Codespace**:
   - Click the green **"Code"** button (top right of the file list)
   - Select the **"Codespaces"** tab
   - Click **"Create codespace on copilot/add-mcp-servers-to-devcontainer"**
   - (The button should now show your selected branch name)
   
   ![Creating a Codespace](https://docs.github.com/assets/cb-77061/mw-1440/images/help/codespaces/new-codespace-button.webp)

#### Alternative: Use the branch selector in Codespace UI

1. **Navigate to the repository**: https://github.com/Vadiml1024/litebox
2. Click the green **"Code"** button → **"Codespaces"** tab
3. Click the **"..."** (three dots) or dropdown arrow next to "Create codespace"
4. Select **"New with options..."**
5. In the branch dropdown, select `copilot/add-mcp-servers-to-devcontainer`
6. Click **"Create codespace"**

4. **Wait for the build** (first time only):
   - The first build takes 10-15 minutes to:
     - Pull the base Debian image
     - Install system packages (Node.js, npm, build tools)
     - Install Rust toolchain
     - Install cargo-nextest
     - Install MCP servers (github-mcp-server)
     - Cache Cargo dependencies
   - Subsequent starts are much faster (< 1 minute)

5. **Codespace is ready!**
   - VS Code will open in your browser
   - All tools and MCP servers are pre-installed
   - You can start developing immediately

### Method 2: GitHub CLI

If you have the GitHub CLI installed:

```bash
# Create a codespace on the current branch
gh codespace create --repo Vadiml1024/litebox --branch copilot/add-mcp-servers-to-devcontainer

# Or create and open it immediately
gh codespace create --repo Vadiml1024/litebox --branch copilot/add-mcp-servers-to-devcontainer --web
```

### Method 3: VS Code Desktop

If you have VS Code installed locally with the GitHub Codespaces extension:

1. Install the **GitHub Codespaces** extension in VS Code
2. Press `F1` or `Ctrl+Shift+P` to open the command palette
3. Type `Codespaces: Create New Codespace`
4. Select the `Vadiml1024/litebox` repository
5. Select the `copilot/add-mcp-servers-to-devcontainer` branch
6. Wait for the Codespace to build

## Verifying the Installation

Once your Codespace is running, open a terminal and verify the installations:

```bash
# Verify Rust toolchain
rustc --version
cargo --version
cargo nextest --version

# Verify Node.js and npm
node --version
npm --version

# Verify MCP server installation
which github-mcp-server
npm list -g --depth=0 | grep github-mcp-server

# Check that all tools are available
echo "✓ Rust: $(rustc --version)"
echo "✓ Cargo: $(cargo --version)"
echo "✓ Nextest: $(cargo nextest --version)"
echo "✓ Node.js: $(node --version)"
echo "✓ npm: $(npm --version)"
echo "✓ MinGW installed: $(x86_64-w64-mingw32-gcc --version | head -1)"
```

Expected output:
- Rust: nightly-2026-01-15
- Cargo: 1.94.x
- Nextest: 0.9.x
- Node.js: v18.x or later
- npm: 9.x or later

## Using MCP Servers in the Codespace

The GitHub MCP server is pre-installed and ready to use with AI assistants.

### What the GitHub MCP Server Provides

- **Repository management**: Clone, create, list repositories
- **Issue operations**: Create, update, search, manage issues
- **Pull request operations**: Create, update, review PRs
- **Code search**: Search across repositories
- **Workflow automation**: Commits, branches, merges
- **Metadata access**: Repository information, stats, etc.

### Using with GitHub Copilot

GitHub Copilot in your Codespace can automatically use the MCP server to:

1. **Search code**: "Find all usages of `litebox_platform_linux_userland`"
2. **Analyze structure**: "Explain how the PE loader works"
3. **Manage issues**: "Create an issue for adding more tests to the PE loader"
4. **Handle PRs**: "What changes are in PR #42?"
5. **Automate workflows**: "Create a branch for implementing BSS section support"

The MCP server provides GitHub Copilot with direct access to the GitHub API, making these operations seamless.

## Building and Testing

Once your Codespace is ready, you can immediately start working:

```bash
# Format code
cargo fmt

# Build the project
cargo build

# Run tests
cargo nextest run

# Run clippy
cargo clippy --all-targets --all-features

# Build Windows test programs
cd windows_test_programs
cargo build --release --target x86_64-pc-windows-gnu
```

## Customizing Your Codespace

### Installing Additional MCP Servers

If you need more MCP servers:

```bash
# Install temporarily (for this Codespace session)
npm install -g @modelcontextprotocol/server-filesystem

# Or edit .devcontainer/Dockerfile to install permanently
# and rebuild the container
```

### Updating VS Code Settings

Edit `.devcontainer/devcontainer.json` to add VS Code settings or extensions.

### Persisting Data

- Your code changes are automatically saved to the Codespace
- The Codespace persists when stopped (doesn't lose your work)
- Cargo registry and git caches are preserved via Docker volumes
- Uncommitted changes persist across Codespace restarts

## Troubleshooting

### Codespace Build Fails

If the Codespace fails to build:

1. Check the build logs in the terminal
2. Common issues:
   - Network timeout: Retry the build
   - Disk space: GitHub provides adequate space, but check if you're using a small machine type
3. You can rebuild: `Codespaces: Rebuild Container` from the command palette

### Can't See the Branch `copilot/add-mcp-servers-to-devcontainer`

If you can't find the branch when creating a Codespace:

**Solution 1: Navigate to the branch first**
1. On the repository page, click the branch dropdown (shows "main" by default)
2. Type `copilot/add-mcp-servers-to-devcontainer` in the search box
3. Click on the branch when it appears
4. Now click "Code" → "Codespaces" → The button should show "Create codespace on copilot/add-mcp-servers-to-devcontainer"

**Solution 2: Use "New with options"**
1. Click "Code" → "Codespaces"
2. Click the "..." menu or dropdown arrow
3. Select "New with options..."
4. Choose `copilot/add-mcp-servers-to-devcontainer` from the branch dropdown
5. Click "Create codespace"

**Solution 3: Use GitHub CLI** (easiest)
```bash
gh codespace create --repo Vadiml1024/litebox --branch copilot/add-mcp-servers-to-devcontainer --web
```

**Solution 4: Create from the branch page directly**
1. Go to: https://github.com/Vadiml1024/litebox/tree/copilot/add-mcp-servers-to-devcontainer
2. Click "Code" → "Codespaces" → "Create codespace on copilot/add-mcp-servers-to-devcontainer"

### MCP Server Not Available

If `github-mcp-server` is not available:

```bash
# Reinstall it
npm install -g github-mcp-server@latest

# Verify installation
which github-mcp-server
```

### Slow Performance

- Use a larger Codespace machine type (Settings → Change machine type)
- Codespaces with 4+ cores work best for Rust development

## Stopping and Managing Codespaces

### Stopping a Codespace

Codespaces automatically stop after 30 minutes of inactivity (configurable). You can also manually stop:

- **Web UI**: Click your profile → Codespaces → Stop
- **CLI**: `gh codespace stop`
- **VS Code**: Command palette → `Codespaces: Stop Current Codespace`

### Deleting a Codespace

When you're done:

- **Web UI**: Click your profile → Codespaces → Delete
- **CLI**: `gh codespace delete`

### Codespace Billing

- GitHub provides free Codespace hours for personal accounts
- Codespaces are billed per hour of compute time (not storage)
- Remember to stop Codespaces when not in use

## Benefits of Using Codespaces

✅ **No local setup required** - Everything is pre-configured
✅ **Consistent environment** - Same setup for all developers
✅ **Fast startup** - After first build, starts in under 1 minute
✅ **Work from anywhere** - Browser-based or local VS Code
✅ **Pre-installed MCP servers** - AI assistants work out of the box
✅ **Powerful machines** - Use cloud compute for faster builds

## Additional Resources

- [GitHub Codespaces Documentation](https://docs.github.com/en/codespaces)
- [Dev Container Documentation](https://containers.dev/)
- [MCP Server Documentation](https://modelcontextprotocol.io/)
- [GitHub MCP Server](https://www.npmjs.com/package/github-mcp-server)

## Getting Help

If you encounter issues:

1. Check this guide for common troubleshooting steps
2. Review the `.devcontainer/README.md` for devcontainer-specific information
3. Check the build logs in the Codespace terminal
4. Open an issue in the repository with details about the problem

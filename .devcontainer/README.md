# LiteBox Development Container

This directory contains the configuration for a development container that provides a pre-configured environment for working on the LiteBox project.

## What's Included

The devcontainer provides:

- **Rust Toolchain**: Pre-installed Rust nightly-2026-01-15 (as specified in `rust-toolchain.toml`)
- **Build Tools**: 
  - `build-essential`, `pkg-config`, `libssl-dev` for compiling Rust projects
  - `mingw-w64` for cross-compiling Windows PE binaries
  - `gdb` for debugging
- **Node.js & npm**: For JavaScript tooling and MCP server support
- **Rust Targets**: `x86_64-pc-windows-gnu` for Windows cross-compilation
- **Cargo Tools**: `cargo-nextest` for faster test execution
- **MCP Servers**: Pre-installed Model Context Protocol servers for AI assistant integration:
  - **GitHub MCP Server** (`github-mcp-server`) - Provides GitHub API access for repository management, issue/PR operations, code search, and workflow automation
- **Cached Dependencies**: All Cargo dependencies are pre-downloaded in the container image
- **VS Code Extensions**:
  - `rust-analyzer` - Rust language server
  - `vscode-lldb` - Debugger
  - `even-better-toml` - TOML syntax support

## Benefits

- **Fast Startup**: Dependencies are cached in the container image, so you don't need to download them every time
- **Consistent Environment**: Everyone uses the same toolchain and dependencies, including MCP servers for AI assistants
- **No Local Setup**: No need to install Rust, MinGW, Node.js, or other tools on your local machine
- **AI-Ready**: Pre-configured MCP servers enable GitHub Copilot and other AI assistants to interact with your repository

## Using the Devcontainer

### GitHub Codespaces

1. Go to the repository on GitHub
2. Click the "Code" button
3. Select "Codespaces" tab
4. Click "Create codespace on [branch]"

The devcontainer will automatically build and start.

### VS Code with Docker

1. Install [Docker](https://www.docker.com/products/docker-desktop)
2. Install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
3. Open the repository in VS Code
4. When prompted, click "Reopen in Container" (or run "Dev Containers: Reopen in Container" from the command palette)

The container will build the first time (this may take 10-15 minutes), but subsequent starts will be much faster.

## Building the Container Manually

If you want to build the container image manually:

```bash
cd .devcontainer
docker build -t litebox-dev .
```

## Customization

To customize the devcontainer:

- **Dockerfile**: Modify system packages, Rust components, or add new tools
- **devcontainer.json**: Adjust VS Code settings, extensions, or environment variables

## Caching

The devcontainer uses Docker volume mounts to cache:
- Cargo registry (`litebox-cargo-registry` volume)
- Cargo git repositories (`litebox-cargo-git` volume)

This means dependencies persist across container rebuilds, making subsequent builds faster.

## Troubleshooting

**Container build fails:**
- Ensure Docker has enough disk space (at least 10GB free)
- Try building with `docker build --no-cache` to force a clean build

**Slow first build:**
- The first build downloads and compiles all dependencies, which can take 10-15 minutes
- Subsequent builds will be much faster due to Docker layer caching

**VS Code can't connect to container:**
- Check that Docker is running
- Try rebuilding the container: "Dev Containers: Rebuild Container"

## MCP Servers

### What are MCP Servers?

Model Context Protocol (MCP) servers enable AI assistants like GitHub Copilot to interact with external systems and tools. They provide a standardized way for AI models to access GitHub repositories, file systems, and other resources.

### Pre-installed Servers

**GitHub MCP Server** (`github-mcp-server`)
- **Purpose**: Provides comprehensive GitHub API access for AI assistants
- **Capabilities**:
  - Repository management (clone, create, list repositories)
  - Issue and pull request operations (create, update, search, manage)
  - Code search and analysis across repositories
  - Workflow automation (commits, branches, merges)
  - GitHub-specific queries and metadata access
- **Usage**: Automatically available to GitHub Copilot and other MCP-compatible AI assistants
- **Documentation**: [github-mcp-server on npm](https://www.npmjs.com/package/github-mcp-server)

### Verifying MCP Server Installation

To verify MCP servers are installed correctly in the devcontainer:

```bash
# Check Node.js and npm versions
node --version
npm --version

# Check GitHub MCP server installation
which github-mcp-server
github-mcp-server --version

# List globally installed npm packages
npm list -g --depth=0
```

### Using MCP Servers with GitHub Copilot

When using this devcontainer with GitHub Copilot:

1. The MCP servers are automatically available to GitHub Copilot Workspace
2. You can interact with GitHub repositories through natural language
3. Copilot can perform actions like:
   - Searching code across the repository
   - Creating and managing issues and pull requests
   - Analyzing repository structure and dependencies
   - Automating common Git workflows

### Adding More MCP Servers

If you need additional MCP servers, you can:

1. **Temporarily** (for current container session):
   ```bash
   npm install -g <mcp-server-package>
   ```

2. **Permanently** (add to Dockerfile):
   - Edit `.devcontainer/Dockerfile`
   - Add installation line: `RUN npm install -g <mcp-server-package>`
   - Rebuild the container

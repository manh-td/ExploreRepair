import argparse

from mcp.server.fastmcp import FastMCP

from src.harnesses.docker import docker_exec_bash


def build_server(container_name: str, cwd: str) -> FastMCP:
    server = FastMCP("patcheval")

    @server.tool(description="Run a shell command inside the repository")
    def bash(command: str) -> str:
        result = docker_exec_bash(container_name, cwd, command)
        return (result.stdout + result.stderr) or f"(no output, exit code {result.returncode})"

    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="stdio MCP server exposing one bash tool inside a container")
    parser.add_argument("--container", required=True)
    parser.add_argument("--cwd", default="/workspace")
    args = parser.parse_args()
    build_server(args.container, args.cwd).run("stdio")

"""SIFT-MCP — typed read-only forensic tool server.

W2 deliverable. Currently a stub entrypoint so the install can be smoke-tested.
"""

import typer

app = typer.Typer(help="SIFT-OWL MCP server (typed read-only DFIR functions).")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    case: str = typer.Option(None, "--case", help="Path to case root."),
    transport: str = typer.Option(
        "stdio", "--transport", help="MCP transport (stdio | sse)."
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    typer.echo(f"sift-mcp stub — case={case} transport={transport}")
    typer.echo("MCP function inventory and stdio loop will be wired in W2.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

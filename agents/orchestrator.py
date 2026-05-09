"""SIFT-OWL orchestrator — LangGraph state machine.

W3 deliverable. Currently a stub entrypoint so the install can be smoke-tested.
"""

import typer

app = typer.Typer(help="SIFT-OWL autonomous DFIR orchestrator.")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    case: str = typer.Option(..., "--case", help="Path to case root."),
    max_iterations: int = typer.Option(3, "--max-iterations"),
    wall_clock_min: int = typer.Option(15, "--wall-clock-min"),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    typer.echo(
        f"sift-owl stub — case={case} max_iterations={max_iterations} "
        f"wall_clock_min={wall_clock_min}"
    )
    typer.echo("Orchestrator + specialists will be wired in W3.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

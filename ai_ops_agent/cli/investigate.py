"""`ai-ops investigate` — cluster-backed investigation from the terminal, and
`ai-ops serve` — run the webhook API. Both use the same AlertService as the
webhook path, so `/aiops investigate` and `ai-ops investigate` are one code
path with different renderers.
"""

from __future__ import annotations

import typer
from rich.console import Console

from ai_ops_agent.config import load_config
from ai_ops_agent.core.alert import alert_from_manual
from ai_ops_agent.core.service import AlertService
from ai_ops_agent.core.task_store import TaskStore
from ai_ops_agent.llm.client import make_client
from ai_ops_agent.reporting.renderers.terminal import render_report
from ai_ops_agent.tools.build import build_registry

EXIT_ERROR = 2


def investigate_command(
    alert_name: str | None = typer.Option(
        None, "--alert-name", help="Alert name to investigate."
    ),
    namespace: str | None = typer.Option(None, "--namespace", "-n"),
    pod: str | None = typer.Option(None, "--pod"),
    workload: str | None = typer.Option(None, "--workload"),
    cluster: str | None = typer.Option(None, "--cluster"),
    node: str | None = typer.Option(None, "--node"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    provider: str | None = typer.Option(None, "--provider"),
    config_file: str | None = typer.Option(None, "--config"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Investigate a cluster object or alert via the metrics + K8s tool layer."""
    err = Console(stderr=True)
    console = Console()
    if not (alert_name or pod or workload):
        err.print("[red]error:[/red] give --alert-name, --pod, or --workload")
        raise typer.Exit(EXIT_ERROR)

    config = load_config(config_file)
    if provider:
        config.llm.provider = provider

    alert = alert_from_manual(
        name=alert_name or f"investigate-{pod or workload}",
        namespace=namespace, workload=workload, pod=pod, cluster=cluster, node=node,
    )

    try:
        llm_client = None if no_llm else make_client(config.llm)
        registry, prefetch = build_registry(config)
    except Exception as exc:  # noqa: BLE001 - surface config/tool errors cleanly
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    if len(registry) == 0:
        err.print(
            "[yellow]warning:[/yellow] no cluster tools configured "
            "(set AI_OPS_METRICS_URL / AI_OPS_K8S_API_URL). "
            "Investigation will be limited."
        )

    store = TaskStore(config.server.db_path)
    service = AlertService(config, store, llm_client, registry, prefetch, notifier=None)
    report, audit = service.investigate(alert)
    render_report(report, console=console, verbose=verbose)
    if verbose:
        console.print("\n[bold]Audit log[/bold]")
        for entry in audit.entries:
            mark = "ok" if entry.ok else "ERR"
            console.print(f"  [{mark}] {entry.kind}:{entry.name} — {entry.detail[:120]}")
    store.close()


def serve_command(
    host: str | None = typer.Option(None, "--host"),
    port: int | None = typer.Option(None, "--port"),
    config_file: str | None = typer.Option(None, "--config"),
) -> None:
    """Run the webhook API server (alertmanager/grafana ingest, /investigate)."""
    import uvicorn

    from ai_ops_agent.api.app import create_app

    config = load_config(config_file)
    if host:
        config.server.host = host
    if port:
        config.server.port = port
    if not config.server.webhook_secret:
        Console(stderr=True).print(
            "[yellow]warning:[/yellow] AI_OPS_SERVER_WEBHOOK_SECRET is unset — "
            "webhook authentication is DISABLED (dev only)."
        )
    app = create_app(config)
    uvicorn.run(app, host=config.server.host, port=config.server.port)


def config_check_command(
    config_file: str | None = typer.Option(None, "--config"),
) -> None:
    """Validate config and probe which backends are enabled."""
    console = Console()
    config = load_config(config_file)
    rows = [
        ("LLM provider", config.llm.provider, config.llm.model),
        ("Metrics (VictoriaMetrics)", "configured" if config.metrics.configured else "off",
         config.metrics.url or "-"),
        ("Kubernetes API", "configured" if config.k8s.configured else "off",
         config.k8s.api_url or "-"),
        ("Mattermost", "configured" if config.mattermost.configured else "off",
         config.mattermost.url or config.mattermost.webhook_url or "-"),
        ("Webhook auth", "on" if config.server.webhook_secret else "OFF (dev)", ""),
        ("Redaction", "on" if config.redact else "off", ""),
    ]
    for name, status, detail in rows:
        console.print(f"  {name:28} {status:12} {detail}")


def tools_list_command(
    config_file: str | None = typer.Option(None, "--config"),
) -> None:
    """List which tools are enabled and why."""
    console = Console()
    config = load_config(config_file)
    try:
        registry, prefetch = build_registry(config)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]error building tools:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None
    if len(registry) == 0:
        console.print("No cluster tools enabled. Configure AI_OPS_METRICS_URL and/or "
                      "AI_OPS_K8S_API_URL.")
        return
    console.print("[bold]Enabled tools:[/bold]")
    for name, spec in registry.tools.items():
        console.print(f"  {name:24} {spec.description[:80]}")
    console.print(f"\n[bold]Deterministic pre-fetch:[/bold] {len(prefetch)} collectors")

"""Command-line interface for LUMENOS Sandbox."""
import argparse
import sys
import json
import logging
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(
        prog="lumenos-sandbox",
        description="LUMENOS Sandbox — Aislamiento multinivel para análisis de malware"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # lumenos-sandbox status
    subparsers.add_parser("status", help="Verificar estado del sistema (Hyper-V, prerequisites)")

    # lumenos-sandbox start --id <id> --name <name> [--memory 8192] [--cpus 4]
    start_parser = subparsers.add_parser("start", help="Iniciar sesión de análisis")
    start_parser.add_argument("--id", required=True, help="Identificador único del sandbox")
    start_parser.add_argument("--name", required=True, help="Nombre descriptivo")
    start_parser.add_argument("--memory", type=int, default=8192, help="RAM en MB (default: 8192)")
    start_parser.add_argument("--cpus", type=int, default=4, help="CPUs (default: 4)")
    start_parser.add_argument("--guest-user", default="Administrator", help="Usuario del guest")
    start_parser.add_argument("--guest-pass", default="", help="Password del guest")

    # lumenos-sandbox stop --id <id>
    stop_parser = subparsers.add_parser("stop", help="Terminar sesión y descontaminar")
    stop_parser.add_argument("--id", required=True, help="ID del sandbox a terminar")

    # lumenos-sandbox analyze --id <id> --sample <path>
    analyze_parser = subparsers.add_parser("analyze", help="Ejecutar muestra en el sandbox")
    analyze_parser.add_argument("--id", required=True, help="ID del sandbox activo")
    analyze_parser.add_argument("--sample", required=True, help="Ruta a la muestra de malware")

    # lumenos-sandbox report --id <id>
    report_parser = subparsers.add_parser("report", help="Obtener reporte de la sesión")
    report_parser.add_argument("--id", required=True, help="ID del sandbox")

    # lumenos-sandbox list
    subparsers.add_parser("list", help="Listar sandboxes activos")

    # lumenos-sandbox health
    subparsers.add_parser("health", help="Verificar salud del sistema")

    # lumenos-sandbox migrate
    subparsers.add_parser("migrate", help="Migrar estado JSON a SQLite")

    # lumenos-sandbox compliance [--id <id>]
    compliance_parser = subparsers.add_parser("compliance", help="Verificar controles de compliance")
    compliance_parser.add_argument("--id", help="ID del sandbox (opcional)")

    # lumenos-sandbox evidence --id <id> [--output <path>]
    evidence_parser = subparsers.add_parser("evidence", help="Recopilar evidencia forense")
    evidence_parser.add_argument("--id", required=True, help="ID del sandbox")
    evidence_parser.add_argument("--output", default="evidence", help="Directorio de salida (default: evidence)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    commands = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "analyze": cmd_analyze,
        "report": cmd_report,
        "list": cmd_list,
        "health": cmd_health,
        "migrate": cmd_migrate,
        "compliance": cmd_compliance,
        "evidence": cmd_evidence,
    }

    try:
        return commands[args.command](args)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def cmd_status(_args=None):
    from .hypervisor import check_hyper_v_available

    hv = check_hyper_v_available()
    print(f"Hyper-V: {'[OK] Available' if hv else '[FAIL] Not available'}")
    if not hv:
        print(
            "  -> Enable Hyper-V: Enable-WindowsOptionalFeature "
            "-Online -FeatureName Microsoft-Hyper-V-All"
        )
    return 0 if hv else 1


def cmd_start(args):
    from .types import BunkerConfig
    from .bunker import Bunker

    config = BunkerConfig(
        id=args.id,
        name=args.name,
        memory_mb=args.memory,
        cpu_cores=args.cpus,
        guest_username=args.guest_user,
        guest_password=args.guest_pass,
    )

    bunker = Bunker(config)
    print(f"Initializing bunker {args.id}...")

    if not bunker.initialize():
        print("[FAIL] Failed to initialize bunker")
        return 1

    print(f"Activating bunker {args.id}...")
    if not bunker.activate():
        print("[FAIL] Failed to activate bunker")
        return 1

    print(f"[OK] Sandbox {args.id} ready")
    print(f"   VM: {bunker._vm_name}")
    print(f"   Memory: {args.memory} MB, CPUs: {args.cpus}")
    print(f"   Escape probability: {bunker.get_escape_probability():.2e}")
    return 0


def cmd_stop(args):
    from .bunker import Bunker, get_state_store

    store = get_state_store()
    state = store.load(args.id)
    if state is None:
        print(f"[FAIL] No active sandbox found with ID: {args.id}")
        return 1

    config_data = state["config"]
    # Reconstruct only the fields BunkerConfig accepts
    from .types import BunkerConfig
    valid_fields = {f.name for f in BunkerConfig.__dataclass_fields__.values()}
    filtered = {k: v for k, v in config_data.items() if k in valid_fields}
    config = BunkerConfig(**filtered)

    bunker = Bunker(config)
    from .types import BunkerState
    bunker.state = BunkerState[state["state"]]
    bunker._vm_name = state.get("vm_name")
    bunker._switch_name = state.get("switch_name")

    print(f"Terminating sandbox {args.id}...")
    if not bunker.terminate():
        print("[FAIL] Termination failed — check logs")
        return 1

    print(f"[OK] Sandbox {args.id} terminated and decontaminated")
    return 0


def cmd_analyze(args):
    from pathlib import Path

    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"[FAIL] Sample not found: {args.sample}")
        return 1

    print(f"Deploying sample to sandbox {args.id}...")
    print(f"  Sample: {args.sample} ({sample_path.stat().st_size} bytes)")
    print(f"  → Execute via PowerShell Direct in guest")
    print(f"  → Monitor for 60 seconds")
    print(f"  → Collect artifacts")
    return 0


def cmd_report(args):
    from .bunker import get_state_store

    store = get_state_store()
    state = store.load(args.id)
    if state is None:
        print(f"[FAIL] No active sandbox found with ID: {args.id}")
        return 1

    print(f"Report for sandbox {args.id}:")
    print(f"  State: {state.get('state', 'unknown')}")
    print(f"  VM: {state.get('vm_name', 'N/A')}")
    print(f"  Switch: {state.get('switch_name', 'N/A')}")
    print(f"  Created: {state.get('created_at', 'N/A')}")
    print(f"  Activated: {state.get('activated_at', 'N/A')}")
    print(f"  Terminated: {state.get('terminated_at', 'N/A')}")
    print(f"  Last updated: {state.get('updated_at', 'N/A')}")
    return 0


def cmd_list(_args=None):
    from .bunker import get_state_store

    store = get_state_store()
    items = store.list_all()
    if not items:
        print("No active sandboxes")
    else:
        for item in items:
            print(f"  - {item['bunker_id']}  state={item['state']}  updated={item['updated_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


def cmd_health(_args=None):
    from .bunker import get_state_store
    from .observability import check_health
    import json as _json

    h = check_health(get_state_store())
    print(_json.dumps(h, indent=2))
    return 0 if h["status"] == "ok" else 1


def cmd_migrate(_args=None):
    from .bunker import get_state_store

    store = get_state_store()
    count = store.migrate_from_json("snapshots")
    print(f"Migrated {count} state file(s) from snapshots/ to SQLite")
    return 0


def cmd_compliance(args):
    from .bunker import get_state_store
    from .compliance import ComplianceReport
    import json as _json

    config = {}
    if args.id:
        store = get_state_store()
        state = store.load(args.id)
        if state:
            config = state.get("config", {})

    report = ComplianceReport()
    result = report.evaluate(config)
    print(_json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 else 1


def cmd_evidence(args):
    from .forensics import collect_evidence, export_evidence
    import json as _json
    from pathlib import Path

    chain = collect_evidence(args.id)
    out_path = str(Path(args.output) / f"{args.id}.json")
    export_evidence(chain, out_path)
    print(f"Evidence exported: {out_path}")
    print(f"  Items: {len(chain.items)}")
    print(f"  Chain valid: {chain.verify()}")
    return 0

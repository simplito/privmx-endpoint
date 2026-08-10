from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import e2e_common

requests = None
MongoClient = None

DOCKER_NETWORK = "endpoint_e2e_testing_network"
BACKEND_READY_TIMEOUT_SECONDS = 5


@dataclass
class BridgeInfo:
    host_port: int
    container_name: str
    mongo_url: str
    db: Any
    mongo_client: Any


def load_runtime_dependencies() -> None:
    global requests, MongoClient

    import requests as requests_module
    from pymongo import MongoClient as mongo_client_class

    requests = requests_module
    MongoClient = mongo_client_class


def check_backend_ready() -> None:
    hint = "Start it with 'docker compose up -d' from the test/ directory (see test/compose.yaml)."

    try:
        client = MongoClient(
            "mongodb://localhost:27017/?directConnection=true",
            serverSelectionTimeoutMS=BACKEND_READY_TIMEOUT_SECONDS * 1000,
        )
        client.admin.command("ping")
        client.close()
    except Exception as exc:
        raise RuntimeError(f"MongoDB is not reachable at localhost:27017. {hint}") from exc

    rc, _, _ = e2e_common.run_command(["docker", "network", "inspect", DOCKER_NETWORK])
    if rc != 0:
        raise RuntimeError(f"Docker network '{DOCKER_NETWORK}' was not found. {hint}")


def print_container_logs(container_name: str) -> None:
    try:
        print(f"\n--- LOGS FOR {container_name} ---")
        rc, stdout, stderr = e2e_common.run_command(["docker", "logs", "--tail", "50", container_name])
        if rc == 0:
            print(e2e_common.decode_output(stdout))
        else:
            print(f"Could not retrieve container logs (exit {rc}): {e2e_common.decode_output(stderr)}")
        print("--- END LOGS ---\n")
    except Exception:
        print("Could not retrieve container logs.")


def load_mongo_dataset(db: Any, dataset_path: str) -> None:
    full_path = Path(dataset_path) / "mongo_collections"
    if not full_path.exists():
        return

    for file_path in sorted(full_path.iterdir()):
        if file_path.suffix != ".json":
            continue

        collection_name = file_path.stem
        try:
            with open(file_path, "r", encoding="utf-8") as file_handle:
                docs = json.load(file_handle)

            if isinstance(docs, list) and docs:
                db[collection_name].insert_many(docs)
        except Exception as exc:
            print(f"Failed to load {file_path.name}: {exc}")


def load_bridge_dataset(dataset_path: str, bridge_container_name: str) -> None:
    full_path = Path(dataset_path) / "storage"
    if not full_path.exists():
        return

    staging_dir = Path(tempfile.mkdtemp(prefix="privmx_e2e_storage_"))
    try:
        staged_storage = staging_dir / "storage"
        shutil.copytree(full_path, staged_storage)
        for entry in (staged_storage, *staged_storage.rglob("*")):
            os.chmod(entry, 0o777)
        e2e_common.require_command_success(
            ["docker", "cp", str(staged_storage), f"{bridge_container_name}:/work/privmx-bridge"],
            action="Loading bridge dataset",
        )
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def wait_for_server_ready(port: int, container_name: str, timeout_seconds: int = 30) -> None:
    url = f"http://localhost:{port}/privmx-configuration.json"
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        try:
            stdout, _ = e2e_common.require_command_success(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                action=f"Checking container state for {container_name}",
            )
            is_running = e2e_common.decode_output(stdout).strip()
            if is_running != "true":
                print_container_logs(container_name)
                raise RuntimeError(f"Container {container_name} stopped unexpectedly.")
        except Exception as exc:
            raise RuntimeError(f"Container check failed: {exc}") from exc

        try:
            response = requests.get(url, timeout=2)
            if response.ok:
                return
        except Exception:
            pass

        time.sleep(0.2)

    print_container_logs(container_name)
    raise RuntimeError(f"Server failed to start on port {port} within {timeout_seconds}s")


def create_bridge_docker(index: int, docker_image: str) -> BridgeInfo:
    host_port = 3001 + index
    container_name = f"privmx_e2e_worker_{index}"
    db_name = f"privmx_e2e_db_{index}"
    internal_mongo_url = f"mongodb://test_mongodb:27017/{db_name}"
    local_mongo_url = f"mongodb://localhost:27017/{db_name}?directConnection=true"

    env_list = [
        "PRIVMX_PORT=3000",
        f"PRIVMX_MONGO_URL={internal_mongo_url}",
        "PRIVMX_WORKERS=1",
        "PMX_MIGRATION=Migration_069_Indexes_for_session",
        "PMX_MEDIA_SERVER_ALLOW_SELF_SIGNED_CERTS=true",
        "PMX_STREAM_ENABLED=true",
        "PRIVMX_HOSTNAME=0.0.0.0",
        "PMX_STREAMS_MEDIA_SERVER=janus",
        "PMX_STREAMS_TURN_SERVER=turn:127.0.0.1:3478",
        "PMX_STREAMS_TURN_SERVER_SECRET=my-secret-key",
    ]

    mongo_client = MongoClient(local_mongo_url)
    e2e_common.run_command(["docker", "rm", "-f", container_name])
    mongo_client.drop_database(db_name)

    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-p",
        f"{host_port}:3000",
        "--network",
        DOCKER_NETWORK,
        "--label",
        "com.docker.compose.project=endpoint_e2e_testing",
        "--label",
        "com.docker.compose.service=e2e_worker",
        "--label",
        "com.docker.compose.oneoff=False",
    ]
    for env_var in env_list:
        cmd.extend(["-e", env_var])
    cmd.extend(
        [
            "--add-host",
            "host.docker.internal:host-gateway",
            docker_image,
        ]
    )

    e2e_common.require_command_success(cmd, action=f"Starting bridge container {container_name}")
    wait_for_server_ready(host_port, container_name)

    return BridgeInfo(
        host_port=host_port,
        container_name=container_name,
        mongo_url=internal_mongo_url,
        db=mongo_client[db_name],
        mongo_client=mongo_client,
    )


def destroy_bridge_docker(bridge_info: BridgeInfo) -> None:
    try:
        bridge_info.mongo_client.drop_database(bridge_info.db.name)
        bridge_info.mongo_client.close()
    except Exception:
        pass
    e2e_common.run_command(["docker", "rm", "-f", bridge_info.container_name])


def prepare_bridge_context(bridge_info: BridgeInfo, dataset_dir_path: str) -> None:
    container_name = bridge_info.container_name
    host_port = bridge_info.host_port

    try:
        e2e_common.run_command(["docker", "stop", container_name])
        e2e_common.require_command_success(["docker", "start", container_name], action=f"Starting {container_name}")
        wait_for_server_ready(host_port, container_name)

        e2e_common.run_command(["docker", "stop", container_name])

        load_mongo_dataset(bridge_info.db, dataset_dir_path)
        load_bridge_dataset(dataset_dir_path, container_name)

        e2e_common.require_command_success(["docker", "start", container_name], action=f"Restarting {container_name}")
        wait_for_server_ready(host_port, container_name)
    except Exception:
        e2e_common.run_command(["docker", "stop", container_name])
        raise

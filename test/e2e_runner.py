import json
import os
import subprocess
import sys
import datetime
import time
import threading
from pathlib import Path
from typing import List, Any, Callable, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import requests
from pymongo import MongoClient
from pymongo.database import Database
# ---- Type-like aliases ----

class BridgeInfo:
    def __init__(
        self,
        host_port: int,
        container_name: str,
        mongo_url: str,
        db: Database,
        mongo_client: MongoClient,
        docker_image: str,
        env_vars: str,
    ):
        self.host_port = host_port
        self.container_name = container_name
        self.mongo_url = mongo_url
        self.db = db
        self.mongo_client = mongo_client
        self.docker_image = docker_image
        self.env_vars = env_vars


class BridgeContext:
    def __init__(self, bridge_url: str, mongo_connection_string: str, db_name: str):
        self.bridge_url = bridge_url
        self.mongo_connection_string = mongo_connection_string
        self.db_name = db_name


class CliContext:
    def __init__(self, call: Callable[[str, Dict[str, Any]], Any]):
        self.call = call


class WorkerOptions:
    def __init__(self, docker_image: str):
        self.docker_image = docker_image

GTEST_BINARY = "./build/privmxplatform_test_e2e_CoreTest"

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

MAX_WORKERS = 4  
TIMEOUT_PER_TEST = 300    
RETRY_COUNT = 2
RETRY_DELAY = 5                
global DOCKER_INDEX

MONGO_URI = "mongodb://localhost:27017/"

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{timestamp}.log"

_log_lock = threading.Lock()

def log(msg: str):
    with _log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")

def run_command(cmd: str, timeout=None):
    # print(f"\033[90mExecuting : {cmd} \033[00m")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, b"", b"TIMEOUT"

def print_container_logs(container_name: str) -> None:
    try:
        print(f"\n--- LOGS FOR {container_name} ---")
        cmd = f"docker logs --tail 50 {container_name}"
        code, stdout, stderr = run_command(cmd)
        if code == 0:
            logs = stdout.decode("utf-8", errors="replace")
            print(logs)
        else:
            err = stderr.decode("utf-8", errors="replace")
            print(f"Could not retrieve container logs (exit {code}): {err}")
        print("--- END LOGS ---\n")
    except Exception:
        print("Could not retrieve container logs.")

def load_mongo_dataset(db: Database, dataset_path: str) -> None:
    full_path = os.path.join(dataset_path, "mongo_collections")
    if not os.path.exists(full_path):
        return

    for file_name in os.listdir(full_path):
        if not file_name.endswith(".json"):
            continue

        collection_name, _ = os.path.splitext(file_name)
        file_path = os.path.join(full_path, file_name)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                docs = json.load(f)

            if isinstance(docs, list) and len(docs) > 0:
                db[collection_name].insert_many(docs)
        except Exception as e:
            print(f"Failed to load {file_name}:", e)

def load_bridge_dataset(dataset_path: str, bridge_container_name: str) -> None:
    full_path = os.path.join(dataset_path, "storage")
    run_command(f"docker cp {full_path} {bridge_container_name}:/work/privmx-bridge")

def wait_for_server_ready(port: int, container_name: str, timeout_seconds: int = 10) -> None:
    url = f"http://localhost:{port}/privmx-configuration.json"
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        try:
            cmd = f"docker inspect -f '{{{{.State.Running}}}}' {container_name}"
            code, stdout, stderr = run_command(cmd)
            if code != 0:
                err = stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"Container check failed: {err}")

            is_running = stdout.decode("utf-8").strip()
            if is_running != "true":
                print_container_logs(container_name)
                raise RuntimeError(f"Container {container_name} stopped unexpectedly.")
        except Exception as e:
            raise RuntimeError(f"Container check failed: {e}")

        # Check if server responds
        try:
            res = requests.get(url, timeout=2)
            if res.ok:
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
    local_mongo_url = f"mongodb://localhost:27017/{db_name}" + "?directConnection=true"
    

    env_list = [
        "PRIVMX_PORT=3000",
        f"PRIVMX_MONGO_URL={internal_mongo_url}",
        "PRIVMX_WORKERS=1",
        "PMX_MIGRATION=Migration_069_Indexes_for_session",
        "PMX_STREAM_ENABLED=true",
        "PRIVMX_HOSTNAME=0.0.0.0",
        "PMX_STREAMS_MEDIA_SERVER=janus",
        "PMX_STREAMS_TURN_SERVER=turn:127.0.0.1:3478",
        "PMX_STREAMS_TURN_SERVER_SECRET=my-secret-key",
    ]
    env_vars = " ".join(f"-e {e}" for e in env_list)

    client = MongoClient(local_mongo_url)
    try:
        run_command(f"docker rm -f {container_name}")
    except subprocess.CalledProcessError:
        pass
    client.drop_database(db_name)
    db = client[db_name]
    cmd = (
        f"docker run -d --name {container_name} -p {host_port}:3000 "
        f"--network endpoint_e2e_testing_network "
        f"--label com.docker.compose.project=endpoint_e2e_testing "
        f"--label com.docker.compose.service=e2e_worker "
        f"--label com.docker.compose.oneoff=False "
        f"{env_vars} "
        f"--add-host=host.docker.internal:host-gateway "
        f"{docker_image}"
    )
    run_command(cmd)

    wait_for_server_ready(host_port, container_name)

    return BridgeInfo(
        host_port=host_port,
        container_name=container_name,
        mongo_url=internal_mongo_url,
        db=db,
        mongo_client=client,
        docker_image=docker_image,
        env_vars=env_vars,
    )

def destroy_bridge_docker(bridge_info: BridgeInfo) -> None:
    try:
        bridge_info.mongo_client.drop_database(bridge_info.db.name)
        bridge_info.mongo_client.close()
    except Exception:
        pass
    try:
        run_command(f"docker rm -f {bridge_info.container_name}")
    except subprocess.CalledProcessError:
        pass

def create_bridge_context(bridge_info: BridgeInfo, dataset_dir_path: str) -> BridgeContext:
    db = bridge_info.db
    container_name = bridge_info.container_name
    host_port = bridge_info.host_port
    mongo_url = bridge_info.mongo_url

    local_mongo_url = mongo_url.replace("test_mongodb", "localhost")

    try:
        try:
            run_command(f"docker stop {container_name}")
        except subprocess.CalledProcessError:
            pass

        run_command(f"docker start {container_name}")

        wait_for_server_ready(host_port, container_name)

        run_command(f"docker stop {container_name}")

        load_mongo_dataset(db, dataset_dir_path)
        load_bridge_dataset(dataset_dir_path, container_name)

        run_command(f"docker start {container_name}")
        wait_for_server_ready(host_port, container_name)

        return BridgeContext(
            bridge_url=f"http://localhost:{host_port}",
            mongo_connection_string=local_mongo_url,
            db_name=db.name,
        )
    except Exception:
        try:
            run_command(f"docker stop {container_name}")
        except subprocess.CalledProcessError:
            pass
        raise

def list_tests(test_file_path: str) -> List[str]:    
    return_code, out, err = run_command(f"{test_file_path} --gtest_list_tests")
    if return_code != 0:
        print(f"Failed to load tests list for {test_file_path}")
        print(f"Recived Error: ")
        print(err)
        sys.exit(1)
    tests = []
    suite = ""
    for line in out.splitlines():
        if not line.strip():
            continue
        if not line.startswith(b"  "):
            suite = line.strip().decode("utf-8")
        else:
            tests.append(f"{suite}{line.strip().decode("utf-8")}")
    return tests

def pre_test(index: int, dataset_dir_path: str, test_name: str) -> BridgeInfo:
    log(f"[PRE-TEST] {test_name}")
    bridge_info  = create_bridge_docker(index, "gitlab2.simplito.com:5050/teamserverdev/privmx-server-ee/privmx-bridge:6ed877ea")
    bridge_context = create_bridge_context(bridge_info, dataset_dir_path)
    return bridge_info

def post_test(test_name: str, bridge_info: str):
    log(f"[POST-TEST] {test_name}")
    destroy_bridge_docker(bridge_info)

def execute_test(test_file_path: str, test_name: str, init_file_path: str, bridge_info: BridgeInfo):
    
    rc, out, err = run_command(f"{test_file_path} -i {init_file_path} -b localhost:{bridge_info.host_port} --gtest_filter={test_name}", timeout=TIMEOUT_PER_TEST)
    log("=" * 80)
    
    log(out.decode("utf-8"))
    log(err.decode("utf-8"))
    if rc == 0:
        return True, rc, out, err
    return False, rc, out, err

def run_single_test(index: int, test_file_path: str, test_name: str, init_file_path: str, dataset_dir_path: str):
    try:
        for attempt in range(1, RETRY_COUNT + 2):
            bridge_info = pre_test(index, dataset_dir_path, test_name)
            print(f"Running: {test_name}")
            success, rc, out, err = execute_test(test_file_path, test_name, init_file_path, bridge_info)
            log(f"[TEST] {test_name} (attempt {attempt})")
            post_test(test_name, bridge_info)
            if success == True:
                return test_name, success, rc, out, err
            if attempt <= RETRY_COUNT:
                time.sleep(RETRY_DELAY)
        return test_name, success, rc, out, err
    except Exception as e:
        log(f"[ERROR] {test_name}: {e}")
        return test_name, False, -1, "", str(e)

def print_result(test, success, rc, out, err):
    if success:
        print(f"Success - {test}")
    else:
        print(f"Failed  - {test} (exit={rc})")
        print("----- STDOUT -----")
        print(out)
        print("----- STDERR -----")
        print(err)
        print("------------------")

def main(test_dir_path: str, init_file_path: str, dataset_dir_path):
    if not os.path.exists(test_dir_path):
        return

    failed = []
    for file_name in os.listdir(test_dir_path):
        if not file_name.startswith("test_e2e_"):
            continue
        file_path = os.path.join(test_dir_path, file_name)
        tests = list_tests(file_path)
        print(f"Found {len(tests)} tests in {file_path}")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(run_single_test, idx, file_path, test_name, init_file_path, dataset_dir_path)
                for idx, test_name in enumerate(tests)
            ]

            for future in as_completed(futures):
                test, success, rc, out, err = future.result()
                print_result(test, success, rc, out, err)
                if not success:
                    failed.append(test)

    print("\n=========================")
    print(f"log file    : {LOG_FILE}")
    print(f"failed tests: ", failed)
    print("=========================")
    return len(failed)

if __name__ == "__main__":
    args = sys.argv
    args.pop(0)
    if (len(args) != 3):
        print("recived args: ", args)
        print("required args: <tests_dir> <path_to_ini_file> <path_to_dataset_directory>")
        print("test files must starts with 'test_e2e_'")
        print("example usage: python3 e2e_runner.py build test_env/create_dataset/ServerData.ini test_env/create_dataset/Dataset")
        sys.exit(1)
    else:
        test_dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), args[0]))
        init_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), args[1]))
        dataset_dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), args[2]))
        sys.exit(main(test_dir_path, init_file_path, dataset_dir_path))


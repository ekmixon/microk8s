import os
import json
import shutil
import subprocess
import time
import string
import random
import datetime
from subprocess import check_output, CalledProcessError

import yaml
import socket


def try_set_file_permissions(file):
    """
    Try setting the ownership group and permission of the file

    :param file: full path and filename
    """

    os.chmod(file, 0o660)
    try:
        shutil.chown(file, group="microk8s")
    except LookupError:
        # not setting the group means only the current user can access the file
        pass


def remove_expired_token_from_file(file):
    """
    Remove expired token from the valid tokens set

    :param file: the file to be removed from
    """
    backup_file = f"{file}.backup"
    # That is a critical section. We need to protect it.
    # We are safe for now because flask serves one request at a time.
    with open(backup_file, "w") as back_fp:
        with open(file, "r") as fp:
            for line in fp:
                if is_token_expired(line):
                    continue
                back_fp.write(f"{line}")

    try_set_file_permissions(backup_file)
    shutil.copyfile(backup_file, file)


def remove_token_from_file(token, file):
    """
    Remove a token from the valid tokens set

    :param token: the token to be removed
    :param file: the file to be removed from
    """
    backup_file = f"{file}.backup"
    # That is a critical section. We need to protect it.
    # We are safe for now because flask serves one request at a time.
    with open(backup_file, "w") as back_fp:
        with open(file, "r") as fp:
            for line in fp:
                # Not considering cluster tokens with expiry in this method.
                if "|" not in line and line.strip() == token:
                    continue
                back_fp.write(f"{line}")

    try_set_file_permissions(backup_file)
    shutil.copyfile(backup_file, file)


def is_token_expired(token_line):
    """
    Checks if the token in the file is expired, when using the TTL based.

    :returns: True if the token is expired, otherwise False
    """
    if "|" in token_line:
        expiry = token_line.strip().split("|")[1]
        if int(round(time.time())) > int(expiry):
            return True

    return False


def get_callback_token():
    """
    Generate a token and store it in the callback token file

    :returns: the token
    """
    snapdata_path = os.environ.get("SNAP_DATA")
    callback_token_file = f"{snapdata_path}/credentials/callback-token.txt"
    if os.path.exists(callback_token_file):
        with open(callback_token_file) as fp:
            token = fp.read()
    else:
        token = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(64))
        with open(callback_token_file, "w") as fp:
            fp.write(f"{token}\n")
        try_set_file_permissions(callback_token_file)

    return token


def is_node_running_dqlite():
    """
    Check if we should use the dqlite joining process (join api version 2.0)

    :returns: True if dqlite is to be used, otherwise False
    """
    ha_lock = os.path.expandvars("${SNAP_DATA}/var/lock/ha-cluster")
    return os.path.isfile(ha_lock)


def is_node_dqlite_worker():
    """
    Check if this is a worker only node

    :returns: True if this is a worker node, otherwise False
    """
    ha_lock = os.path.expandvars("${SNAP_DATA}/var/lock/ha-cluster")
    clustered_lock = os.path.expandvars("${SNAP_DATA}/var/lock/clustered.lock")
    traefik_lock = os.path.expandvars("${SNAP_DATA}/var/lock/no-traefik")
    return (
        os.path.isfile(ha_lock)
        and os.path.isfile(clustered_lock)
        and not os.path.exists(traefik_lock)
    )


def is_low_memory_guard_enabled():
    """
    Check if the low memory guard is enabled on this Node

    :returns: True if enabled, otherwise False
    """
    lock = os.path.expandvars("${SNAP_DATA}/var/lock/low-memory-guard.lock")
    return os.path.isfile(lock)


def get_dqlite_port():
    """
    What is the port dqlite listens on

    :return: the dqlite port
    """
    # We get the dqlite port from the already existing deployment
    snapdata_path = os.environ.get("SNAP_DATA")
    cluster_dir = f"{snapdata_path}/var/kubernetes/backend"
    dqlite_info = f"{cluster_dir}/info.yaml"
    port = 19001
    if os.path.exists(dqlite_info):
        with open(dqlite_info) as f:
            data = yaml.safe_load(f)
        if "Address" in data:
            port = data["Address"].split(":")[1]

    return port


def get_cluster_agent_port():
    """
    What is the cluster agent port

    :return: the port
    """
    cluster_agent_port = "25000"
    snapdata_path = os.environ.get("SNAP_DATA")
    filename = f"{snapdata_path}/args/cluster-agent"
    with open(filename) as fp:
        for line in fp:
            if line.startswith("--bind"):
                port_parse = line.split(" ")
                port_parse = port_parse[-1].split("=")
                port_parse = port_parse[-1].split(":")
                if len(port_parse) > 1:
                    cluster_agent_port = port_parse[1].rstrip()
    return cluster_agent_port


def get_control_plane_nodes_internal_ips():
    """
    Return the internal IP of the nodes labeled running the control plane.

    :return: list of node internal IPs
    """
    snap_path = os.environ.get("SNAP")
    nodes_info = subprocess.check_output(
        f"{snap_path}/microk8s-kubectl.wrapper get no -o json -l node.kubernetes.io/microk8s-controlplane=microk8s-controlplane".split()
    )

    info = json.loads(nodes_info.decode())
    node_ips = []
    for node_info in info["items"]:
        node_ip = get_internal_ip_from_get_node(node_info)
        node_ips.append(node_ip)
    return node_ips


def get_internal_ip_from_get_node(node_info):
    """
    Retrieves the InternalIp returned by kubectl get no -o json
    """
    for status_addresses in node_info["status"]["addresses"]:
        if status_addresses["type"] == "InternalIP":
            return status_addresses["address"]


def is_same_server(hostname, ip):
    """
    Check if the hostname is the same as the current node's hostname
    """
    try:
        hname, _, _ = socket.gethostbyaddr(ip)
        if hname == hostname:
            return True
    except socket.error:
        # Ignore any unresolvable IP by host, surely this is not from the same node.
        pass

    return False


def apply_cni_manifest(timeout_insec=60):
    """
    Apply the CNI yaml. If applying the manifest fails an exception is raised.
    :param timeout_insec: Try up to timeout seconds to apply the manifest.
    """
    yaml = f'{os.environ.get("SNAP_DATA")}/args/cni-network/cni.yaml'
    snap_path = os.environ.get("SNAP")
    cmd = f"{snap_path}/microk8s-kubectl.wrapper apply -f {yaml}"
    deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout_insec)
    while True:
        try:
            check_output(cmd.split()).strip().decode("utf8")
            break
        except CalledProcessError as err:
            output = err.output.strip().decode("utf8").replace("\\n", "\n")
            print(f"Applying {yaml} failed with {output}")
            if datetime.datetime.now() > deadline:
                raise
            print(f"Retrying {cmd}")
            time.sleep(3)


def cni_is_patched():
    """
    Detect if the cni.yaml manifest already has the hint for detecting nodes routing paths
    :return: True if calico knows where the rest of the nodes are.
    """
    yaml = f'{os.environ.get("SNAP_DATA")}/args/cni-network/cni.yaml'
    with open(yaml) as f:
        return "can-reach" in f.read()


def patch_cni(ip):
    """
    Patch the cni.yaml manifest with the proper hint on where the rest of the nodes are
    :param ip: The IP another k8s node has.
    """
    cni_yaml = f'{os.environ.get("SNAP_DATA")}/args/cni-network/cni.yaml'
    backup_file = f"{cni_yaml}.backup"
    with open(backup_file, "w") as back_fp:
        with open(cni_yaml, "r") as fp:
            for line in fp:
                if "first-found" in line:
                    line = line.replace("first-found", f"can-reach={ip}")
                back_fp.write(f"{line}")

    try_set_file_permissions(backup_file)
    shutil.copyfile(backup_file, cni_yaml)


def try_initialise_cni_autodetect_for_clustering(ip, apply_cni=True):
    """
    Try to initialise the calico route autodetection based on the IP
    provided, see https://docs.projectcalico.org/networking/ip-autodetection.
    If the cni manifest got changed by default it gets reapplied.
    :param ip: The IP another k8s node has.
    :param apply_cni: Should we apply the the manifest
    """
    if cni_is_patched():
        return True

    patch_cni(ip)
    if apply_cni:
        apply_cni_manifest()


def is_kubelite():
    """
    Do we run kubelite?
    """
    snap_data = os.environ.get("SNAP_DATA")
    if not snap_data:
        snap_data = "/var/snap/microk8s/current/"
    kubelite_lock = f"{snap_data}/var/lock/lite.lock"
    return os.path.exists(kubelite_lock)


def service(operation, service_name):
    """
    Restart a service. Handle case where kubelite is enabled.

    :param service_name: The service name
    :param operation: Operation to perform on the service
    """
    if (
        service_name
        in ["apiserver", "proxy", "kubelet", "scheduler", "controller-manager"]
        and is_kubelite()
    ):
        subprocess.check_call(f"snapctl {operation} microk8s.daemon-kubelite".split())
    else:
        subprocess.check_call(
            f"snapctl {operation} microk8s.daemon-{service_name}".split()
        )


def mark_no_cert_reissue():
    """
    Mark a node as being part of a cluster that should not re-issue certs
    on network changes
    """
    snap_data = os.environ.get("SNAP_DATA")
    lock_file = f"{snap_data}/var/lock/no-cert-reissue"
    open(lock_file, "a").close()
    os.chmod(lock_file, 0o700)


def unmark_no_cert_reissue():
    """
    Unmark a node as being part of a cluster. The node should now re-issue certs
    on network changes
    """
    snap_data = os.environ.get("SNAP_DATA")
    lock_file = f"{snap_data}/var/lock/no-cert-reissue"
    if os.path.exists(lock_file):
        os.unlink(lock_file)


def restart_all_services():
    """
    Restart all services
    """
    snap_path = os.environ.get("SNAP")
    waits = 10
    while waits > 0:
        try:
            subprocess.check_call(
                f"{snap_path}/microk8s-stop.wrapper".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            break
        except subprocess.CalledProcessError:
            time.sleep(5)
            waits -= 1
    waits = 10
    while waits > 0:
        try:
            subprocess.check_call(
                f"{snap_path}/microk8s-start.wrapper".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            break
        except subprocess.CalledProcessError:
            time.sleep(5)
            waits -= 1


def get_token(name, tokens_file="known_tokens.csv"):
    """
    Get token from known_tokens file

    :param name: the name of the node
    :param tokens_file: the file where the tokens should go
    :returns: the token or None(if name doesn't exist)
    """
    snapdata_path = os.environ.get("SNAP_DATA")
    file = f"{snapdata_path}/credentials/{tokens_file}"
    with open(file) as fp:
        for line in fp:
            if name in line:
                parts = line.split(",")
                return parts[0].rstrip()
    return None

#!/usr/bin/python3
import json
import os
import shutil
import subprocess
import sys

import click
import netifaces

from common.utils import (
    try_set_file_permissions,
    is_node_running_dqlite,
)

snapdata_path = os.environ.get("SNAP_DATA")
snap_path = os.environ.get("SNAP")
callback_tokens_file = f"{snapdata_path}/credentials/callback-tokens.txt"

cluster_dir = f"{snapdata_path}/var/kubernetes/backend"


def remove_dqlite_node(node, force=False):
    try:
        # Make sure this node exists
        node_info = subprocess.check_output(
            f"{snap_path}/microk8s-kubectl.wrapper get no {node} -o json".split()
        )

        info = json.loads(node_info.decode())
        node_address = next(
            (
                a["address"]
                for a in info["status"]["addresses"]
                if a["type"] == "InternalIP"
            ),
            None,
        )

        if not node_address:
            print(f"Node {node} is not part of the cluster.")
            exit(1)

        node_ep = None
        my_ep, other_ep = get_dqlite_endpoints()
        for ep in other_ep:
            if ep.startswith(f"{node_address}:"):
                node_ep = ep

        if node_ep:
            if force:
                delete_dqlite_node([node_ep], my_ep)
            else:
                print(
                    f"Removal failed. Node {node} is registered with dqlite. Please, run first 'microk8s leave' on the departing node. \nIf the node is not available anymore and will never attempt to join the cluster in the future use the '--force' flag \nto unregister the node while removing it."
                )

                exit(1)

    except subprocess.CalledProcessError:
        print(f"Node {node} does not exist in Kubernetes.")
        if force:
            print(f"Attempting to remove {node} from dqlite.")
            # Make sure we do not have the node in dqlite.
            # We assume the IP is provided to denote the
            my_ep, other_ep = get_dqlite_endpoints()
            for ep in other_ep:
                if ep.startswith(f"{node}:"):
                    print("Removing node entry found in dqlite.")
                    delete_dqlite_node([ep], my_ep)
        exit(1)

    remove_node(node)


def remove_node(node):
    try:
        # Make sure this node exists
        subprocess.check_call(
            f"{snap_path}/microk8s-kubectl.wrapper get no {node}".split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    except subprocess.CalledProcessError:
        print(f"Node {node} does not exist.")
        exit(1)

    remove_kubelet_token(node)
    remove_callback_token(node)
    subprocess.check_call(
        f"{snap_path}/microk8s-kubectl.wrapper delete no {node}".split(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def remove_kubelet_token(node):
    """
    Remove a token for a node in the known tokens

    :param node: the name of the node
    """
    file = f"{snapdata_path}/credentials/known_tokens.csv"
    backup_file = f"{file}.backup"
    token = f"system:node:{node}"
    # That is a critical section. We need to protect it.
    with open(backup_file, "w") as back_fp:
        with open(file, "r") as fp:
            for line in fp:
                if token in line:
                    continue
                back_fp.write(f"{line}")

    try_set_file_permissions(backup_file)
    shutil.copyfile(backup_file, file)


def get_dqlite_endpoints():
    """
    Return the endpoints the current node has on dqlite and the endpoints of the rest of the nodes.

    :return: two lists with the endpoints
    """
    out = subprocess.check_output(
        "{snappath}/bin/dqlite -s file://{dbdir}/cluster.yaml -c {dbdir}/cluster.crt "
        "-k {dbdir}/cluster.key -f json k8s .cluster".format(
            snappath=snap_path, dbdir=cluster_dir
        ).split()
    )
    data = json.loads(out.decode())
    ep_addresses = [ep["Address"] for ep in data]
    local_ips = []
    for interface in netifaces.interfaces():
        if netifaces.AF_INET not in netifaces.ifaddresses(interface):
            continue
        local_ips.extend(
            link["addr"]
            for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]
        )

    my_ep = []
    other_ep = []
    for ep in ep_addresses:
        found = False
        for ip in local_ips:
            if f"{ip}:" in ep:
                my_ep.append(ep)
                found = True
        if not found:
            other_ep.append(ep)

    return my_ep, other_ep


def delete_dqlite_node(delete_node, dqlite_ep):
    if len(delete_node) <= 0 or "127.0.0.1" in delete_node[0]:
        return
    for ep in dqlite_ep:
        try:
            cmd = (
                "{snappath}/bin/dqlite -s file://{dbdir}/cluster.yaml -c {dbdir}/cluster.crt "
                "-k {dbdir}/cluster.key -f json k8s".format(
                    snappath=snap_path, dbdir=cluster_dir
                ).split()
            )
            cmd.append(f".remove {delete_node[0]}")
            subprocess.check_output(cmd)
            break
        except Exception as err:
            print(f"Contacting node {ep} failed. Error:")
            print(repr(err))
            exit(2)


def remove_callback_token(node):
    """
    Remove a callback token

    :param node: the node
    """
    tmp_file = f"{callback_tokens_file}.tmp"
    if not os.path.isfile(callback_tokens_file):
        open(callback_tokens_file, "a+")
        os.chmod(callback_tokens_file, 0o600)
    with open(tmp_file, "w") as backup_fp:
        os.chmod(tmp_file, 0o600)
        with open(callback_tokens_file, "r+") as callback_fp:
            # Entries are of the format: 'node_hostname:agent_port token'
            # We need to get the node_hostname part
            for line in callback_fp:
                parts = line.split(":")
                if parts[0] == node:
                    continue
                else:
                    backup_fp.write(line)

    try_set_file_permissions(tmp_file)
    shutil.move(tmp_file, callback_tokens_file)


@click.command()
@click.argument("node", required=True)
@click.option(
    "--force",
    is_flag=True,
    required=False,
    default=False,
    help="Force the node removal operation. (default: false)",
)
def reset(node, force):
    """
    Remove a node from the cluster
    """
    if is_node_running_dqlite():
        remove_dqlite_node(node, force)
    else:
        remove_node(node)
    sys.exit(0)


if __name__ == "__main__":
    reset(prog_name="microk8s remove-node")

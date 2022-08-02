#!/usr/bin/python3
import os
import argparse

import tempfile
import datetime
import subprocess
import tarfile
import os.path

from common.utils import (
    exit_if_no_permission,
    is_cluster_locked,
    is_ha_enabled,
)


def get_kine_endpoint():
    """
    Return the default kine endpoint
    """
    return "unix:///var/snap/microk8s/current/var/kubernetes/backend/kine.sock:12379"


def kine_exists():
    """
    Check the existence of the kine socket
    :return: True if the kine socket exists
    """
    kine_socket = get_kine_endpoint()
    kine_socket_path = kine_socket.replace("unix://", "")
    return os.path.exists(kine_socket_path)


def generate_backup_name():
    """
    Generate a filename based on the current time and date
    :return: a generated filename
    """
    now = datetime.datetime.now()
    return f'backup-{now.strftime("%Y-%m-%d-%H-%M-%S")}'


def run_command(command):
    """
    Run a command while printing the output
    :param command: the command to run
    :return: the return code of the command
    """
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    while True:
        output = process.stdout.readline()
        if (not output or output == "") and process.poll() is not None:
            break
        if output:
            print(output.decode().strip())
    return process.poll()


def backup(fname=None, debug=False):
    """
    Backup the database to a provided file
    :param fname_tar: the tar file
    :param debug: show debug output
    """
    snap_path = os.environ.get("SNAP")
    kine_ep = get_kine_endpoint()
    # snap_path = '/snap/microk8s/current'
    # snapdata_path = '/var/snap/microk8s/current'

    if not fname:
        fname = generate_backup_name()
    if fname.endswith(".tar.gz"):
        fname = fname[:-7]
    fname_tar = f"{fname}.tar.gz"

    with tempfile.TemporaryDirectory() as tmpdirname:
        backup_cmd = f"{snap_path}/bin/migrator --endpoint {kine_ep} --mode backup-dqlite --db-dir {tmpdirname}/{fname}"

        if debug:
            backup_cmd = f"{backup_cmd} --debug"
        try:
            rc = run_command(backup_cmd)
            if rc > 0:
                print(f"Backup process failed. {rc}")
                exit(1)
            with tarfile.open(fname_tar, "w:gz") as tar:
                tar.add(
                    f"{tmpdirname}/{fname}",
                    arcname=os.path.basename(f"{tmpdirname}/{fname}"),
                )


            print(f"The backup is: {fname_tar}")
        except subprocess.CalledProcessError as e:
            print(f"Backup process failed. {e}")
            exit(2)


def restore(fname_tar, debug=False):
    """
    Restore the database from the provided file
    :param fname_tar: the tar file
    :param debug: show debug output
    """
    snap_path = os.environ.get("SNAP")
    kine_ep = get_kine_endpoint()
    # snap_path = '/snap/microk8s/current'
    with tempfile.TemporaryDirectory() as tmpdirname:
        with tarfile.open(fname_tar, "r:gz") as tar:
            tar.extractall(path=tmpdirname)
        fname = fname_tar[:-7] if fname_tar.endswith(".tar.gz") else fname_tar
        fname = os.path.basename(fname)
        restore_cmd = f"{snap_path}/bin/migrator --endpoint {kine_ep} --mode restore-to-dqlite --db-dir {tmpdirname}/{fname}"

        if debug:
            restore_cmd = f"{restore_cmd} --debug"
        try:
            rc = run_command(restore_cmd)
            if rc > 0:
                print(f"Restore process failed. {rc}")
                exit(3)
        except subprocess.CalledProcessError as e:
            print(f"Restore process failed. {e}")
            exit(4)


if __name__ == "__main__":
    exit_if_no_permission()
    is_cluster_locked()

    if not kine_exists() or not is_ha_enabled():
        print("Please ensure the kubernetes apiserver is running and HA is enabled.")
        exit(10)

    # initiate the parser with a description
    parser = argparse.ArgumentParser(
        description="backup and restore the Kubernetes datastore.", prog="microk8s dbctl"
    )
    parser.add_argument("--debug", action="store_true", help="print debug output")
    commands = parser.add_subparsers(title="commands", help="backup and restore operations")
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("backup-file", help="name of file with the backup")
    backup_parser = commands.add_parser("backup")
    backup_parser.add_argument("-o", metavar="backup-file", help="output filename")
    args = parser.parse_args()

    if "backup-file" in args:
        fname = vars(args)["backup-file"]
        print(f"Restoring from {fname}")
        restore(fname, args.debug)
    elif "o" in args:
        print("Backing up the datastore")
        backup(vars(args)["o"], args.debug)
    else:
        parser.print_help()

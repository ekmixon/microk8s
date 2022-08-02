import string
import random
import time

import pytest
import os
import subprocess
from os import path

# Provide a list of VMs you want to reuse. VMs should have already microk8s installed.
# the test will attempt a refresh to the channel requested for testing
# reuse_vms = ['vm-ldzcjb', 'vm-nfpgea', 'vm-pkgbtw']
reuse_vms = None

# Channel we want to test. A full path to a local snap can be used for local builds
channel_to_test = os.environ.get("CHANNEL_TO_TEST", "latest/edge")
backend = os.environ.get("BACKEND", None)
profile = os.environ.get("LXC_PROFILE", "lxc/microk8s.profile")


class VM:
    """
    This class abstracts the backend we are using. It could be either multipass or lxc.
    """

    def __init__(self, backend=None, attach_vm=None):
        """Detect the available backends and instantiate a VM.

        If `attach_vm` is provided we just make sure the right MicroK8s is deployed.
        :param backend: either multipass of lxc
        :param attach_vm: the name of the VM we want to reuse
        """
        rnd_letters = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
        self.backend = backend
        self.vm_name = f"vm-{rnd_letters}"
        self.attached = False
        if attach_vm:
            self.attached = True
            self.vm_name = attach_vm

    def setup(self, channel_or_snap):
        """Setup the VM with the right snap.

        :param channel_or_snap: the snap channel or the path to the local snap build
        """
        if (path.exists("/snap/bin/multipass") and not self.backend) or self.backend == "multipass":
            print("Creating mulitpass VM")
            self.backend = "multipass"
            self._setup_multipass(channel_or_snap)

        elif (path.exists("/snap/bin/lxc") and not self.backend) or self.backend == "lxc":
            print("Creating lxc VM")
            self.backend = "lxc"
            self._setup_lxc(channel_or_snap)
        else:
            raise Exception("Need to install multipass of lxc")

    def _setup_lxc(self, channel_or_snap):
        if not self.attached:
            profiles = subprocess.check_output("/snap/bin/lxc profile list".split())
            if "microk8s" not in profiles.decode():
                subprocess.check_call("/snap/bin/lxc profile copy default microk8s".split())
                with open(profile, "r+") as fp:
                    profile_string = fp.read()
                    process = subprocess.Popen(
                        "/snap/bin/lxc profile edit microk8s".split(),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                    )
                    process.stdin.write(profile_string.encode())
                    process.stdin.close()

            subprocess.check_call(
                f"/snap/bin/lxc launch -p default -p microk8s ubuntu:18.04 {self.vm_name}".split()
            )

            time.sleep(20)
            if channel_or_snap.startswith("/"):
                self._transfer_install_local_snap_lxc(channel_or_snap)
            else:
                cmd_prefix = f"/snap/bin/lxc exec {self.vm_name}  -- script -e -c".split()
                cmd = [f"snap install microk8s --classic --channel {channel_or_snap}"]
                time.sleep(20)
                subprocess.check_output(cmd_prefix + cmd)
        elif channel_or_snap.startswith("/"):
            self._transfer_install_local_snap_lxc(channel_or_snap)
        else:
            cmd = f"/snap/bin/lxc exec {self.vm_name}  -- ".split()
            cmd.append(f"sudo snap refresh microk8s --channel {channel_or_snap}")
            subprocess.check_call(cmd)

    def _transfer_install_local_snap_lxc(self, channel_or_snap):
        print(f"Installing snap from {channel_or_snap}")
        cmd_prefix = f"/snap/bin/lxc exec {self.vm_name}  -- script -e -c".split()
        cmd = ["rm -rf /var/tmp/microk8s.snap"]
        subprocess.check_output(cmd_prefix + cmd)
        cmd = f"lxc file push {channel_or_snap} {self.vm_name}/var/tmp/microk8s.snap".split()

        subprocess.check_output(cmd)
        cmd = ["snap install /var/tmp/microk8s.snap --classic --dangerous"]
        subprocess.check_output(cmd_prefix + cmd)
        time.sleep(20)

    def _setup_multipass(self, channel_or_snap):
        if not self.attached:
            subprocess.check_call(
                f"/snap/bin/multipass launch 18.04 -n {self.vm_name} -m 2G".split()
            )

            if channel_or_snap.startswith("/"):
                self._transfer_install_local_snap_multipass(channel_or_snap)
            else:
                subprocess.check_call(
                    f"/snap/bin/multipass exec {self.vm_name}  -- sudo snap install microk8s --classic --channel {channel_or_snap}".split()
                )

        elif channel_or_snap.startswith("/"):
            self._transfer_install_local_snap_multipass(channel_or_snap)
        else:
            subprocess.check_call(
                f"/snap/bin/multipass exec {self.vm_name}  -- sudo snap refresh microk8s --channel {channel_or_snap}".split()
            )

    def _transfer_install_local_snap_multipass(self, channel_or_snap):
        print(f"Installing snap from {channel_or_snap}")
        subprocess.check_call(
            f"/snap/bin/multipass transfer {channel_or_snap} {self.vm_name}:/var/tmp/microk8s.snap".split()
        )

        subprocess.check_call(
            f"/snap/bin/multipass exec {self.vm_name}  -- sudo snap install /var/tmp/microk8s.snap --classic --dangerous".split()
        )

    def run(self, cmd):
        """
        Run a command
        :param cmd: the command we are running.
        :return: the output of the command
        """
        if self.backend == "multipass":
            output = subprocess.check_output(
                f"/snap/bin/multipass exec {self.vm_name}  -- sudo {cmd}".split()
            )

            return output
        elif self.backend == "lxc":
            cmd_prefix = f"/snap/bin/lxc exec {self.vm_name}  -- script -e -c ".split()
            output = subprocess.check_output(cmd_prefix + [cmd])
            return output
        else:
            raise Exception(f"Not implemented for backend {self.backend}")

    def release(self):
        """
        Release a VM.
        """
        print(f"Destroying VM in {self.backend}")
        if self.backend == "multipass":
            subprocess.check_call(f"/snap/bin/multipass stop {self.vm_name}".split())
            subprocess.check_call(f"/snap/bin/multipass delete {self.vm_name}".split())
        elif self.backend == "lxc":
            subprocess.check_call(f"/snap/bin/lxc stop {self.vm_name}".split())
            subprocess.check_call(f"/snap/bin/lxc delete {self.vm_name}".split())


class TestCluster(object):
    @pytest.fixture(autouse=True, scope="module")
    def setup_cluster(self):
        """
        Provision VMs and for a cluster.
        :return:
        """
        try:
            print("Setting up cluster")
            type(self).VM = []
            if not reuse_vms:
                size = 3
                for i in range(size):
                    print(f"Creating machine {i}")
                    vm = VM(backend)
                    vm.setup(channel_to_test)
                    print(f"Waiting for machine {i}")
                    vm.run("/snap/bin/microk8s.status --wait-ready --timeout 120")
                    self.VM.append(vm)
            else:
                for vm_name in reuse_vms:
                    vm = VM(backend, vm_name)
                    vm.setup(channel_to_test)
                    self.VM.append(vm)

            # Form cluster
            vm_master = self.VM[0]
            connected_nodes = vm_master.run("/snap/bin/microk8s.kubectl get no")
            for vm in self.VM:
                if vm.vm_name in connected_nodes.decode():
                    continue
                print(f"Adding machine {vm.vm_name} to cluster")
                add_node = vm_master.run("/snap/bin/microk8s.add-node")
                endpoint = [ep for ep in add_node.decode().split() if ":25000/" in ep]
                vm.run(f"/snap/bin/microk8s.join {endpoint[0]}")

            # Wait for nodes to be ready
            print("Waiting for nodes to register")
            connected_nodes = vm_master.run("/snap/bin/microk8s.kubectl get no")
            while "NotReady" in connected_nodes.decode():
                time.sleep(5)
                connected_nodes = vm_master.run("/snap/bin/microk8s.kubectl get no")
            print(connected_nodes.decode())

            # Wait for CNI pods
            print("Waiting for cni")
            while True:
                pods = vm_master.run("/snap/bin/microk8s.kubectl get po -n kube-system -o wide")
                ready_pods = sum(
                    "calico" in line and "Running" in line
                    for line in pods.decode().splitlines()
                )

                if ready_pods == (len(self.VM) + 1):
                    print(pods.decode())
                    break
                time.sleep(5)

            yield

        finally:
            print("Cleanup up cluster")
            if not reuse_vms:
                for vm in self.VM:
                    print(f"Releasing machine {vm.vm_name} in {vm.backend}")
                    vm.release()

    def test_calico_in_nodes(self):
        """
        Test each node has a calico pod.
        """
        print("Checking calico is in all nodes")
        pods = self.VM[0].run("/snap/bin/microk8s.kubectl get po -n kube-system -o wide")
        for vm in self.VM:
            if vm.vm_name not in pods.decode():
                assert False
            print(f"Calico found in node {vm.vm_name}")

    def test_nodes_in_ha(self):
        """
        Test all nodes are seeing the database while removing nodes
        """
        # All nodes see the same pods
        for vm in self.VM:
            pods = vm.run("/snap/bin/microk8s.kubectl get po -n kube-system -o wide")
            for other_vm in self.VM:
                if other_vm.vm_name not in pods.decode():
                    assert False
        print("All nodes see the same pods")

        attempt = 100
        while True:
            assert attempt > 0
            for vm in self.VM:
                status = vm.run("/snap/bin/microk8s.status")
                if "high-availability: yes" not in status.decode():
                    attempt += 1
                    continue
            break

        # remove a node
        print(f"Removing machine {self.VM[0].vm_name}")
        self.VM[0].run("/snap/bin/microk8s.leave")
        self.VM[1].run(f"/snap/bin/microk8s.remove-node {self.VM[0].vm_name}")
        # allow for some time for the leader to hand over leadership
        time.sleep(10)
        attempt = 100
        while True:
            pods = self.VM[1].run("/snap/bin/microk8s.kubectl get po -n kube-system -o wide")
            ready_pods = sum(
                "calico" in line and "Running" in line
                for line in pods.decode().splitlines()
            )

            if ready_pods == (len(self.VM)):
                print(pods.decode())
                break
            attempt -= 1
            if attempt <= 0:
                assert False
            time.sleep(5)
        print("Checking calico is on the nodes running")

        leftVMs = [self.VM[1], self.VM[2]]
        attempt = 100
        while True:
            assert attempt > 0
            for vm in leftVMs:
                status = vm.run("/snap/bin/microk8s.status")
                if "high-availability: no" not in status.decode():
                    attempt += 1
                    time.sleep(2)
                    continue
            break

        for vm in leftVMs:
            pods = vm.run("/snap/bin/microk8s.kubectl get po -n kube-system -o wide")
            for other_vm in leftVMs:
                if other_vm.vm_name not in pods.decode():
                    time.sleep(2)
                    assert False
        print("Remaining nodes see the same pods")

        print("Waiting for two ingress to appear")
        self.VM[1].run("/snap/bin/microk8s.enable ingress")
        # wait for two ingress to appear
        time.sleep(10)
        attempt = 100
        while True:
            pods = self.VM[1].run("/snap/bin/microk8s.kubectl get po -A -o wide")
            ready_pods = sum(
                "ingress" in line and "Running" in line
                for line in pods.decode().splitlines()
            )

            if ready_pods == (len(self.VM) - 1):
                print(pods.decode())
                break
            attempt -= 1
            if attempt <= 0:
                assert False
            time.sleep(5)

        print("Rejoin the node")
        add_node = self.VM[1].run("/snap/bin/microk8s.add-node")
        endpoint = [ep for ep in add_node.decode().split() if ":25000/" in ep]
        self.VM[0].run(f"/snap/bin/microk8s.join {endpoint[0]}")

        print("Waiting for nodes to be ready")
        connected_nodes = self.VM[0].run("/snap/bin/microk8s.kubectl get no")
        while "NotReady" in connected_nodes.decode():
            time.sleep(5)
            connected_nodes = self.VM[0].run("/snap/bin/microk8s.kubectl get no")

        attempt = 100
        while True:
            assert attempt > 0
            for vm in self.VM:
                status = vm.run("/snap/bin/microk8s.status")
                if "high-availability: yes" not in status.decode():
                    attempt += 1
                    time.sleep(2)
                    continue
            break

    def test_worker_noode(self):
        """
        Test a worker node is setup
        """
        print("Setting up a worker node")
        vm = VM()
        vm.setup(channel_to_test)
        self.VM.append(vm)

        # Form cluster
        vm_master = self.VM[0]
        print(f"Adding machine {vm.vm_name} to cluster")
        add_node = vm_master.run("/snap/bin/microk8s.add-node")
        endpoint = [ep for ep in add_node.decode().split() if ":25000/" in ep]
        vm.run(f"/snap/bin/microk8s.join {endpoint[0]} --worker")
        ep_parts = endpoint[0].split(":")
        master_ip = ep_parts[0]

        # Wait for nodes to be ready
        print("Waiting for node to register")
        connected_nodes = vm_master.run("/snap/bin/microk8s.kubectl get no")
        while "NotReady" in connected_nodes.decode():
            time.sleep(5)
            connected_nodes = vm_master.run("/snap/bin/microk8s.kubectl get no")
        print(connected_nodes.decode())

        # Check that kubelet talks to traefik and traefik to the master node
        print("Checking the worker's configuration")
        provider = vm.run("cat /var/snap/microk8s/current/args/traefik/provider.yaml")
        assert master_ip in provider.decode()
        kubelet = vm.run("cat /var/snap/microk8s/current/credentials/kubelet.config")
        assert "127.0.0.1" in kubelet.decode()

    def test_no_cert_reissue_in_nodes(self):
        """
        Test that each node has the cert no-reissue lock.
        """
        print("Checking for the no re-issue lock")
        for vm in self.VM:
            lock_files = vm.run("ls /var/snap/microk8s/current/var/lock/")
            assert "no-cert-reissue" in lock_files.decode()

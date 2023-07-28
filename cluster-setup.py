import nmap
import paramiko
import argparse
import time
import os

# TODO: https://stackoverflow.com/questions/39523216/paramiko-add-host-key-to-known-hosts-permanently

NETWORK_SEARCH_SECTION = '192.168.50.0/24'

class NodeInfo():
    """Stores important information about each pi in the cluster."""

    def __init__(self, ip, name):
        self.ip: str = ip
        self.name: str
        self.known: bool = False
        self.public_key: str

        if name == '':
            self.name = None
        else:
            self.name = name

    def __str__(self):
        return f"Name: {self.name}  IP: {self.ip}  Known: {str(self.known)}"

    def __repr__(self) -> str:
        return self.__str__()

    @property
    def hosts_file_line(self) -> str:
        """Contains the necessary information to be added to the hosts file.

        Returns:
            str: A string with a format as follows '127.0.0.1 rpi0 rpi0.local rpi.lan\n'
        """
        return f"{self.ip} {self.name} {self.name}.local {self.name}.lan\n"


def action_all_pis(pis: list[NodeInfo], username: str, password: str, action: str) -> None:
    """Perform a command on all pi's in the cluster.

    Args:
        pis (list[NodeInfo]): All of the pi's in the cluster represented as NodeInfo objects
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's
        action (str): Action to be executed on all of the pi's
    """
    print(f"Performing action {action}")

    for node in pis:

        if action == "reboot":
            if node.name != "rpi0":
                reboot_pi(node.ip, username, password)

        elif action == "update":
            update_pi(node, username, password)

        elif action == "ssh-key-gen":
            node.public_key = generate_ssh_key(node.ip, username, password)

    if action == "reboot":
        print("Sleeping for 60 seconds")
        time.sleep(60)


def reboot_pi(ip: str, username: str, password: str) -> None:
    """Reboots the raspberry pi.

    Args:
        ip (str): Standard ipv4 address
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    cmd = "sudo reboot"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    ssh.close()


def update_pi(node: NodeInfo, username: str, password: str) -> None:
    """Updates and upgrades a raspberry pi.

    Args:
        node (NodeInfo): A raspberry pi represented as a NodeInfo object
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's
    """
    print(f"Updating {node.name}, Please wait...")
    ssh = paramiko.SSHClient()
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ip, username=username, password=password)

    cmd = "sudo apt-get update -y"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    time.sleep(120)

    cmd = "sudo apt-get upgrade -y"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    ssh.close()


def generate_ssh_key(ip: str, username: str, password: str) -> str:
    """Generates a private/public ssh key pair if one does not exist and returns the public key.

    Args:
        ip (str): Standard ipv4 address
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's

    Returns:
        str: Public ssh key
    """
    print(f"Generating ssh key for {ip}")

    ssh = paramiko.SSHClient()
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    # Create .ssh directory
    ssh.exec_command('mkdir ~/.ssh')

    # Set permissions
    ssh.exec_command('chmod 700 ~/.ssh')

    # Create authorized keys file and set permissions
    stdin, stdout, stderr = ssh.exec_command("touch ~/.ssh/authorized_keys")
    stdin, stdout, stderr = ssh.exec_command("chmod 600 ~/.ssh/authorized_keys")

    # Generate a new key pair
    if not os.path.isfile("~/.ssh/pi_id_rsa.pub"):

        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("ssh-keygen -t rsa")
        print("Generating rsa key for ssh...")
        time.sleep(20)
        ssh_stdin.write('\n')
        ssh_stdin.flush()
        time.sleep(1)
        ssh_stdin.write('\n')
        ssh_stdin.flush()
        time.sleep(1)

    else:
        print("ssh key pair exists")

    # Read the public key from the file
    stdin, stdout, stderr = ssh.exec_command("cat ~/.ssh/pi_id_rsa.pub")
    public_key = stdout.read().decode()

    ssh.close()

    return public_key


def share_ssh_keys(pis: list[NodeInfo], username: str, password: str) -> None:
    """Adds the generated SSH keys for each of the pi's in the cluster to the authorized_keys
    file in each pi

    Args:
        pis (list[NodeInfo]): All of the pi's in the cluster represented as NodeInfo objects
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's
    """
    print("Sharing ssh Keys")
    # Create an SSH client
    ssh = paramiko.SSHClient()
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to each Raspberry Pi
    for current_node in pis:
        ssh.connect(current_node.ip, username=username, password=password)

        # Append the contents of the public key to the authorized_keys file on each other Raspberry Pi
        for other_node in pis:
            if other_node.ip != current_node.ip:
                cmd = f"echo '{other_node.public_key}' >> ~/.ssh/authorized_keys"
                stdin, stdout, stderr = ssh.exec_command(cmd)

        # Close the SSH connection
        ssh.close()


def get_pis_on_network(input_ips: list[str]) -> list[NodeInfo]:
    """Searches your network on 192.168.50.0/24 to find the raspberry pi's in the provided list.

    Args:
        input_ips (list[str]): List containing all of the IP addresses of the pi's in the cluster

    Returns:
        list[NodeInfo]: All of the pi's in the cluster represented as NodeInfo objects
    """
    print("Finding Pi's on network")

    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts=NETWORK_SEARCH_SECTION, arguments='-sn')#, sudo=True)
    ip_list = []
    found_input_ip = []

    for host in nm.all_hosts():

        cur_hostname = scan_result["scan"][host]['hostnames'][0]["name"].lower()
        cur_info = NodeInfo(ip=host, name=cur_hostname)

        if 'raspberrypi' in cur_hostname or host in input_ips:
            ip_list.append(cur_info)

        elif 'rpi' in cur_hostname:
            cur_info.known = True
            ip_list.append(cur_info)

        if host in input_ips:
            found_input_ip.append(host)

    # Check that all input hosts have been found
    input_ip_diff = set(found_input_ip) ^ set(input_ips)

    for item in input_ip_diff:
        print(f"Could not find the following IP {item}")

    return ip_list


def change_hostname(node: NodeInfo, username: str, password: str) -> None:
    """Changes the hostname of the given raspberry pi.

    Args:
        node (NodeInfo): A raspberry pi represented as a NodeInfo object
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's

    Raises:
        Exception: If this is unable to change the pi's hostname, then it will raise an error.
    """
    print("Change hostname")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ip, username=username, password=password)

    cmd = f"sudo hostnamectl set-hostname {node.name}"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    if stdout.channel.recv_exit_status() != 0:
        raise Exception(f"Failed to change hostname: {stderr.read().decode()}")

    ssh.close()


def update_all_hosts_file(pis: list[NodeInfo], username: str, password: str) -> None:
    """Updates each pi's host file with all of the information about the other pi's as well
    as information about the current pi

    Args:
        pis (list[NodeInfo]): All of the pi's in the cluster represented as NodeInfo objects
        username (str): Username to login to all of the pi's
        password (str): Password to login to all of the pi's
    """
    print("Update all hosts files")
    footer: str = ""

    pis.sort(key=lambda x: x.name)

    for node in pis:
        footer += node.hosts_file_line

    for node in pis:

        hosts_file_data = f"127.0.0.1       localhost\n::1             localhost ip6-localhost ip6-loopback\nff02::1         ip6-allnodes\nff02::2         ip6-allrouters\n\n127.0.1.1 {node.name}\n"
        hosts_file_data += footer

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(node.ip, username=username, password=password)

        # Overwrite the hosts file with the new contents
        cmd = f"echo -n '{hosts_file_data}' | sudo tee /etc/hosts"
        stdin, stdout, stderr = ssh.exec_command(cmd)

        ssh.close()


if __name__ == '__main__':
    input_pis = ['192.168.50.214', '192.168.50.200', '192.168.50.220']
    username = 'pi'
    password = 'EnterPassword'
    keyfile = '~/.ssh/pi_id_rsa'
    current_hostname = 'localhost'
    pis = get_pis_on_network(input_pis)

    unknown_hosts = [pi for pi in pis if pi.name != 'rpi0' and not pi.known]
    known_hosts = [pi for pi in pis if pi.known]

    # Get last known pi number
    last_pi_num = 0

    for pi in pis:
        if pi.name:
            if "rpi" in pi.name and pi.known:
                last_pi_num = max(last_pi_num, int(pi.name[-1]))

    # Change all unknown pi's hostnames
    for idx, node in enumerate(unknown_hosts, start=last_pi_num+1):
        node.name = f"rpi{idx}"
        change_hostname(node, username, password)

    # Update all host files
    update_all_hosts_file(pis, username, password)

    # Reboot all Pi's
    action_all_pis(pis, username, password, "reboot")

    # Setup ssh between pi's
    # Generate keys
    action_all_pis(pis, username, password, "ssh-key-gen")

    # Share keys
    share_ssh_keys(pis, username, password)

    # Update all Pi's
    action_all_pis(pis, username, password, "update")

    # Reboot all Pi's
    action_all_pis(pis, username, password, "reboot")

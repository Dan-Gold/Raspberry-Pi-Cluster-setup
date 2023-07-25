import nmap
import paramiko
import argparse
import time

# TODO: https://stackoverflow.com/questions/39523216/paramiko-add-host-key-to-known-hosts-permanently


class NodeInfo():
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
        return f"{self.ip} {self.name} {self.name}.local {self.name}.lan\n"


def action_all_pis(pis: list, username: str, password: str, action: str) -> None:

    for node in pis:

        if action == "reboot":
            if node.name != "rpi0":
                reboot_pi(node.ip, username, password)

        elif action == "update":
            update_pi(node, username, password)

        elif action == "ssh-key-gen":
            node.public_key = generate_ssh_key(node.ip, username, password)

    if action == "reboot":
        print("Sleeping for 30 seconds")
        time.sleep(30)


def reboot_pi(ip: str, username: str, password: str) -> None:
    """Reboots the raspberry pi."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    cmd = f"sudo reboot"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    ssh.close()


def update_pi(node: NodeInfo, username: str, password: str) -> None:
    """Updates and upgrades a raspberry pi."""

    print(f"Updating {node.name}, Please wait...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ip, username=username, password=password)

    cmd = f"sudo apt-get update -y"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    time.sleep(120)

    cmd = f"sudo apt-get upgrade -y"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    ssh.close()


def generate_ssh_key(ip, username, password) -> str:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    # Create .ssh directory
    ssh.exec_command('mkdir ~/.ssh')

    # Set permissions
    ssh.exec_command('chmod 700 ~/.ssh')

    # Create authorized keys file and set permissions
    stdin, stdout, stderr = ssh.exec_command("touch ~/.ssh/authorized_keys")
    stdin, stdout, stderr = ssh.exec_command("chmod 600 ~/.ssh/authorized_keys")

    # Generate a new key pair
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("ssh-keygen -t rsa")
    print("Generating rsa key for ssh...")
    time.sleep(20)
    ssh_stdin.write('\n')
    ssh_stdin.flush()
    time.sleep(1)
    ssh_stdin.write('\n')
    ssh_stdin.flush()
    time.sleep(1)

    # Read the public key from the file
    stdin, stdout, stderr = ssh.exec_command("cat ~/.ssh/id_rsa.pub")
    public_key = stdout.read().decode()

    ssh.close()

    return public_key


def share_ssh_keys(pis: list, username, password) -> None:
    # Create an SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Automatically add the host keys of each Raspberry Pi to the client's host key policy
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to each Raspberry Pi
    for current_node in pis:
        ssh.connect(current_node.ip, username=username, password=password)

        # Create the .ssh directory if it doesn't exist
        #stdin, stdout, stderr = ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

        # Read the contents of the public key file
        #with open('/home/pi/.ssh/id_rsa.pub', 'r') as f:
        #    public_key = f.read().strip()

        # Append the contents of the public key to the authorized_keys file on each other Raspberry Pi
        for other_node in pis:
            if other_node.ip != current_node.ip:
                cmd = f"echo '{other_node.public_key}' >> ~/.ssh/authorized_keys"
                stdin, stdout, stderr = ssh.exec_command(cmd)

        # Close the SSH connection
        ssh.close()


def get_pis_on_network(input_ips: list) -> dict:
    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts='192.168.50.0/24', arguments='-sn')#, sudo=True)
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


def change_hostname(node, username, password) -> None:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ip, username=username, password=password)

    cmd = f"sudo hostnamectl set-hostname {node.name}"
    stdin, stdout, stderr = ssh.exec_command(cmd)

    if stdout.channel.recv_exit_status() != 0:
        raise Exception(f"Failed to change hostname: {stderr.read().decode()}")

    ssh.close()


def update_all_hosts_file(pis, username, password) -> None:

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
    password = 'nopass'
    keyfile = '~/.ssh/id_rsa'
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

    # Need to add stuff to known hosts file
    # TODO:

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
    #action_all_pis(pis, username, password, "update")
    
    # Reboot all Pi's
    #action_all_pis(pis, username, password, "reboot")

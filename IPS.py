import socket
import os


#Firewall Rules
'''To enable PF and load the configuration, run the following commands in the terminal:
===>sudo pfctl -ef /path/to/block_ips.conf'''

def block_ip_address(ip_address):
    with open("blocked_ips.txt", "a") as f:
        f.write(f"{ip_address}\n")
    command = f"sudo pfctl -t block_ips -T add {ip_address}"
    os.system(command)
'''
the Paramiko library to create an SSH connection to the network device
==>pip install paramiko
'''
#============================================================
import paramiko

def ssh_disconnect_device(host, username, password, mac_address):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password)

        # Find the DHCP lease with the given MAC address
        find_lease_command = f"/ip dhcp-server lease print where mac-address={mac_address}"
        stdin, stdout, stderr = ssh.exec_command(find_lease_command)
        lease_info = stdout.read().decode()

        if "0 leases found" in lease_info:
            print(f"No lease found for MAC address: {mac_address}")
            return

        # Extract the lease ID
        lease_id = lease_info.split()[1]

        # Disable the lease
        disable_lease_command = f"/ip dhcp-server lease set {lease_id} disabled=yes"
        stdin, stdout, stderr = ssh.exec_command(disable_lease_command)

        if stderr.read():
            print(f"Error disconnecting device: {stderr.read().decode()}")
        else:
            print(f"Device {mac_address} disconnected successfully")
    except paramiko.AuthenticationException:
        print("Authentication failed")
    except Exception as e:
        print(f"Error connecting to the network device: {e}")
    finally:
        ssh.close()
def block_malicious_traffic(ip_address, device_id):
    # Block the IP address at the firewall level
    block_ip_address(ip_address)

    # Disconnect the malicious device from the network
    ssh_disconnect_device(device_id)

# Example Usage
if __name__ == "__main__":
    malicious_ip = "192.168.1.100"
    malicious_device_id = "device_001"

    block_malicious_traffic(malicious_ip, malicious_device_id)
'''
#Example usage of ssh_disconnect_device
if __name__ == "__main__":
    network_device_host = "192.168.1.1"
    network_device_username = "admin"
    network_device_password = "password"
    malicious_device_mac = "00:11:22:33:44:55"

    ssh_disconnect_device(
        network_device_host,
        network_device_username,
        network_device_password,
        malicious_device_mac
    )'''
"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import sys
from termcolor import colored
from modules.tasks_management import Task, DAEMONS_MANAGER
import platform
import re
from tabulate import tabulate
from modules.utility import app_id_from_user_input, get_app_id_from_owner_uid, get_owner_from_app_id, ip_and_port_from_user_input, ip_from_user_input, loading_animation, port_from_user_input, pc_wifi_ip
from modules.adb import get_session_device_id

DNS_TASK_ID = -1 

def get_current_proxy_settings(user_input):
    """
    Get and display the current global proxy settings on the mobile device.

    Args:
        user_input (str): User input (not used in this function).
    """
    print("Proxy set on mobile device:", end=" ")
    proxy = get_proxy()
    
    if (proxy==":0"):
        proxy = "NO PROXY"

    print(proxy)


def get_proxy():
    """
    Get the current global proxy settings on the mobile device.

    Returns:
        str: The current proxy settings.
    """
    command = ['adb', '-s', get_session_device_id(), 'shell', 'settings', 'get', 'global', 'http_proxy']
    output, error = Task().run(command)

    return output.strip()

def del_proxy(user_input):
    """
    Reset the global proxy settings on the mobile device.

    Args:
        user_input (str): User input (not used in this function).
    """
    command = ['adb', '-s', get_session_device_id(), 'shell', 'settings', 'put', 'global', 'http_proxy', ':0']
    output, error = Task().run(command)

    print("Proxy removed on mobile device")

def set_current_pc_proxy(user_input):
    """
    Set the proxy on the mobile device using the current PC's IP and the specified port.

    Args:
        user_input (str): The port number to use for the proxy.
    """
    # If the user input is not a port, ask the user to insert it again
    port = port_from_user_input(user_input)

    # Retrieve current IP of the PC on the Wi-Fi network  
    ip = pc_wifi_ip()
    # Set the proxy on the mobile device
    set_proxy(ip, user_input)


def set_generic_proxy(user_input):
    """
    Set the proxy on the mobile device using the specified IP address and port.

    Args:
        user_input (str): The IP address and port in the format <address>:<port>.
    """
    ip, port = ip_and_port_from_user_input(user_input)
    set_proxy(ip, port)
    

def set_proxy(ip, port):
    """
    Set the proxy on the mobile device.

    Args:
        ip (str): The IP address to use for the proxy.
        port (str): The port number to use for the proxy.
    """
    command = ['adb', '-s', get_session_device_id(), 'shell', 'settings', 'put', 'global', 'http_proxy', f'{ip}:{port}']
    output, error = Task().run(command)

    print("Proxy set on mobile device:", end=" ")
    print(get_proxy())


# Main function
def dns_proxy(target_ip):
    """
    Start the DNS proxy server.

    Args:
        target_ip (str): The target IP address for DNS spoofing.
    """
    global DNS_TASK_ID, DAEMONS_MANAGER

    if DNS_TASK_ID == -1:
        # Get the next available ID from the DAEMONS_MANAGER
        DNS_TASK_ID = DAEMONS_MANAGER.get_next_id()
        # Add a new DNS task to the DAEMONS_MANAGER
        DAEMONS_MANAGER.add_task('dns', [sys.executable, 'modules/dns_spoofing.py', target_ip])

        additional_info = {'Fake DNS IP':target_ip,}
        DAEMONS_MANAGER.add_info('dns', DNS_TASK_ID, additional_info)


def get_current_dns_proxy(user_input):
    """
    Get the current DNS proxy settings on the mobile device.

    Args:
        user_input (str): User input (not used in this function).
    """
    pass

def set_current_pc_dns_proxy(user_input):
    """
    Set the DNS proxy on the mobile device using the current PC's IP address.

    Args:
        user_input (str): User input (not used in this function).
    """
    
    print("\nSet the DNS1 and DNS2 on mobile device at: "+pc_wifi_ip())
    current_os = platform.system()

    if current_os == "Windows":
        print("(Disable the Microsoft Windows firewall)")

    command = ['adb', '-s', get_session_device_id(), 'shell', 'am', 'start', '-a', 'android.settings.WIFI_SETTINGS']
    output, error = Task().run(command)

    # Get the current Wi-Fi SSID
    pc_ssid = get_current_pc_wifi_ssid()
    mobile_ssid = get_mobile_wifi_ssid()

    print("\nWi-Fi SSIDs")
    row_list = []
    
    if pc_ssid:
        row_list.append(["Current PC",pc_ssid])
    else:
        row_list.append(["Current PC","Undetectable"])

    if pc_ssid:
        row_list.append(["Mobile Device",mobile_ssid])
    else:
        row_list.append(["Mobile Device","Undetectable"])

    print(tabulate(row_list, headers=['Device', 'Wi-Fi SSID'], tablefmt='fancy_grid'))

    if pc_ssid!=mobile_ssid:
        print("\nPlease connect the mobile device and the current PC to the same network!!!")

    command = ['adb', '-s', get_session_device_id(), 'shell', 'am', 'start', '-a', 'android.settings.WIFI_SETTINGS']
    output, error = Task().run(command)
    x=input(colored("Press ENTER to launch the DNS Server...\n", "green"))

    dns_proxy(pc_wifi_ip())

def set_generic_dns_proxy(user_input):
    """
    Set the DNS proxy on the mobile device using the specified IP address.

    Args:
        user_input (str): The IP address to use for the DNS proxy.
    """
    remote_ip = ip_from_user_input(user_input)
        
    print("\nSet the DNS1 and DNS2 on mobile device at: "+remote_ip)
    print("(If on Windows, disable the firewall)")
    command = ['adb', '-s', get_session_device_id(), 'shell', 'am', 'start', '-a', 'android.settings.WIFI_SETTINGS']
    output, error = Task().run(command)

    x=input(colored("Press ENTER to launch the DNS Server (or CTRL+C to stop the operation)...\n", "green"))
    dns_proxy(remote_ip)


def del_dns_proxy(user_input):
    """
    Delete the DNS proxy settings on the mobile device.

    Args:
        user_input (str): User input (not used in this function).
    """
    global DNS_TASK_ID, DAEMONS_MANAGER

    if DNS_TASK_ID != -1:
        DAEMONS_MANAGER.stop_task('dns', DNS_TASK_ID)
        DNS_TASK_ID = -1
        loading_animation("Stopping DNS Server", 0.5, 30, 'grey', 'red')
        print("DNS Server STOPPED!!!\n")


def get_current_invisible_proxy(user_input):
    command = ['adb', '-s', get_session_device_id(), 'shell']
    shell_input = [ "su root",
                   """iptables -t nat -L OUTPUT -v -n | grep 'DNAT'"""]
    
    output, error = Task().run(command, input_to_cmd=shell_input)

    lines = output.strip().splitlines()
    uid_pattern = re.compile(r'UID match (\d+)')
    dst_port_port = re.compile(r'dpt:(\d+)')
    proxy_ip_pattern = re.compile(r'to:([\d\.]+):\d+')
    proxy_port_pattern = re.compile(r'to:[\d\.]+:(\d+)')

    info = []
    info_headers = []
    for line in lines:
        line_info = {}
        uid_match = uid_pattern.search(line)
        dst_port_match = dst_port_port.search(line)
        proxy_ip_match = proxy_ip_pattern.search(line)
        proxy_port_match = proxy_port_pattern.search(line)

        if uid_match:
            uid = uid_match.group(1)
            line_info["Owner"] = get_app_id_from_owner_uid(uid) +f" ({uid})"
            
            if "Owner" not in info_headers:
                info_headers.append("Owner")

        if dst_port_match: 
            line_info["Destination Port"] = dst_port_match.group(1)

            if "Destination Port" not in info_headers:
                info_headers.append("Destination Port")
        
        if proxy_ip_match: 
            line_info["Proxy IP"] = proxy_ip_match.group(1)

            if "Proxy IP" not in info_headers:
                info_headers.append("Proxy IP")

        if proxy_port_match:
            line_info["Proxy Port"] = proxy_port_match.group(1)

            if "Proxy Port" not in info_headers:
                info_headers.append("Proxy Port")
            
        info.append(line_info)

    if info:
        table_content = []
        for line in info:
            row = []

            for header in info_headers:
                if header in line:
                    row.append(line[header])
                else:
                    row.append("-")

            table_content.append(row)

        for header in info_headers:
            if "Proxy" in header:
                info_headers[info_headers.index(header)] = colored(header, 'red')
            else:
                info_headers[info_headers.index(header)] = colored(header, 'yellow')

        print(tabulate(table_content, headers=info_headers, tablefmt='fancy_grid', colalign=('center',)*len(info_headers)))

    else:
        print("No invisible proxy is set on the mobile device")

def set_current_pc_invisible_global_proxy(user_input):
    # Get the current Wi-Fi SSID
    pc_ssid = get_current_pc_wifi_ssid()
    mobile_ssid = get_mobile_wifi_ssid()

    print("\nWi-Fi SSIDs")
    row_list = []
    
    if pc_ssid:
        row_list.append(["Current PC",pc_ssid])
    else:
        row_list.append(["Current PC","Undetectable"])

    if pc_ssid:
        row_list.append(["Mobile Device",mobile_ssid])
    else:
        row_list.append(["Mobile Device","Undetectable"])

    print(tabulate(row_list, headers=['Device', 'Wi-Fi SSID'], tablefmt='fancy_grid'))

    if pc_ssid!=mobile_ssid:
        print("\nPlease connect the mobile device and the current PC to the same network!!!")

        command = ['adb', '-s', get_session_device_id(), 'shell', 'am', 'start', '-a', 'android.settings.WIFI_SETTINGS']
        output, error = Task().run(command)
    
    x=input(colored("Press ENTER to set the IPTables...\n", "green"))

    set_invisible_proxy(pc_wifi_ip(), limit_owner=False)

def set_generic_invisible_global_proxy(user_input):
    remote_ip = ip_from_user_input(user_input)
    set_invisible_proxy(remote_ip, limit_owner=False)


def set_current_pc_invisible_app_proxy(user_input):
    # Get the current Wi-Fi SSID
    pc_ssid = get_current_pc_wifi_ssid()
    mobile_ssid = get_mobile_wifi_ssid()

    print("\nWi-Fi SSIDs")
    row_list = []
    
    if pc_ssid:
        row_list.append(["Current PC",pc_ssid])
    else:
        row_list.append(["Current PC","Undetectable"])

    if pc_ssid:
        row_list.append(["Mobile Device",mobile_ssid])
    else:
        row_list.append(["Mobile Device","Undetectable"])

    print(tabulate(row_list, headers=['Device', 'Wi-Fi SSID'], tablefmt='fancy_grid'))

    if pc_ssid!=mobile_ssid:
        print("\nPlease connect the mobile device and the current PC to the same network!!!")

        command = ['adb', '-s', get_session_device_id(), 'shell', 'am', 'start', '-a', 'android.settings.WIFI_SETTINGS']
        output, error = Task().run(command)

    set_invisible_proxy(pc_wifi_ip(), limit_owner=True)

def set_generic_invisible_app_proxy(user_input):
    remote_ip = ip_from_user_input(user_input)
    set_invisible_proxy(remote_ip, limit_owner=True)

def set_invisible_proxy(target_ip, limit_owner):
    del_invisible_proxy("")

    command = ['adb', '-s', get_session_device_id(), 'shell']
    
    owner_filtering = ""

    if limit_owner:
        user_input = input(colored("Write a valid app ID or a set of keyword to be searched\n", "green"))
        app_id = app_id_from_user_input(user_input)
        uid_owner = get_owner_from_app_id(app_id)

        owner_filtering = f" -m owner --uid-owner {uid_owner}"

    shell_input = [ "su root",
                    f"iptables -t nat -A OUTPUT{owner_filtering} -p tcp --dport 443 -j DNAT --to-destination {target_ip}:443",
                    f"iptables -t nat -A OUTPUT{owner_filtering} -p tcp --dport 80 -j DNAT --to-destination {target_ip}:80",
                    f"iptables -t nat -A POSTROUTING{owner_filtering} -p tcp --dport 443 -j MASQUERADE",
                    f"iptables -t nat -A POSTROUTING{owner_filtering} -p tcp --dport 80 -j MASQUERADE"
                ]
    output, error = Task().run(command, input_to_cmd=shell_input)


def del_invisible_proxy(user_input):
    # flush previous configuration
    #iptables -t nat -F
    command = ['adb', '-s', get_session_device_id(), 'shell']
    shell_input = [ "su root",
                   "iptables -t nat -F"
                ]
    
    output, error = Task().run(command, input_to_cmd=shell_input)


def get_current_pc_wifi_ssid():
    """
    Get the current Wi-Fi SSID of the PC.

    Returns:
        str: The current Wi-Fi SSID.
    """
    current_os = platform.system()

    if current_os == "Windows":
        # Windows command to get Wi-Fi SSID
        command = ['netsh', 'wlan', 'show', 'interfaces']
        output, error = Task().run(command)

        for line in output.splitlines():
            if "SSID" in line:
                return line.split(":")[1].strip()
                
    elif current_os == "Linux":
        # Linux command to get Wi-Fi SSID
        command = ['iwgetid', '-r']
        output, error = Task().run(command)
        return output.strip()

    elif current_os == "Darwin":  # macOS
        # macOS command to get Wi-Fi SSID
        command = ['networksetup', '-getairportnetwork', 'en0']
        output, error = Task().run(command)

        for line in output.splitlines():
            if "Current Wi-Fi Network" in line:
                return line.split(":")[1].strip()

    return None

def get_mobile_wifi_ssid():
    """
    Get the current Wi-Fi SSID of the mobile device.

    Returns:
        str: The current Wi-Fi SSID.
    """
    command = ['adb', '-s', get_session_device_id(), 'shell', 'dumpsys', 'netstats', '|', 'grep', '-E', 'iface=wlan.*networkId']
    output, error = Task().run(command)
    
    if output:
        REGEX_SSID = r'networkId=\"(.*)\"'
    else:
        REGEX_SSID = r'current\sSSID\(s\):\{iface=.+,ssid=\"(.*)\"}'
        command = ['adb', '-s', get_session_device_id(), 'shell', "dumpsys wifi | grep 'current SSID(s):'"]
        output, error = Task().run(command)

    mobile_ssid = re.search(REGEX_SSID, output.splitlines()[0])

    if mobile_ssid:
        return mobile_ssid.group(1)
    else:
        return None
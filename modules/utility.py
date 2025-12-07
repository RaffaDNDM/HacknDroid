"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import subprocess
import netifaces
import re
import os
import sys
import time
import requests
from modules.adb import get_session_device_id
from datetime import datetime
from termcolor import colored, cprint
from modules.tasks_management import Task
import ipaddress
from pyfiglet import Figlet

APP_ID_REGEX = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"

def split_user_input(user_input):
    """
    Remove a sequence of more than one whitespace and split the user input into a list of keywords.

    Args:
        user_input (str): The input string from the user.

    Returns:
        list: A list of keywords.
    """
    #Remove a sequence of more than one whitespace
    user_input = re.sub(r"\s{2,}", " ", user_input)
    # Take the full list of the values to be searched
    return user_input.split(' ')

def get_app_id(grep_string):
    """
    Retrieve the list of application IDs on the device that match the given keywords.

    Args:
        grep_string (str): Keywords to search for in the application IDs.

    Returns:
        list: A list of matching application IDs.
    """
    keywords = split_user_input(grep_string)
    
    # List all the application IDs
    command = ['adb', '-s', get_session_device_id(), 'shell', 'pm', 'list', 'packages']
    result = subprocess.run(command, capture_output=True, text=True)

    packages = []
    # If ADB command goes well
    if result.returncode == 0:
        # All the lines returned by the command (one line per package in the format "package:{app_id}")
        lines = [l.replace("package:","") for l in result.stdout.splitlines()]
        
        # Iterate over the lines looking for a match
        for l in lines:
            # Check that the first value in grep_string is in the line
            check = keywords[0] in l

            # Check that also 
            if len(keywords)>1:
                for v in keywords[1:]:
                    # If the previous keyword was not found in the app ID,
                    # the app ID could not be a good candidate
                    if not check:
                        break
                    
                    # 
                    check = check and (v in l)

            # If all the keywords were found in the current app ID
            # add the app ID to the list of possible packages to be returned
            if check:
                packages.append(l)

    # List of all the packages that pass the check
    return packages

def is_app_id(user_input):
    """
    Check if the user input is a valid app ID.

    Args:
        user_input (str): The input string from the user.

    Returns:
        bool: True if the input is a valid app ID, False otherwise.
    """
    command = ['adb', '-s', get_session_device_id(), 'shell', 'pm', 'list', 'packages']
    result = subprocess.run(command, capture_output=True, text=True)

    packages = []
    # If ADB command goes well
    if result.returncode == 0:
        # All the lines returned by the comman (one line per package)
        packages = [x.replace("package:","") for x in result.stdout.splitlines()]

    return user_input in packages 


def app_id_from_user_input(user_input):
    """
    Check if the user input is a valid app ID or a valid set of keywords and return the corresponding app ID.

    Args:
        user_input (str): The input string from the user.

    Returns:
        str: The valid app ID.
    """
    # Check if the user input is a valid app ID
    if is_app_id(user_input):
        # Return the app IDs
        return user_input
    else:
        # List of app IDs the matches the user input
        possible_app_ids = get_app_id(user_input)

        # If no possible match was found, ask keywords again to the user 
        while not possible_app_ids:
            user_input=input(colored("Write a valid app ID or a set of keyword to be searched\n", "green"))
            possible_app_ids = get_app_id(user_input)

        # If some app IDs related to the specified keywords are found
        # List the app IDs previously found

        num_digits = len(str(abs(len(possible_app_ids)-1)))
        
        cprint("\nAvailable applications:", 'cyan')
        for (i,x) in enumerate(possible_app_ids):
            print(colored(f"{i:{num_digits}d}) ", 'yellow')+x)

        print("")
        # The user continues to choose the ID until a valid number is inserted by him
        choice = -1
        while choice<0 or choice>=len(possible_app_ids): 
            try:
                # Number inserted by the user
                choice = int(input(colored("Select the app you want to test:\n", "green")))
            except ValueError:
                choice = -1

        print("")
        # Return the app ID related to the number chosen by the user
        return possible_app_ids[choice]
    
def active_applications():
    """
    Retrieve the list of active applications on the device.

    Returns:
        list: A list of active application IDs.
    """
    command = "adb -s "+get_session_device_id()+" shell \"ps -A | awk '{print $9}'\""
    output, error = Task().run(command)

    lines = output.splitlines()
    apps = []
    for l in lines:
        if "[" not in l and l.count(".")>=2 and ":" not in l and "@" not in l:
            apps.append(l.strip())

    return apps

def is_active_app_id(user_input):
    """
    Check if the user input is a valid active app ID.

    Args:
        user_input (str): The input string from the user.

    Returns:
        bool: True if the input is a valid active app ID, False otherwise.
    """
    apps = active_applications()

    return user_input in apps


def get_active_app_id(user_input):
    """
    Retrieve the list of active application IDs on the device that match the given keywords.

    Args:
        user_input (str): Keywords to search for in the active application IDs.

    Returns:
        list: A list of matching active application IDs.
    """
    apps = active_applications()
    possible_apps = []

    for a in apps:
        keywords = split_user_input(user_input)

        check = keywords[0] in a

        for k in keywords[1:]:
            check = check and (k in a)

            if not check:
                break

        if check:
            possible_apps.append(a)

    return possible_apps


def active_app_id_from_user_input(user_input):
    """
    Check if the user input is a valid active app ID or a valid set of keywords and return the corresponding active app ID.

    Args:
        user_input (str): The input string from the user.

    Returns:
        str: The valid active app ID.
    """
    # Check if the user input is a valid app ID
    if is_active_app_id(user_input):
        # Return the app IDs
        return user_input
    else:
        # List of app IDs the matches the user input
        possible_app_ids = get_active_app_id(user_input)

        # If no possible match was found, ask keywords again to the user 
        while not possible_app_ids:
            user_input=input(colored("Write a valid app ID or a set of keyword to be searched\n", "green"))
            possible_app_ids = get_active_app_id(user_input)

        # If some app IDs related to the specified keywords are found
        # List the app IDs previously found
        num_digits = len(str(abs(len(possible_app_ids)-1)))
        
        cprint("\nAvailable applications:", 'cyan')
        for (i,x) in enumerate(possible_app_ids):
            print(colored(f"{i:{num_digits}d}) ", 'yellow')+x)

        print("")

        # The user continues to choose the ID until a valid number is inserted by him
        choice = -1
        while choice<0 or choice>=len(possible_app_ids): 
            try:
                # Number inserted by the user
                choice = int(input(colored("Select the app you want to test: ", "green")))
            except ValueError:
                choice = -1

        # Return the app ID related to the number chosen by the user
        return possible_app_ids[choice]

def sd_path():
    """
    Identify the current SD Card folder on the device.

    Returns:
        str: The path to the SD Card folder.
    """
    # Open ADB shell
    command = ['adb', '-s', get_session_device_id(), 'shell']
    # Print the external storage path
    input_cmd = ['echo $EXTERNAL_STORAGE','exit']
    output, error = Task().run(command, input_to_cmd=input_cmd)
    
    sdcard_path = output.splitlines()[0]
    
    # Return the found path
    return sdcard_path

def rsc_from_path(path):
    """
    Extract the resource name from a given path.

    Args:
        path (str): The file path.

    Returns:
        str: The resource name.
    """
    rsc_name = os.path.basename(path)
    if rsc_name == '':
        rsc_name = os.path.basename(path[:-1])

    return rsc_name

def is_apk_on_system(apks):
    """
    Check if the provided list of APK files exists on the system.

    Args:
        apks (list): A list of APK file paths.

    Returns:
        bool: True if all APK files exist, False otherwise.
    """
    check = True

    for f in apks:
        check = check and f.endswith(".apk") and os.path.isfile(f)

        if not check:
            return check
        
    return check

def valid_apk_file(user_input):
    """
    Prompt the user to provide a valid APK file path.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        str: The valid APK file path.
    """
    while not os.path.exists(user_input) or not user_input.endswith(".apk"):
        user_input = input(colored("Write the path of an APK file on the PC:\n", "green"))

    print("")

    return user_input

def valid_aab_file(user_input):
    """
    Prompt the user to provide a valid APK file path.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        str: The valid APK file path.
    """
    while not os.path.exists(user_input) or not user_input.endswith(".aab"):
        user_input = input(colored("Write the path of an AAB file on the PC:\n", "green"))

    print("")

    return user_input

def get_valid_playstore_app_id(user_input):
    """
    Prompt the user to provide a valid and existing app ID from the Play Store.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        str: The valid Play Store app ID.
    """
    while not is_valid_app_id(user_input) or not is_app_on_store(user_input):
        user_input = input(colored("Write a valid and existing app ID to be searched on Play Store: ", "green"))

    return user_input

def is_valid_app_id(app_id):
    """
    Check if the provided app ID matches the valid app ID regex pattern.

    Args:
        app_id (str): The app ID to check.

    Returns:
        bool: True if the app ID is valid, False otherwise.
    """
    if re.match(APP_ID_REGEX, app_id):
        return True
    
    return False

def is_app_on_store(app_id):
    """
    Check if the provided app ID exists on the Play Store.

    Args:
        app_id (str): The app ID to check.

    Returns:
        bool: True if the app ID exists on the Play Store, False otherwise.
    """
    store_url = f"https://play.google.com/store/apps/details?id={app_id}"

    response = requests.get(store_url)

    return response.status_code == 200


def current_date():
    # Current date and time
    now = datetime.now()

    # Format the date and time as a string
    formatted_date = now.strftime("%Y-%m-%d_%H-%M-%S")

    return formatted_date

def is_port(user_input):
    """
    Check if the user input is a valid port number.

    Args:
        user_input (str): The input string from the user.

    Returns:
        bool: True if the input is a valid port number, False otherwise.
    """
    try:
        port = int(user_input)
        return (port>=0 and port< 65536)
    except ValueError:
        return False
    
def is_ip(ip_string):
    """
    Check if the provided string is a valid IP address.

    Args:
        ip_string (str): The string to check.

    Returns:
        bool: True if the string is a valid IP address, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return False
    
    return True

def ip_from_user_input(user_input):
    """
    Prompt the user to provide a valid IP address.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        str: The valid IP address.
    """
    check = is_ip(user_input)

    while not check:
        print(f"Address is invalid.")
        user_input = input(f"Enter the IP address: ")

        check = is_ip(user_input)

    return user_input

def port_from_user_input(user_input):
    """
    Prompt the user to provide a valid port number.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        int: The valid port number.
    """
    check = is_port(user_input)

    while not check:
        print(f"Port number is invalid.")
        user_input = input(f"Enter the port number: ")

        check = is_port(user_input)    

    return int(user_input)

def ip_and_port_from_user_input(user_input):
    """
    Prompt the user to provide a valid IP address and port.

    Args:
        user_input (str): The initial input string from the user.

    Returns:
        tuple: A tuple containing the valid IP address and port.
    """
    ip = ''
    port = ''
    check = True # Initialize check to True to enter the loop for validation

    while check:
        if ":" not in user_input:
            print(f"Invalid format. Please use <ip>:<port>.")
            user_input = input(f"Insert a valid IP address and port (e.g., 192.168.1.100:8080): ")
            continue # Re-evaluate the loop condition with new input

        parts = user_input.split(":")
        if len(parts) != 2:
            print(f"Invalid format. Please use <ip>:<port>.")
            user_input = input(f"Insert a valid IP address and port (e.g., 192.168.1.100:8080): ")
            continue # Re-evaluate the loop condition with new input

        temp_ip, temp_port = parts[0], parts[1]

        if not is_ip(temp_ip):
            print(f"Invalid IP address: '{temp_ip}'.")
            user_input = input(f"Insert a valid IP address and port (e.g., 192.168.1.100:8080): ")
        elif not is_port(temp_port):
            print(f"Invalid port number: '{temp_port}'.")
            user_input = input(f"Insert a valid IP address and port (e.g., 192.168.1.100:8080): ")
        else:
            # If both are valid, set them and exit the loop
            ip = temp_ip
            port = temp_port
            check = False # Exit condition met

    return ip, port


def pc_wifi_ip():
    """
    Get the IP address of the current PC on the Wi-Fi network.

    Returns:
        str: The IP address of the PC.
    """
    netifaces.gateways()
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]

    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

    return ip

def get_owner_from_app_id(app_id):
    cmd = ["adb", "-s", get_session_device_id(), "shell", f"pm list packages -U | grep {app_id} | cut -d: -f3"]

    output, error = Task().run(cmd)

    if error:
        print(f"Error occurred while getting owner from app ID {app_id}: {error}")
        return None

    return output.strip()

def get_app_id_from_owner_uid(owner_uid):
    cmd = ["adb", "-s", get_session_device_id(), "shell", f"pm list packages -U | grep {owner_uid} | cut -d: -f2 | cut -d' ' -f1"]

    output, error = Task().run(cmd)

    if error:
        print(f"Error occurred while getting app ID from owner UID {owner_uid}: {error}")
        return None

    return output.strip()
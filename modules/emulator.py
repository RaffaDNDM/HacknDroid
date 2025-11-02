"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import subprocess
import uuid
import re # Import regex for parsing avdmanager list avd output
from termcolor import colored
from modules.tasks_management import Task, DAEMONS_MANAGER
import sys
from tabulate import tabulate

# Map of compatible system images for each device
DEVICE_PACKAGE_MAP = {
    # 📱 Phones
    "pixel_c": [
        "system-images;android-30;google_apis;x86_64" # Android 11.0 ("R")
    ],
    "pixel_3": [
        "system-images;android-29;google_apis;x86_64", # Android 10.0 ("Q")
        "system-images;android-30;google_apis;x86_64", # Android 11.0 ("R")
        "system-images;android-31;google_apis;x86_64" # Android 12.0 ("S")
    ],
    "pixel_4": [
        "system-images;android-32;google_apis;x86_64" # Android 12L ("Sv2")
    ],
    "pixel_6": [
        "system-images;android-33;google_apis;x86_64", # Android 13.0 ("Tiramisu")
        "system-images;android-34;google_apis;x86_64" # Android 14.0 ("UpsideDownCake")
    ],
    "pixel_7": [
        "system-images;android-34;google_apis;x86_64" # Android 14.0 ("UpsideDownCake")
    ],


    # 📺 TV
    "tv_1080p": [
        "system-images;android-32;google_apis;x86_64" # Android 12L ("Sv2")
    ],

    # 🚗 Automotive
    "automotive_1024p_landscape": [
        "system-images;android-30;google_apis;x86_64" # Android 11.0 ("R")
    ],
}

def list_available_avds_pretty(user_input):
    """Prints available AVDs in a formatted way."""
    avds = get_existing_avds()
    if not avds:
        print("📃 No AVDs found.")
    
    else:
        print("📃 Existing AVDs:")

        color_headers = [colored("Name", "blue"),
                         colored("Device", "blue"),
                         colored("Package", "blue")]
        row_list = []
        for avd in avds:
            row = []

            row.append(colored(avd.get('name', 'N/A'),'yellow'))
            row.append(avd.get('device', 'N/A'))
            row.append(avd.get('package', 'N/A'))

            row_list.append(row)
            
        print("\n"+tabulate(row_list, headers=color_headers, tablefmt='fancy_grid'), end='\n\n')

def launch_avd_emulator(user_input):
    avd_name, avd_device, avd_package = select_avd()

    if avd_name:
        cmd = [ "emulator.exe",
            "-avd", avd_name,
            "-no-boot-anim",
            "-netspeed", "full",
            "-netdelay", "none",
            "-gpu", "host",
            "-writable-system"
        ]
        print(f"🚀 Launching emulator '{avd_name}' in background...")
        # Launching emulator blocks the terminal, allowing script to continue

        id = DAEMONS_MANAGER.get_next_id()
        DAEMONS_MANAGER.add_task('emulator', cmd)
        additional_info = {'AVD name':avd_name, 'Device': avd_device, 'Package': avd_package}
        DAEMONS_MANAGER.add_info('emulator', id, additional_info)

def create_avd_device(user_input):
    # 1. Get user desired device and package
    chosen_device_name = choose_device()
    chosen_package_path = choose_package(chosen_device_name)
    chosen_abi = "x86_64" if "x86_64" in chosen_package_path else "x86"

    # 2. Check if selected package is installed
    print("\n🔍 Checking installed SDK packages...")
    installed_sdk_packages = get_installed_packages()

    # Get API level from the chosen package for platform installation
    api_level_match = re.search(r'android-(\d+)', chosen_package_path)
    if api_level_match:
        api_level = f"platforms;android-{api_level_match.group(1)}"
        if not is_package_installed(api_level, installed_sdk_packages):
            if not install_package(api_level):
                exit(1)
        else:
            print(f"📦 Platform '{api_level}' is already installed.")
    else:
        print(f"⚠️ Could not determine API level from package path: {chosen_package_path}")

    # Finally, check and install the chosen system image package
    if not is_package_installed(chosen_package_path, installed_sdk_packages):
        if not install_package(chosen_package_path):
            exit(1)
    else:
        print(f"📦 System image '{chosen_package_path}' is already installed.")

    if "wear" in chosen_device_name and not is_package_installed("device-definitions", installed_sdk_packages):
        install_package("wearable")

    # 3. Check for existing AVDs with same characteristics
    print("\n🔍 Checking for existing AVDs...")
    existing_avds = get_existing_avds()
    matching_avds = []

    for avd in existing_avds:
        # Check for device and package match
        # Note: The device skin name from avdmanager list avd might not be exact match to DEVICE_PACKAGE_MAP keys
        # We'll try to be flexible by checking if the chosen_device_name is part of the AVD's device name,
        # or if the avd's device name is part of the chosen device name.
        device_match = (chosen_device_name.lower() in avd.get('device', '').lower() or
                        avd.get('device', '').lower() in chosen_device_name.lower())
        package_match = (chosen_package_path == avd.get('package'))

        if device_match and package_match:
            matching_avds.append(avd)

    chosen_avd_name = None

    if matching_avds:
        print("💡 Found existing AVD(s) with similar characteristics:")
        for i, avd in enumerate(matching_avds):
            print(f"  {i + 1}. Name: {avd['name']}, Device: {avd['device']}, Package: {avd['package']}")
        
        while True:
            user_choice = input("Do you want to use an existing AVD (enter number), create a new one (n), or Ctrl+C to exit? ").strip().upper()
            if user_choice.lower() == 'n':
                chosen_avd_name = f"MyTestDevice_{uuid.uuid4().hex[:6]}"
                print(f"✨ Will create a new AVD: {chosen_avd_name}")
                break
            else:
                try:
                    avd_index = int(user_choice) - 1
                    if 0 <= avd_index < len(matching_avds):
                        chosen_avd_name = matching_avds[avd_index]['name']
                        print(f"✅ Using existing AVD: {chosen_avd_name}")
                        break
                    else:
                        print("❌ Invalid selection. Please enter a valid number, 'N', or 'X'.")
                except ValueError:
                    print("❌ Invalid input. Please enter a valid number, 'N', or 'X'.")
    else:
        chosen_avd_name = f"MyTestDevice_{uuid.uuid4().hex[:6]}"
        print(f"✨ No matching AVDs found. Creating a new AVD: {chosen_avd_name}")


    # 4. Create AVD if a new one is chosen
    if chosen_avd_name and chosen_avd_name not in [avd['name'] for avd in existing_avds]:
        if not create_avd(avd_name=chosen_avd_name, package=chosen_package_path, device_skin=chosen_device_name, abi=chosen_abi):
            print("🛑 AVD creation failed. Exiting.")
            exit(1)

def delete_avd(user_input):
    avd_name, avd_device, avd_package = select_avd()

    if avd_name:
        try:
            output, error = Task().run(["avdmanager", "delete", "avd", "--name", avd_name], is_shell=True)
            print(f"✅ AVD '{avd_name}' deleted successfully.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error deleting AVD '{avd_name}': {e}")

def select_avd():
    existing_avds = get_existing_avds()
    avd_name = None

    if existing_avds:
        while True:
            row_list = [[colored(i, "red"), colored(avd['name'], "yellow"), avd['device'], avd['package']] for i, avd in enumerate(existing_avds)]
            
            color_headers = [colored("ID", "blue"),
                            colored("Name", "blue"),
                            colored("Device", "blue"),
                            colored("Package", "blue")]
            
            print("\n"+tabulate(row_list, headers=color_headers, tablefmt='fancy_grid'), end='\n\n')

            try:
                choice = int(input("Select an AVD to launch by number: "))
                if 0 <= choice < len(existing_avds):
                    selected_avd = existing_avds[choice]
                    return selected_avd['name'], selected_avd['device'], selected_avd['package']
                else:
                    print("❌ Invalid selection, try again.")
            except ValueError:
                print("❌ Please enter a valid number.")

    else:
        print("❌ No existing AVDs found. Please create one first.")
        return None, None, None

def get_installed_packages():
    """Returns a set of currently installed SDK packages."""
    installed_packages = set()
    
    output, error = Task().run(["sdkmanager", "--list_installed"], is_shell=True)
    
    if not error:
        # sdkmanager --list_installed output format:
        # Path | Version | Description | Location
        # ------|-------|-------------|---------
        # platform-tools | 34.0.5 | Android SDK Platform-Tools | ...
        # system-images;android-34;google_apis;x86_64 | 15 | Google APIs Intel x86_64 Atom System Image | ...

        # Regular expression to capture the package path
        # It looks for lines starting with a path (not headers or separators)
        # and captures everything up to the first space or pipe.
        for line in output.decode("utf-8").splitlines():
            match = re.match(r'^(.*?)\s+\|', line)
            if match and not match.group(1).startswith('---') and not match.group(1).startswith('Path'):
                package_path = match.group(1).strip()
                installed_packages.add(package_path)
        
    return installed_packages

def is_package_installed(package, installed_packages_set):
    """Checks if a specific package is in the set of installed packages."""
    return package in installed_packages_set

def install_package(package):
    print(f"⬇️ Installing package '{package}'...")
    output, error = Task().run(["sdkmanager", package], is_shell=True, input_to_cmd=["y",])
    
    if not error:
        print(f"✅ Package '{package}' installed successfully.")
        return True

    return False

def get_existing_avds():
    """
    Parses 'avdmanager list avd' output and returns a list of dictionaries
    with AVD name, device, and package.
    """
    avds = []
    command = ["avdmanager", "list", "avd"]
    output, error = Task().run(command, is_shell=True)

    if error or not output:
        return avds

    current_avd = {}
    for line in output.decode("utf-8").splitlines():
        line = line.strip()

        if not line:
            continue

        # Pattern for AVD name: 'Name: <AVD_NAME>'
        name_match = re.match(r'Name:\s*(.*)', line)
        if name_match:
            if current_avd: # Save previous AVD if exists
                avds.append(current_avd)
            current_avd = {"name": name_match.group(1).strip()}
            continue

        # Pattern for Device: 'Device: <DEVICE_NAME>'
        device_match = re.match(r'Device:\s*(.*?)\s*\(.*?\)|\s*Path:\s*.*/devices/(.*?)/.*', line)
        if device_match:
            current_avd["device"] = device_match.group(1).strip() if device_match.group(1) else device_match.group(2).strip()
            continue

        # Pattern for Package: 'Package: <PACKAGE_PATH>'
        package_match = re.match(r'Based on:\s*(.*)\s*Tag\/ABI:\s*(.*)', line)
        if package_match:
            current_avd["package"] = package_match.group(1).strip()
            current_avd["abi"] = package_match.group(2).strip()
            continue
    
    if current_avd: # Add the last parsed AVD
        avds.append(current_avd)

    return avds

def create_avd(avd_name, package, device_skin, abi="x86", sdcard_size="512M"):
    """
    Creates an AVD.
    device_skin corresponds to the '--device' argument in avdmanager.
    """
    cmd = [
        "avdmanager.bat", "create", "avd",
        "--name", avd_name,
        "--package", package,
        "--device", device_skin, # Use device_skin for the --device argument
        "--abi", abi,
        "--sdcard", sdcard_size,
        "--force" # --force is good for non-interactive creation, but prompts for custom settings (like RAM)
    ]
    # For AVD creation, avdmanager might ask for custom hardware profile settings.
    # We pass a newline character (b'\n') to accept default settings.
    print(f"🏗️ Creating AVD '{avd_name}' with package '{package}' and device '{device_skin}'...")
    sys.stdout.flush()  # Ensure output is flushed immediately
    output, error = Task().run(cmd, is_shell=True, input_to_cmd=["\n",])
    
    if not error:
        print(f"✅ AVD '{avd_name}' created successfully.")
        return True
    return False

def choose_device():
    devices = list(DEVICE_PACKAGE_MAP.keys())
    print("\n📱 Available devices:")
    for i, dev in enumerate(devices):
        print(f"  {i + 1}. {dev}")
    while True:
        try:
            choice = int(input("Select a device by number: ")) - 1
            if 0 <= choice < len(devices):
                return devices[choice]
            else:
                print("❌ Invalid selection, try again.")
        except ValueError:
            print("❌ Please enter a valid number.")

def choose_package(device):
    packages = DEVICE_PACKAGE_MAP[device]
    print(f"\n📦 Compatible system images for '{device}':")
    for i, pkg in enumerate(packages):
        print(f"  {i + 1}. {pkg}")
    while True:
        try:
            choice = int(input("Select a system image by number: ")) - 1
            if 0 <= choice < len(packages):
                return packages[choice]
            else:
                print("❌ Invalid selection, try again.")
        except ValueError:
            print("❌ Please enter a valid number.")
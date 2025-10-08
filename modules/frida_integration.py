"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import os
import requests
import time
import lzma
import shutil
from modules.tasks_management import Task
from prompt_toolkit.styles import Style
from modules.file_transfer import mobile_exists
from modules.adb import get_session_device_id
from modules.utility import app_id_from_user_input
import questionary
from questionary.prompts.common import Choice

FRIDA_SCRIPTS_PATH = os.path.join(os.path.dirname(__file__), '../frida_scripts')
FRIDA_TOOLS_VERSION = "13.0.0"

"""
Frida Server setup on mobile device
"""
def get_android_arch():
    print("[*] Detecting Android architecture...")    
    cmd = ['adb', '-s', get_session_device_id(), 'shell', 'getprop', 'ro.product.cpu.abi']
    output, error = Task().run(cmd)

    arch = output.strip()
    print(f"[*] Architecture: {arch}")
    return arch

def download_frida_server(arch, version):
    arch_map = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "i386",
        "x86_64": "x86_64"
    }

    frida_arch = arch_map.get(arch)

    """response = requests.get("https://api.github.com/repos/frida/frida/releases/latest")
    response_json = json.loads(response.text)
    version = response_json['tag_name']"""
    
    if not frida_arch:
        raise ValueError(f"Unsupported architecture: {arch}")

    file_name = f"frida-server-{version}-android-{frida_arch}"
    url = f"https://github.com/frida/frida/releases/download/{version}/{file_name}.xz"
    print(f"[*] Downloading: {url}")
    response = requests.get(url)

    frida_folder = os.path.join(os.getcwd(), "dependencies", "frida")
    print(frida_folder)
    os.makedirs(frida_folder, exist_ok=True)
    xz_path = os.path.join(frida_folder, f"{file_name}.xz")
    output_path = os.path.join(frida_folder, f"frida-server")
    
    with open(xz_path, "wb") as f:
        f.write(response.content)

    with lzma.open(xz_path, "rb") as xz_file, open(output_path, "wb") as out_file:
        shutil.copyfileobj(xz_file, out_file)

    return output_path, version

def push_frida_server(frida_binary_path):
    print("[*] Pushing Frida server to device...")
    cmd = ['adb', '-s', get_session_device_id(),"push", frida_binary_path, "/data/local/tmp/frida-server"]
    output, error = Task().run(cmd)

    print("[*] Changing permissions of the Frida server...")
    cmd = ['adb', '-s', get_session_device_id(), 'shell', "chmod", "755", "/data/local/tmp/frida-server"]
    output, error = Task().run(cmd)

def run_frida_server():
    if is_running_frida_server():
        print("Frida server already running")
    else:
        print("[*] Starting Frida server (requires root)...")
        cmd = ['adb', '-s', get_session_device_id(), 'shell']
        output, error = Task().run(cmd, input_to_cmd=["su", "/data/local/tmp/frida-server & 1> /dev/null 2>&1"])
    
def is_running_frida_server():
    print("[*] Checking if Frida server is running...")
    cmd = ['adb', '-s', get_session_device_id(), 'shell']
    output, error = Task().run(cmd, input_to_cmd=["su", "pidof frida-server"])

    try:
        pid = int(output)
        return True
    except:
        return False

def stop_frida_server():
    if is_running_frida_server():
        print("[*] Stopping Frida server...")
        cmd = ['adb', '-s', get_session_device_id(), 'shell']
        output, error = Task().run(cmd, input_to_cmd=["su", "pkill -f frida-server"])
        print("[*] Frida server stopped.")
    
    else:
        print("[*] Frida server not running.")


def is_installed_frida_server():
    if mobile_exists(["/data/local/tmp/frida-server",]):
        print("Frida server was already installed.")
        return True

    else:
        print("Frida server not installed.")
        return False


def uninstall_frida_server():
    if is_installed_frida_server:
        print("Uninstalling the Frida server...")
        cmd = ['adb', '-s', get_session_device_id(), 'shell']
        output, error = Task().run(cmd, input_to_cmd=["su", "rm /data/local/tmp/frida-server"])

def run_frida_script_on_running_app(user_input):
    # Check for Frida installation
    if not (is_installed_frida_server() and get_installed_version("frida") and get_installed_version("frida-tools")):
        print("Frida is not installed...")
        print("Install Frida and start the Frida server before launching the script")
        return

    import frida
    
    # Get the USB device
    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        print(f"Error: Could not connect to a USB device. Make sure your device is connected and USB debugging is enabled.")
        return

    # List all running processes
    print("[*] Listing running processes...")
    try:
        processes = [p for p in device.enumerate_applications() if p.pid > 0]
    except Exception as e:
        print(f"Error: Could not enumerate processes. Is the Frida server running on the device?")
        return

    if not processes:
        print("No running processes found.")
        return

    choices = [Choice(title=f"{p.name} > {p.identifier} (PID: {p.pid})", value=p.pid) for p in processes]

    # Ask the user to select a process to attach to
    try:
        pid = questionary.select(
            "Select a process to attach to:",
            choices=choices,
            style=questionary.Style.from_dict({
                'pointer': 'fg:#00ffff bold',
                'selected': 'fg:#0000ff bg:#444444',
            })
        ).ask()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return

    if not pid:
        print("No process selected. Exiting.")
        return

    print(f"[*] Attaching to process with PID: {pid}...")
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"Error: Could not attach to the process. Make sure the app is running and you have necessary permissions.")
        return

    # The rest of your script for handling Frida scripts remains the same
    scripts = os.listdir(FRIDA_SCRIPTS_PATH)
    scripts_names = {s.replace("_"," ").replace(".js", ""):os.path.join(FRIDA_SCRIPTS_PATH,s) for s in scripts}

    title = "Select the scripts to be used and then press Enter\n"
    
    # Define custom style
    custom_style = questionary.Style.from_dict({
        'question': 'bold',
        'answer': 'fg:#00ff00 bold',
        'pointer': 'fg:#00ffff bold',
        'highlighted': 'fg:#ff0000 bold',
        'selected': 'fg:#0000ff bg:#444444',
        'separator': 'fg:#cc5454',
        'instruction': '',  # default
        'text': '',         # default
    })
    
    # Ask the question
    selected = questionary.checkbox(
        title,
        choices=list(scripts_names.keys()),
        style=custom_style
    ).ask()
    
    selected_filenames = []
    script_source = ''

    if selected:
        selected_filenames = [scripts_names[x] for x in selected] 

        for script_name in selected_filenames:
            with open(script_name, "r") as f:
                script_source = script_source + '\n\n' + f.read()

    if script_source != "":
        # Step 4: Create script objects
        script = session.create_script(script_source)

        # Optional: Set message handlers
        def on_message(message, data):
            print("[*] Message:", message)

        script.on("message", on_message)
        script.load()

        input("[*] Press Enter to detach...\n")
        session.detach()
        print("[*] Detached from the process.")
    else:
        print("Scripts not specified. Detaching from the process.")
        session.detach()
        
    print("[*] Exiting script.")

def spawn_app_and_run_frida_script(user_input):
    if not (is_installed_frida_server() and get_installed_version("frida") and get_installed_version("frida-tools")):
        print("Frida is not installed...")
        print("Install Frida and start Frida server before launching the script")
        return

    import frida

    package_name = app_id_from_user_input(user_input)
    scripts = os.listdir(FRIDA_SCRIPTS_PATH)
    scripts_names = {s.replace("_"," ").replace(".js", ""):os.path.join(FRIDA_SCRIPTS_PATH,s) for s in scripts}

    title = "Select the scripts to be used and then press Enter\n"

    # Define custom style
    custom_style = Style.from_dict({
        'question': 'bold',
        'answer': 'fg:#00ff00 bold',
        'pointer': 'fg:#00ffff bold',
        'highlighted': 'fg:#ff0000 bold',
        'selected': 'fg:#0000ff bg:#444444',
        'separator': 'fg:#cc5454',
        'instruction': '',  # default
        'text': '',         # default
    })

    # Define choices (colors are defined in the style, not per choice)
    
    # Ask the question
    selected = questionary.checkbox(
        title,
        choices=list(scripts_names.keys()),
        style=custom_style
    ).ask()
    
    selected_filenames = []
    script_source = ''

    if selected:
        selected_filenames = [scripts_names[x] for x in selected] 

        for script_name in selected_filenames:
            with open(script_name, "r") as f:
                script_source = script_source + '\n\n' + f.read()

    print("[*] Attaching to app with Frida...")
    device = frida.get_usb_device()
    # pid = device.spawn(package_name)
    pid = device.spawn([package_name,])
    pid = device.get_process(package_name).pid
    session = device.attach(pid)  # pidof package_name
    
    if script_source != "":
        # Step 4: Create script objects
        script = session.create_script(script_source)

        # Optional: Set message handlers
        def on_message(message, data):
            print("[*] Message:", message)

        script.on("message", on_message)

        script.load()

        time.sleep(2)
        device.resume(pid)
    
        input("[*] Press Enter to detach...\n")
    else:
        print("Scripts not specified")

def check_version_on_device():
    cmd = ["adb","shell"]

    output, error = Task().run(cmd, input_to_cmd=["su", "/data/local/tmp/frida-server --version"])
    return output

"""
Frida and Frida-tools installation via pip
"""
def get_installed_version(package_name):
    try:
        # Try importlib.metadata (Python 3.8+)
        from importlib.metadata import version
        try:
            return version(package_name)
        except Exception:
            return None
    except ImportError:
        # Fallback to pkg_resources for older Python versions
        try:
            import pkg_resources
            return pkg_resources.get_distribution(package_name).version
        except Exception:
            return None

def install_package(package_name, version):
    print(f"Installing {package_name}...")
    output, error = Task().run(["pip", "install", f"{package_name}=={version}"], input_to_cmd=["y"])

def uninstall_package(package_name):
    print(f"Uninstalling {package_name}...")
    output, error = Task().run(["pip", "uninstall", package_name], input_to_cmd=["y"])

def start_frida(user_input):
    run_frida_server()

def stop_frida(user_input):
    stop_frida_server()
    
def install_frida(user_input):
    arch = get_android_arch()
    version = get_installed_version("frida")

    if version:
        uninstall_package("frida")
        uninstall_package("frida-tools")
    
    install_package("frida-tools", FRIDA_TOOLS_VERSION)
    version = get_installed_version("frida")
    frida_server_binary, version = download_frida_server(arch, get_installed_version("frida"))
    stop_frida_server()
    push_frida_server(frida_server_binary)

def uninstall_frida():
    version = get_installed_version("frida")

    if version:
        uninstall_package("frida")
        uninstall_package("frida-tools")
    
    stop_frida_server()
    uninstall_frida_server()
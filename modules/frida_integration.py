"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0

This module provides integration helpers for Frida:
- Installing / uninstalling frida Python packages and frida-server binaries on device
- Managing frida-server processes on the device
- Creating and running Frida scripts (JS / TS bridge support)
- Utility helpers to detect environment (venv node/npm, Android arch)
"""
from questionary import Choice
import questionary
from tabulate import tabulate
from termcolor import colored
from modules.apk_install import install_from_playstore
from modules.tasks_management import Task
from modules.adb import get_session_device_id
import requests
import os
import shutil
import os
import requests
import time
import lzma
import shutil
from prompt_toolkit.styles import Style
from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from modules.file_transfer import is_mobile_file, is_mobile_folder, upload_to_dest
from modules.useful_stuff import reboot
from modules.utility import app_id_from_user_input
import sys
import platform


# Base paths and constants
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.join(BASE_DIR, "..", ".frida-agent")
PREFIX_IN_SCRIPT = """//Ignore TypeScript strict errors for now
//@ts-nocheck
import Java from 'frida-java-bridge';"""
FRIDA_SCRIPTS_PATH = os.path.join(os.path.dirname(__file__), "..", "frida_scripts")

# Styles used for the selection UI
FRIDA_JS_SCRIPT_SELECTION_STYLES = Style.from_dict({
    'question': 'bold',
    'answer': 'fg:#00ff00 bold',
    'pointer': 'fg:#00ffff bold',
    'highlighted': 'fg:#ff0000 bold',
    'selected': 'fg:#0000ff bg:#444444',
    'separator': 'fg:#cc5454',
})


def is_installed_frida_server():
    """Return True if any frida-server binaries are present on the connected device."""
    return len(list_frida_servers_on_device()) > 0


def uninstall_frida_server(frida_version=None, fridatools_version=None):
    """Remove a specific frida-server binary from the device (requires root)."""
    print("Uninstalling the Frida server...")
    cmd = ['adb', '-s', get_session_device_id(), 'shell']
    output, error = Task().run(cmd, input_to_cmd=["su", f"rm /data/local/tmp/frida-servers/frida-server_{frida_version}_{fridatools_version}"])


def pip_versions(package_name):
    """Return list of available versions for a pip package from PyPI JSON API."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    data = requests.get(url).json()
    versions = list(data["releases"].keys())
    return versions


class VersionTrieCompleter(Completer):
    """Simple completion helper that completes full version strings from a list."""

    def __init__(self, versions):
        # treat full version strings as flat values
        self.versions = versions

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor

        for version in self.versions:
            if version.startswith(text):
                yield Completion(version, start_position=-len(text))


def uninstall_frida_modules(user_input):
    """Uninstall frida and frida-tools pip packages if present."""
    frida_version = get_installed_pip_package_version("frida")
    if frida_version:
        uninstall_package("frida")

    if int(frida_version.split('.')[0])>=17:
        print("Removing frida agent template...")
        if os.path.isdir(AGENT_DIR):
            shutil.rmtree(AGENT_DIR)

    if get_installed_pip_package_version("frida-tools"):
        uninstall_package("frida-tools")


def is_version_available_on_pip(package_name, package_version):
    """Check if a given version exists on PyPI for the package."""
    return package_version in pip_versions(package_name)


def get_installed_pip_package_version(package_name):
    """
    Return installed pip package version.
    Tries importlib.metadata first (py3.8+), falls back to pkg_resources.
    Returns None if not installed.
    """
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


def install_pip_package(package_name, version):
    """Install a pip package into the current Python environment."""
    print(f"Installing {package_name}...")

    if version == 'latest':
        output, error = Task().run(["pip", "install", package_name], input_to_cmd=["y"])
    else:
        output, error = Task().run(["pip", "install", f"{package_name}=={version}"], input_to_cmd=["y"])

    print(output)


def uninstall_package(package_name):
    """Uninstall a pip package from the current environment."""
    print(f"Uninstalling {package_name}...")
    output, error = Task().run(["pip", "uninstall", package_name], input_to_cmd=["y"])
    print(output)


def get_pid_running_frida_server(frida_version=None, fridatools_version=None):
    """
    Return PID of a running frida-server on the device.
    If frida_version & fridatools_version are provided, look for that specific binary name.
    Returns -1 if not found or parsing fails.
    """
    cmd = ['adb', '-s', get_session_device_id(), 'shell']

    if frida_version and fridatools_version:
        # Search for a specific named binary
        print(f"[*] Checking if Frida server {frida_version} is running...")
        output, error = Task().run(cmd, input_to_cmd=["su",
                                                  f"ps -A | grep frida-server_{frida_version}_{fridatools_version}"+
                                                  " | grep -v grep | awk '{print $2}'"])
    else:
        # Generic lookup for any frida-server process
        print("[*] Checking if Frida server is running...")
        output, error = Task().run(cmd, input_to_cmd=["su",
                                                  f"ps -A | grep frida-server"+
                                                  " | grep -v grep | awk '{print $2}'"])

    try:
        pid = int(output)
        return pid
    except:
        # Non-integer output -> no running process found
        return -1


def run_frida_server(frida_version, fridatools_version):
    """
    Start the frida-server binary on the device. Uses su to run the binary in background.
    If another running frida-server is found, it will be killed first.
    """
    if get_pid_running_frida_server(frida_version, fridatools_version) > 0:
        print("Frida server already running")
    else:
        pid = get_pid_running_frida_server()
        if pid > 0:
            # kill generic frida-server if found
            kill_process(pid)

        print(f"[*] Starting Frida server {frida_version} (requires root)...")
        print(colored("Press Ctrl+C to send the daemon in background", 'green'))
        cmd = ['adb', '-s', get_session_device_id(), 'shell']
        input_to_cmd=["su", f"/data/local/tmp/frida-servers/frida-server_{frida_version}_{fridatools_version} & 1> /dev/null 2>&1"]
        output, error = Task().run(cmd, input_to_cmd=input_to_cmd)


def kill_process(pid : int):
    """Force kill a process on the device given its PID (requires root)."""
    if pid>0:
        cmd = ['adb', '-s', get_session_device_id(), 'shell', f"su -c 'kill -9 {pid}'"]
        output, error = Task().run(cmd)
    else:
        print("No running process!!!")


def get_venv_node_path():
    """Return node binary path inside the current virtualenv (cross-platform)."""
    if platform.system() == "Windows":
        return os.path.join(sys.prefix, "Scripts", "node.exe")
    else:
        return os.path.join(sys.prefix, "bin", "node")


def get_venv_npm_path():
    """Return npm binary path inside the current virtualenv (cross-platform)."""
    if platform.system() == "Windows":
        return os.path.join(sys.prefix, "Scripts", "npm.cmd")
    else:
        return os.path.join(sys.prefix, "bin", "npm")


def is_node_in_venv():
    """Check if node is present in the current virtualenv."""
    return os.path.isfile(get_venv_node_path())


def ensure_nodeenv():
    """
    Ensure nodeenv is installed and a node/npm environment is created inside
    the Python virtualenv. This enables building Frida agents that require npm.
    """
    if is_node_in_venv():
        print("✔ Node is already installed in venv:", get_venv_node_path())
        return

    print("📦 Installing nodeenv...")
    output, error = Task().run([sys.executable, "-m", "pip", "install", "nodeenv"], input_to_cmd=["y"])
    print(output)

    print("📦 Creating Node environment inside venv...")
    output, error = Task().run(["nodeenv", "-p"], input_to_cmd=["y"])
    print(output)

    if is_node_in_venv():
        print("✔ Node + npm successfully installed into virtual environment!")
    else:
        print("❌ Failed to install Node into venv.")
        sys.exit(1)


def ensure_frida_agent_template():
    """
    Create a frida agent template folder using frida-create if it does not exist.
    The agent template can be extended and built with npm later.
    """
    if os.path.isdir(AGENT_DIR):
        print("✔ Agent already exists:", AGENT_DIR)
        return

    print("📦 Creating agent template...")
    os.makedirs(os.path.dirname(AGENT_DIR), exist_ok=True)
    output, error = Task().run(["frida-create", "-o", AGENT_DIR, "-t", "agent"])
    print(output)

    print("✔ Agent created at:", AGENT_DIR)


def install_npm_packages():
    """
    Run npm install inside the agent folder and install frida-java-bridge, required
    when using frida >= 17 and TypeScript/JS bridge code.
    """
    npm = get_venv_npm_path()
    if not os.path.isfile(npm):
        print("❌ npm not found at:", npm)
        sys.exit(1)

    print("📦 Running npm install in agent folder...")
    output, error = Task().run([npm, "install"], cwd=AGENT_DIR)
    print(output)

    print("📦 Installing frida-java-bridge in agent folder...")
    output, error = Task().run([npm, "install", "frida-java-bridge"], cwd=AGENT_DIR)
    print(output)


def build_agent():
    """Build the npm agent (optional). Checks for the generated _agent.js after build."""
    npm = get_venv_npm_path()
    print("🔨 Building agent...")
    output, error = Task().run([npm, "run", "build"], cwd=AGENT_DIR)
    print(output)

    built_js = os.path.join(AGENT_DIR, "_agent.js")
    if os.path.isfile(built_js):
        print("✔ Agent build successful:", built_js)
    else:
        # Not fatal: continue, agent build may be optional depending on frida version
        print("⚠️ Agent build skipped or failed — continuing.")


def setup_bridge():
    """Ensure nodeenv and agent template are present and npm dependencies are installed."""
    ensure_nodeenv()
    ensure_frida_agent_template()
    install_npm_packages()


def install_frida_modules(fridatools_version):
    """
    Install frida-tools (requested version) and inspect installed frida version.
    If frida major version >= 17, ensure the JS/TS agent bridge environment is prepared.
    Returns tuple (frida_version, fridatools_version) after install.
    """
    # Install frida-tools version
    current_version = get_installed_pip_package_version('frida-tools')
    
    if current_version and current_version != fridatools_version:
        install_pip_package('frida-tools', fridatools_version)
    
    frida_version = get_installed_pip_package_version('frida')

    if int(frida_version.split('.')[0]) >= 17:
        # Newer Frida uses JS bridge; prepare agent + npm deps
        setup_bridge()

    return frida_version, fridatools_version


def print_current_frida_modules_versions():
    """Return a tuple with currently installed (frida_version, fridatools_version)."""
    # Default to currently installed frida-tools or "latest"
    current_frida_version = get_installed_pip_package_version("frida")
    current_fridatools_version = get_installed_pip_package_version("frida-tools")
    
    print(colored("\nCurrent PIP Modules on PC:", 'green'), end="\n\n")
    rows = [
        [colored("Frida: ", 'red'),colored(current_frida_version if current_frida_version else "N/A", 'yellow')],
        [colored("Frida-tools: ", 'red'),colored(current_fridatools_version if current_fridatools_version else "N/A", 'yellow')]
    ]

    print(tabulate(rows, headers=[colored("Module", 'blue'), colored("Version", 'blue')], tablefmt='fancy_grid', colalign=('left', 'left')))
    
def get_android_arch():
    """Detect device CPU ABI used to select the correct frida-server binary."""
    print("[*] Detecting Android architecture...")
    cmd = ['adb', '-s', get_session_device_id(), 'shell', 'getprop', 'ro.product.cpu.abi']
    output, error = Task().run(cmd)

    arch = output.strip()
    print(f"[*] Architecture: {arch}")
    return arch


def download_frida_server(arch, frida_version, fridatools_version):
    """
    Download the appropriate frida-server .xz from GitHub releases, decompress it,
    and write the resulting binary into ./dependencies/frida/frida-server_{frida_version}_{fridatools_version}
    Returns the path to the decompressed binary file.
    """
    # Map Android ABI to Frida release arch notation
    arch_map = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "i386",
        "x86_64": "x86_64"
    }

    frida_arch = arch_map.get(arch)

    if not frida_arch:
        raise ValueError(f"Unsupported architecture: {arch}")

    file_name = f"frida-server-{frida_version}-android-{frida_arch}"
    print(colored("Frida version:       ", 'blue')+frida_version)
    print(colored("Frida-tools version: ", 'blue')+fridatools_version)

    url = f"https://github.com/frida/frida/releases/download/{frida_version}/{file_name}.xz"
    print(f"[*] Downloading: {url}")
    response = requests.get(url)

    frida_folder = os.path.join(os.getcwd(), "dependencies", "frida")
    print(frida_folder)
    os.makedirs(frida_folder, exist_ok=True)
    xz_path = os.path.join(frida_folder, f"{file_name}.xz")
    output_path = os.path.join(frida_folder, f"frida-server_{frida_version}_{fridatools_version}")

    # Save compressed file
    with open(xz_path, "wb") as f:
        f.write(response.content)

    # Decompress .xz to the final binary file
    with lzma.open(xz_path, "rb") as xz_file, open(output_path, "wb") as out_file:
        shutil.copyfileobj(xz_file, out_file)

    return output_path


def push_frida_server(frida_binary_path):
    """
    Upload the frida-server binary to /data/local/tmp/frida-servers on the device and set +x.
    Uses upload_to_dest helper for the actual file transfer.
    """
    # Ensure remote directory exists (is_mobile_folder checks via adb)
    if not is_mobile_folder("/data/local/tmp/frida-servers"):
        cmd = cmd = ['adb', '-s', get_session_device_id(), 'shell', " mkdir /data/local/tmp/frida-servers"]
        output, error = Task().run(cmd)

    if not is_mobile_file(f"/data/local/tmp/frida-servers/{os.path.basename(frida_binary_path)}"):
        print("Created /data/local/tmp/frida-servers on device")
        print("[*] Pushing Frida server to device...")
        # Upload binary to the device destination folder
        upload_to_dest(frida_binary_path, "/data/local/tmp/frida-servers")

        print("[*] Changing permissions of the Frida server...")
        cmd = ['adb', '-s', get_session_device_id(), 'shell', f"su -c 'chmod 755 /data/local/tmp/frida-servers/{os.path.basename(frida_binary_path)}'"]
        output, error = Task().run(cmd)
        # Print command output / errors for debugging
        print(output)
        print(error)

    else:
        print(f"Frida server {os.path.basename(frida_binary_path)} already present on device.")


def install_frida_server(frida_version, fridatools_version):
    """Download correct frida-server for device architecture and push it to device."""
    arch = get_android_arch()
    # Download and push server to device, stored using a name containing both versions
    frida_server_binary = download_frida_server(arch, frida_version, fridatools_version)
    push_frida_server(frida_server_binary)


def fix_device_reboot_after_frida_server_run(user_input):
    """
    Docstring for fix_device_reboot_after_frida_server_run
    
    :param user_input: Description
    """
    #print("Uninstalling ART")
    #cmd = ['adb', '-s', get_session_device_id(), 'shell', "pm uninstall com.google.android.art"]
    #output, error = Task().run(cmd)
    #print(output)
    #print(error)
    #reboot('')
    print("Disable updates for Google Play Services")
    install_from_playstore('com.google.android.gms')


def install_frida(user_input):
    """
    Interactive flow to select a frida-tools version (with completions), install pip packages,
    and deploy the frida-server on the device.
    """
    print_current_frida_modules_versions()
    print_frida_servers_on_device('')

    fridatools_version = None

    # Retrieve versions list from PyPI for autocompletion
    versions = pip_versions("frida-tools")

    # Setup completer with versions
    fridatools_versions_completer = VersionTrieCompleter(versions)

    # Prompt until a valid version is provided
    while (not fridatools_version) or (not is_version_available_on_pip("frida-tools", fridatools_version) and not fridatools_version == 'latest'):
        fridatools_version = prompt("Specify the version of frida-tools you want to use ('latest' or version number):\n",
                                   completer=fridatools_versions_completer, multiline=False)

    # Install modules & server
    frida_version, fridatools_version = install_frida_modules(fridatools_version)
    install_frida_server(frida_version, fridatools_version)


def list_frida_servers_on_device():
    """
    Return a list of frida-server binaries found on the device under /data/local/tmp/frida-servers.
    Each entry is [server_id, frida_version, frida_tools_version].
    """
    cmd = ["adb","shell"]
    output, error = Task().run(["adb", "shell", "ls /data/local/tmp/frida-servers"])

    # Parse filenames like frida-server_{frida}_{fridatools}
    tmp_list = [l.replace("frida-server_", "").split("_") for l in output.splitlines()]
    output_list = []

    for server_id, l in enumerate(tmp_list):
        # append a row with id, frida version, frida-tools version
        output_list.append([server_id, l[0], l[1]])

    return output_list


def print_frida_servers_on_device(user_input):
    """
    Print a nicely formatted table of frida-server binaries on the device.
    Highlights currently running server in red background.
    Returns the raw table rows for programmatic selection.
    """
    print(colored("\nFrida Servers on the mobile device:", 'green'), end="\n\n")
    table_rows = list_frida_servers_on_device()
    headers = [" Server ID ", " Frida ", " Frida Tools "]
    color_headers = [colored(h, 'blue') for h in headers]
    max_width = sum([len(header) for header in headers]) + 4

    formatted_rows = []
    for server_detail in table_rows:
        # Check if this specific server is running (by versioned name)
        if get_pid_running_frida_server(server_detail[1], server_detail[2])>0:
            # running server -> highlight ID with red background
            formatted_rows.append([colored(str(server_detail[0]).center(max(len(headers[0]),len(str(server_detail[0]))+2)), 'white', 'on_red'),
                                   colored(server_detail[1].center(max(len(headers[1]),len(server_detail[1])+2)), 'black', 'on_white'),
                                   colored(server_detail[2].center(max(len(headers[2]),len(server_detail[2])+2)), 'black', 'on_white')])
        else:
            formatted_rows.append([colored(str(server_detail[0]).center(max(len(headers[0]),len(str(server_detail[0]))+2)), 'red'),
                                   colored(server_detail[1].center(max(len(headers[1]),len(server_detail[1])+2)), 'yellow'),
                                   colored(server_detail[2].center(max(len(headers[2]),len(server_detail[2])+2)), 'yellow')])

    table_str=tabulate(formatted_rows, headers=color_headers, tablefmt='fancy_grid', colalign=('center', 'center', 'center'))
    print(table_str, end="\n\n")

    print(colored("Legend: ", 'white'), end=" ")
    print(colored(" Running server ", 'white', 'on_red'), end="\n\n")

    return table_rows


def start_server(user_input):
    """
    Interactive flow to select a frida-server present on the device and start it.
    Ensures local frida-tools pip version matches the selected server's tools version.
    """
    # Show servers and get a selection
    table_rows = print_frida_servers_on_device('')
    selected_server_name = ''

    while True:
        try:
            choice = int(prompt("Insert the Frida Server ID you want to use:\n"))

            if choice<0 or choice>= len(table_rows):
                raise ValueError
            else:
                selected_frida_version = table_rows[choice][1].strip()
                selected_fridatools_version = table_rows[choice][2].strip()
                selected_server_name = f'frida-server_{selected_frida_version}_{selected_fridatools_version}'
                break

        except ValueError:
            print(colored("\n[Invalid Server ID]", "red"), end=" ")

    # Print selection for debug
    print(selected_server_name)
    print(selected_frida_version)
    print(selected_fridatools_version)

    # If local frida-tools differs from device fridatools, reinstall Python packages
    if get_installed_pip_package_version("frida-tools") != selected_fridatools_version:
        uninstall_frida_modules('')
        install_pip_package("frida-tools", selected_fridatools_version)
    else:
        print(f"Frida-tools version {selected_fridatools_version} already installed on PC.")

    pid = get_pid_running_frida_server()

    # Start requested server (will kill existing generic frida-server if present)
    run_frida_server(selected_frida_version, selected_fridatools_version)


def uninstall_frida_server_on_device(user_input):
    """
    Interactive removal of a selected frida-server binary from the device.
    """
    print("Uninstalling Frida server from mobile device...")
    table_rows = print_frida_servers_on_device('')
    selected_server_name = ''

    while True:
        try:
            choice = int(prompt("Insert the Frida Server ID you want to use:\n"))

            if choice<0 or choice>= len(table_rows):
                raise ValueError
            else:
                selected_frida_version = table_rows[choice][1].strip()
                selected_fridatools_version = table_rows[choice][2].strip()
                selected_server_name = f'frida-server_{selected_frida_version}_{selected_fridatools_version}'
                break

        except ValueError:
            print(colored("\n[Invalid Server ID]", "red"), end=" ")

    uninstall_frida_server(selected_frida_version, selected_fridatools_version)


def patch_custom_frida_script(js_content):
    """Copy custom script to agent folder for compilation."""

    dest_path = os.path.join(AGENT_DIR, "tmp.ts")

    with open(dest_path, "w", encoding="utf8") as f:
        f.write(PREFIX_IN_SCRIPT + "\n\n" + js_content)

    return dest_path

def run_frida_ts_scripts_on_running_app():
    """
    Placeholder for running TypeScript/TS-based Frida scripts against a running app.
    Implementation should handle building/patching TS -> JS with the agent bridge.
    """
    import frida

    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception:
        print("Error: Could not connect to USB device. Enable USB debugging.")
        return

    print("[*] Listing running processes...")
    try:
        # enumerate_applications returns objects with pid > 0 for running apps
        processes = [p for p in device.enumerate_applications() if p.pid > 0]
    except Exception:
        print("Error: Could not enumerate processes. Is the Frida server running?")
        return

    if not processes:
        print("No running processes found.")
        return

    choices = [
        Choice(title=f"{p.name} > {p.identifier} (PID: {p.pid})", value=p.pid)
        for p in processes
    ]

    try:
        pid = questionary.select(
            "Select a process to attach to:",
            choices=choices,
            style=FRIDA_JS_SCRIPT_SELECTION_STYLES
        ).ask()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return

    if not pid:
        print("No process selected.")
        return

    print(f"[*] Attaching to PID {pid}...")
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"Error: Could not attach. Check permissions and if app is running. Details: {e}")
        return

    js_content = select_scripts()
    
    if not js_content:
        print("No scripts selected.")
        return
    
    script_path = patch_custom_frida_script(js_content)


    if script_path:
        load_and_run_script(session, script_path, is_path=True)
    else:
        print("No scripts selected. Detaching.")
        session.detach()


def spawn_app_and_run_frida_ts_scripts(user_input):
    """
    Placeholder for spawning an app and running TypeScript/TS-based Frida scripts.
    """
    import frida
    package_name = app_id_from_user_input(user_input)

    # ---- Reused helper ----
    js_content = select_scripts()
    
    if not js_content:
        print("No scripts selected.")
        return
    
    script_path = patch_custom_frida_script(js_content)

    # Connect to USB device
    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=10)
    except Exception as e:
        print(f"❌ Could not connect to a USB device: {e}")
        return

    # Attach and run script
    print(f"[*] Attaching to app {colored(package_name, 'yellow')}", end=" ")
    pid = device.spawn([package_name])
    pid = device.get_process(package_name).pid
    print(f"(PID: {colored(pid, 'blue')})")
    
    session = device.attach(pid)

    if script_path:
        print(colored("HERE", "red"))
        load_and_run_script(session, script_path, is_path=True)

        # Allow application to initialize and then resume execution
        time.sleep(2)
        device.resume(pid)
    else:
        print("No scripts selected.")
        session.detach()
        return


def select_scripts():
    """
    Show a checkbox UI allowing the user to select one or more JS scripts from FRIDA_SCRIPTS_PATH.
    Reads and merges the selected scripts into a single source string and returns it.
    Returns None if no scripts selected.
    """
    scripts = os.listdir(FRIDA_SCRIPTS_PATH)
    script_map = {
        s.replace("_", " ").replace(".js", ""): os.path.join(FRIDA_SCRIPTS_PATH, s)
        for s in scripts
    }

    selected = questionary.checkbox(
        "Select the scripts to be used and then press Enter\n",
        choices=list(script_map.keys()),
        style=FRIDA_JS_SCRIPT_SELECTION_STYLES
    ).ask()

    if not selected:
        return None

    merged_source = ""
    for name in selected:
        with open(script_map[name], "r") as f:
            merged_source += "\n\n" + f.read()

    return merged_source if merged_source.strip() else None


def load_and_run_script(session, script_source, is_path=False):
    """
    Create a Frida script in the given session, hook message handler, load it,
    and block until user presses Enter to detach.
    """

    if is_path:
        from frida import Compiler
        from frida import InvalidArgumentError

        print("[*] Compiling custom script...")
        try:            
            compiler = Compiler()
            compiler.on("diagnostics", lambda diags: print("[diagnostics]", diags))

            script_source = compiler.build(script_source)
        except InvalidArgumentError as e:
            print(f"❌ Compilation failed: {e}")
            return
    
    script = session.create_script(script_source)

    def on_message(message, data):
        # Basic message callback: print any messages received from script
        print("[*] Message:", message)

    script.on("message", on_message)
    script.load()

    input(colored("\n[*] Press Enter to detach...\n", "green"))
    session.detach()
    print("[*] Detached from the process.")


def run_frida_js_scripts_on_running_app():
    """
    Attach to a running process on the connected USB device, let the user select scripts,
    and load them into the process. Works with legacy JS scripts (frida < 17).
    """
    import frida

    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception:
        print("Error: Could not connect to USB device. Enable USB debugging.")
        return

    print("[*] Listing running processes...")
    try:
        # enumerate_applications returns objects with pid > 0 for running apps
        processes = [p for p in device.enumerate_applications() if p.pid > 0]
    except Exception:
        print("Error: Could not enumerate processes. Is the Frida server running?")
        return

    if not processes:
        print("No running processes found.")
        return

    choices = [
        Choice(title=f"{p.name} > {p.identifier} (PID: {p.pid})", value=p.pid)
        for p in processes
    ]

    try:
        pid = questionary.select(
            "Select a process to attach to:",
            choices=choices,
            style=FRIDA_JS_SCRIPT_SELECTION_STYLES
        ).ask()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return

    if not pid:
        print("No process selected.")
        return

    print(f"[*] Attaching to PID {pid}...")
    try:
        session = device.attach(pid)
    except Exception:
        print("Error: Could not attach. Check permissions and if app is running.")
        return

    # ---- Reused helper ----
    script_source = select_scripts()

    if script_source:
        load_and_run_script(session, script_source)
    else:
        print("No scripts selected. Detaching.")
        session.detach()


def spawn_app_and_run_frida_js_scripts(user_input):
    """
    Spawn an application specified by package name, attach to it and run selected JS scripts.
    Useful when the target app is not running yet.
    """
    import frida
    package_name = app_id_from_user_input(user_input)

    # ---- Reused helper ----
    script_source = select_scripts()

    # Connect to USB device
    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device(timeout=10)
    except Exception as e:
        print(f"❌ Could not connect to a USB device: {e}")
        return

    # Attach and run script
    print(f"[*] Attaching to app {colored(package_name, 'yellow')}", end=" ")
    pid = device.spawn([package_name])
    pid = device.get_process(package_name).pid
    print(f"(PID: {colored(pid, 'blue')})")
    
    session = device.attach(pid)

    if script_source:
        load_and_run_script(session, script_source)

        # Allow application to initialize and then resume execution
        time.sleep(2)
        device.resume(pid)
    else:
        print("No scripts selected.")
        session.detach()
        return


def run_script_on_running_app(user_input):
    """
    Entry-point to run a script on a running app.
    Ensures frida + frida-tools + frida-server are installed before proceeding.
    For frida >= 17, TS/bridge flow should be used (not implemented here).
    """
    if not (is_installed_frida_server() and get_installed_pip_package_version("frida") and get_installed_pip_package_version("frida-tools")):
        print("Frida is not installed...")
        print("Install Frida and start Frida server before launching the script")
        return

    if int(get_installed_pip_package_version("frida").split('.')[0]) >= 17:
        run_frida_ts_scripts_on_running_app()
        pass
    else:
        # Legacy JS flow
        run_frida_js_scripts_on_running_app()


def spawn_app_and_run_script(user_input):
    """
    Entry-point to spawn an app and run a script inside it.
    Ensures environment is available, chooses appropriate flow based on frida version.
    """
    if not (is_installed_frida_server() and get_installed_pip_package_version("frida") and get_installed_pip_package_version("frida-tools")):
        print("Frida is not installed...")
        print("Install Frida and start Frida server before launching the script")
        return

    if int(get_installed_pip_package_version("frida").split('.')[0]) >= 17:
        # TS/bridge spawn flow would go here
        spawn_app_and_run_frida_ts_scripts(user_input)
    else:
        spawn_app_and_run_frida_js_scripts(user_input)
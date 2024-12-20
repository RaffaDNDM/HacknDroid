from modules import utility
import subprocess
from prompt_toolkit import prompt, print_formatted_text
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
import config.menu as menu
import config.style as tool_style
from tabulate import tabulate
from modules.tasks_management import Task

def screenshot(user_input):
    pass

def record_video(user_input):
    pass

def reboot(user_input):
    choice = input("Are you sure you want to reboot the mobile device (y/n)? ")
    command = ['adb', 'shell', 'reboot']
    print(command)
    output, error = Task().run(command, is_shell=True)
    print(output)


def reboot_recovery(user_input):
    choice = input("Are you sure you want to reboot the mobile device (y/n)? ")
    command = ['adb', 'reboot', 'recovery']
    print(command)
    output, error = Task().run(command, is_shell=True)
    print(output)


def reboot_bootloader(user_input):
    choice = input("Are you sure you want to reboot the mobile device (y/n)? ")
    command = ['adb', 'reboot', 'bootloader']
    print(command)
    output, error = Task().run(command, is_shell=True)
    print(output)


def shutdown(user_input):
    choice = input("Are you sure you want to shutdown the mobile device (y/n)? ")
    command = ['adb', 'shell', 'reboot', '-p']
    print(command)
    output, error = Task().run(command, is_shell=True)
    print(output)


def screen_lock_disabled(user_input):
    # Click LOCK button (26)
    command = ['adb', 'shell', 'input', 'keyevent','26']
    print(command)
    output, error = Task().run(command, is_shell=True)
    print(output)


def screen_lock_enabled(user_input):
    while True:
        try:
            pin = int(input("Write the pin to unlock the device"))
            break
        except ValueError:
            pass

    # Click LOCK button (26)
    command = ['adb', 'shell', 'input', 'keyevent','26']
    print(command)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    print(stdout)

    # Swipe from bottom to top
    command = ['adb', 'shell', 'input', 'swipe','500','1500', '500', '100']
    print(command)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    print(stdout)

    # Insert the PIN of the user
    command = ['adb', 'shell', 'input', 'text', pin]
    print(command)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    print(stdout)

    # Click ENTER button (66)
    command = ['adb', 'shell', 'input', 'keyevent','66']
    print(command)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()

    print(stdout)

def general_info(user_input):
    """
    Device model
    adb shell getprop ro.product.model
    Android version
    adb shell getprop ro.build.version.release
    """

    style = Style.from_dict(tool_style.STYLE)
    
    print('')
    print_formatted_text(HTML(f"<option>Device Information</option>"), style=style)
    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.product.model']
    output, error = Task().run(command)
    print(f"Device Model: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.product.brand']
    output, error = Task().run(command)
    print(f"Brand: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.product.manufacturer']
    output, error = Task().run(command)
    print(f"Manufacturer: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.build.version.release']
    output, error = Task().run(command)
    print(f"Android Version: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.build.id']
    output, error = Task().run(command)
    print(f"Build ID: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.build.version.sdk']
    output, error = Task().run(command)
    print(f"SDK Version: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.build.date']
    output, error = Task().run(command)
    print(f"Build Date: {output.strip()}")

    # Open ADB shell
    command = ['adb', 'shell', 'getprop', 'ro.serialno']
    output, error = Task().run(command)
    print(f"Device Serial Number: {output.strip()}", end='\n\n')


def cpu_info(user_input):
    command = ['adb', 'shell', 'cat', '/proc/cpuinfo']
    output, error = Task().run(command)
    print(output.strip(), end='\n\n')


def network_info(user_input):
    command = ['adb', 'shell', 'dumpsys', 'connectivity']
    output, error = Task().run(command)
    print(output.strip(), end='\n\n')


def ram_info(user_input):
    pass


def storage_info(user_input):
    command = ['adb', 'shell', 'df']
    print(command)
    output, error = Task().run(command)
    print(output.strip(), end='\n\n')


def system_apps(user_input):
    command = ['adb', 'shell', 'pm', 'list', 'packages', '-s']
    print(command)
    output, error = Task().run(command)

    packages_in_output_table(output, 2)

def third_party_apps(user_input):
    command = ['adb', 'shell', 'pm', 'list', 'packages', '-3']
    print(command)
    output, error = Task().run(command)

    packages_in_output_table(output, 3)


def packages_in_output_table(output, num_cols):
    packages_list = []
    packages = [l.replace("package:", '') for l in output.strip().splitlines()]
    
    row_list = []
    for i, p in enumerate(packages):
        if i%num_cols == 0:
            if len(row_list)>0:
                packages_list.append(row_list)

            row_list = []
        
        row_list.append(p)

    print(tabulate(packages_list, tablefmt='fancy_grid'))

def force_app_stop(user_input):
    app_id = utility.active_app_id_from_user_input(user_input)

    # Open ADB shell
    command = ['adb', 'shell', 'am', 'force-stop', app_id]
    print(command)
    output, error = Task().run(command)
    print(f"{app_id} STOPPED")
"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import os
from prompt_toolkit import HTML, print_formatted_text, prompt
from tabulate import tabulate
from termcolor import colored
from modules.error import ADBConnectionException, OptionNotAvailable
import configparser
from modules.tasks_management import Task
from prompt_toolkit.styles import Style
import config.style as tool_style
from prompt_toolkit.shortcuts import clear
from config.style import print_title, get_terminal_size

def check_connection(adb_shell_output):
    """
    Check if the device is connected to ADB.

    Returns:
        bool: True if the device is connected to ADB, False otherwise.
    """

    if "no devices/emulators found" in adb_shell_output:
        raise ADBConnectionException("No device connected", code=1)


def select_device(user_input):
    """
    List the devices connected to ADB.

    Args:
        user_input (str): The user input string.

    Returns:
        str: The output of the ADB devices command.
    """

    # Create an instance of ConfigParser

    from prompt_toolkit.key_binding import KeyBindings
    
    kb = KeyBindings()
    style = Style.from_dict(tool_style.STYLE)

    @kb.add('c-r')   # CTRL + R
    def _(event):
        event.app.current_buffer.document = event.app.current_buffer.document  # no-op
        event.app.exit(result='refresh')

    while True:
        try:
            clear()
            print_title()
            print_formatted_text(HTML("<option> > CTRL+R to refresh list</option>"), style=style)
            print_formatted_text(HTML("<option> > CTRL+C to skip choice (like 'none')</option>"), style=style)

            # Get terminal width
            terminal_width = get_terminal_size()

            # Create a line that spans the full terminal width
            line = '━' * terminal_width
            print(f"\n{line}\n")

            adb_devices = adb_devices_list()
        
            choice = prompt(HTML("<option>Select the device ID you want to use (</option>'none' to not select devices, 'refresh' to refresh the list<option>):</option>\n"), key_bindings=kb, style=style)
                
            if choice.lower() == 'none':
                config = configparser.ConfigParser()

                script_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
                config_file_path = os.path.join(script_folder, "config.ini")

                if os.path.exists(config_file_path):
                    config.read(config_file_path)

                # Add a new section if it doesn't exist
                if not config.has_section('General'):
                    return
                
                config.remove_section('General')

                # Write the configuration to a file
                with open(config_file_path, 'w') as configfile:
                    config.write(configfile)

                break
            
            elif choice.lower() == 'refresh':
                pass
            else:
                choice = int(choice)
                print("")
                
                if choice >= 0 and choice < len(adb_devices):
                    config = configparser.ConfigParser()
            
                    script_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
                    config_file_path = os.path.join(script_folder, "config.ini")

                    if os.path.exists(config_file_path):
                        config.read(config_file_path)

                    # Add a new section if it doesn't exist
                    if not config.has_section('General'):
                        config.add_section('General')
                    
                    config.set('General', 'adb_session_device', adb_devices[choice][1])
                    config.set('General', 'adb_session_model', adb_devices[choice][3])

                    # Write the configuration to a file
                    with open(config_file_path, 'w') as configfile:
                        config.write(configfile)
                    
                    break

                else:
                    raise ValueError("")

        except ValueError:
            try:
                print(colored("Invalid choice. Please select a valid device.", 'red'))
                prompt(HTML("<option>Press ENTER to continue</option>\n"), style=style, key_bindings=kb)
            except KeyboardInterrupt as e:
                del_session_device_id()
                break

        except ADBConnectionException as e:
            try:
                print(colored("No device connected to ADB.", 'red'))
                prompt(HTML("<option>Press ENTER to refresh</option>\n"),   style=style, key_bindings=kb)
            except KeyboardInterrupt as e:
                del_session_device_id()
                break

        except KeyboardInterrupt as e:
            del_session_device_id()
            break


def adb_devices_list():
    while True:
        command = ['adb', 'devices', '-l']
        output, error = Task().run(command)

        headers = ["Device ID", "Device Name", "Status", "Model"]

        row_list = []
        table_rows = []
        id = 0
        for row in output.replace("List of devices attached\n","").strip().splitlines():
            device_row = row.split()

            for info in device_row[2:]:
                if info.startswith('model:'):
                    model = info.replace('model:', '').replace('_',' ')

                    if get_session_device_id() == device_row[0]:
                        selected_id = f" {id} ".center(len(headers[0]))
                        table_rows.append([colored(f" {id} ".center(len(headers[0])), 'black', 'on_red'), 
                                           colored(f" {device_row[0]} ".center(len(headers[1])), 'black', 'on_white'), 
                                           colored(f" {device_row[1]} ".center(len(headers[2])), 'black', 'on_white'), 
                                           colored(f" {model} ".center(len(headers[2])), 'black', 'on_white')])
                    else:
                        table_rows.append([colored(f" {id} ", 'red'), colored(f" {device_row[0]} ", 'yellow'), f" {device_row[1]} ", f" {model} "])

                    row_list.append([id, device_row[0], device_row[1], model])

            id += 1

        color_headers = [colored(h, 'blue') for h in headers]

        if len(row_list)>0:
            print(tabulate(table_rows, headers=color_headers, tablefmt='fancy_grid', colalign=('center', 'center', 'center', 'center')), end='\n\n')
        else:
            print(tabulate(table_rows, headers=color_headers, tablefmt='fancy_grid'), end='\n\n')
        
        print(colored("device\t\t", "cyan")+"Connected and ready")
        print(colored("offline\t\t", "cyan")+"Device not responsive")
        print(colored("unauthorized\t", "cyan")+"Connection not authorized by the device", end="\n\n")

        if len(row_list) == 0:
            raise ADBConnectionException("")

        else:
            return row_list

def get_session_device_id():
    """
    Get the device ID from the configuration file.

    Returns:
        str: The device ID.
    """
    device_id = None

    script_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    config_file_path = os.path.join(script_folder, "config.ini")

    if os.path.exists(config_file_path):
        config = configparser.ConfigParser()
        config.read(config_file_path)

        if config.has_section('General') and config.has_option('General', 'adb_session_device'):
            device_id = config.get('General', 'adb_session_device')

    return device_id

def get_session_device_model():
    """
    Get the device ID from the configuration file.

    Returns:
        str: The device ID.
    """
    device_id = None

    script_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    config_file_path = os.path.join(script_folder, "config.ini")

    if os.path.exists(config_file_path):
        config = configparser.ConfigParser()
        config.read(config_file_path)

        if config.has_section('General') and config.has_option('General', 'adb_session_model'):
            device_id = config.get('General', 'adb_session_model')

    return device_id
    
def del_session_device_id():
    script_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    config_file_path = os.path.join(script_folder, "config.ini")

    if os.path.exists(config_file_path):
        config = configparser.ConfigParser()
        config.read(config_file_path)
            
        if config.has_section('General') and config.has_option('General','adb_session_device'):
            config.remove_option('General', 'adb_session_device')

        if config.has_section('General') and config.has_option('General','adb_session_model'):
            config.remove_option('General', 'adb_session_model')

        # Write the changes back to the config file
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
        
def start_adb_server():
    print("Killing ADB servers running...")
    command = ['adb', 'kill-server']
    output, error = Task().run(command)

    print("Starting a new ADB server...")
    command = ['adb','start-server']
    output, error = Task().run(command)

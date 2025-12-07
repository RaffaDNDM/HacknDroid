"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

from modules.adb import get_session_device_id
import config.style as tool_style
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from modules.tasks_management import Task
from prompt_toolkit.shortcuts import clear
from config.style import print_title
from modules.file_transfer import su_download, upload_to_dest
from prompt_toolkit.key_binding import KeyBindings

CURRENT_USER = ""
CURRENT_DIR = ""

def interactive_adb_shell(user_input):
    global CURRENT_USER, CURRENT_DIR
    print("")
    # Load the CLI style from the tool_style configuration
    shell_style = Style.from_dict(tool_style.STYLE)

    command = ["adb", '-s', get_session_device_id(), "shell"]
    cmd_input = "whoami\npwd\n"
    output, error = Task().run(command, input_to_cmd=["whoami\npwd\n",])
    CURRENT_USER, CURRENT_DIR = output.splitlines()
    
    history = InMemoryHistory()
    session = PromptSession(history=history)

    clear()
    print_title()

    while True:
        # Prompt the user for input (tab completion enabled)
        cmd = session.prompt(HTML(f"<shell_user> {CURRENT_USER} </shell_user><shell_pwd> {CURRENT_DIR} </shell_pwd> "), style=shell_style, multiline=False)
        cmd = cmd.strip()
        words_in_cmd = cmd.split(" ")

        if cmd == "clear":
            clear()
            print_title()
        elif cmd in ["exit", "quit"]:
            print("")
            break
        elif words_in_cmd[0] in ["download", "upload"]:
            if len(words_in_cmd) < 2:
                print(f"[!] Usage: {words_in_cmd[0]} <mobile_path> [local_path]" if words_in_cmd[0] == "download" else f"[!] Usage: {words_in_cmd[0]} <local_path> [mobile_path]")
            else:
                if words_in_cmd[0] == "download":
                    mobile_path = words_in_cmd[1] if words_in_cmd[1].startswith("/") else f"{CURRENT_DIR}/{words_in_cmd[1]}"
                    local_path = words_in_cmd[2] if len(words_in_cmd) > 2 else "."
                    su_download(mobile_path, local_path)
                else:  # upload
                    local_path = words_in_cmd[1]
                    if len(words_in_cmd) > 2:
                        mobile_path = words_in_cmd[2] if words_in_cmd[2].startswith("/") else f"{CURRENT_DIR}/{words_in_cmd[2]}"
                    else:
                        mobile_path = CURRENT_DIR
                    upload_to_dest(local_path, mobile_path)
                    
        else:
            command = ["adb", '-s', get_session_device_id(), "shell"]
            cmd_input = f"su {CURRENT_USER}\ncd {CURRENT_DIR}\n{cmd}\nwhoami;pwd\n"
            output, error = Task().run(command, input_to_cmd=[cmd_input,])

            output_lines = output.strip().splitlines()
            CURRENT_USER = output_lines[-2]
            CURRENT_DIR = output_lines[-1]
            print("\n".join(output_lines[:-2]))
            print(error)
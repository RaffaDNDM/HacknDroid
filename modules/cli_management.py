"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

from tabulate import tabulate
import config.menu as menu
import config.style as tool_style

from prompt_toolkit import prompt, print_formatted_text
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import clear
from termcolor import colored

# Function pointer in OPTIONS
from modules.tasks_management import DAEMONS_MANAGER
from modules.adb import del_session_device_id, get_session_device_model, select_device, start_adb_server
from modules.error import ADBConnectionException, OptionNotAvailable
from modules.adb import get_session_device_id
from config.style import print_title, loading_animation, get_terminal_size

from prompt_toolkit.key_binding import KeyBindings

def print_shortcuts():
    """
    Docstring for print_shortcuts
    """

    print("")
    print(colored("Available Shortcuts","green"))
    headers = [colored("Shortcut", "blue"), colored("Description", "blue")]

    rows = [
        [colored("TAB", "yellow"), "Show available options"],
        [colored("Ctrl+D", "yellow"), "Exit the program"],
        [colored("Ctrl+B", "yellow"), "Go back to the previous menu"],
        [colored("Ctrl+X CTRL+H", "yellow"), "Go back to the homepage"],
    ]

    if len(CURRENT_OPTION['children']) == 2:
        rows.append([colored("Ctrl+C", "yellow"), "Cancel the current action"])
    
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))
    
    x=input(colored("\nPress ENTER to continue\n","green"))


class CLI():

    def __init__(self):
        """
        Initialize the CLI with options and styles.
        """
        start_adb_server()
        # Initialize the global variable CURRENT_OPTION
        global CURRENT_OPTION
        
        # Load the CLI options from the menu configuration
        self._options = menu.OPTIONS
        
        # Initialize the current path with the root option
        self._current_path = []
        self._current_path.append(list(self._options.keys())[0])
        
        # Set the CURRENT_OPTION to the root option
        CURRENT_OPTION = self._options[self._current_path[0]]
        
        # Load the CLI style from the tool_style configuration
        self._style = Style.from_dict(tool_style.STYLE)
        
        self._kb = KeyBindings()

        @self._kb.add('c-b')   # CTRL + B
        def _(event):
            event.app.current_buffer.document = event.app.current_buffer.document  # no-op
            event.app.exit(result='back')

        @self._kb.add('c-x', 'c-h')   # CTRL + X, CTRL + H
        def _(event):
            event.app.current_buffer.document = event.app.current_buffer.document  # no-op
            event.app.exit(result='home')

        @self._kb.add('c-s')   # CTRL + S
        def _(event):
            event.app.current_buffer.document = event.app.current_buffer.document  # no-op
            event.app.exit(result='shortcuts')

        print_title()

    def completer(text, state):
        """
        Tab completion for CLI options.

        Args:
            text (str): The current input text.
            state (int): The state of the completion.

        Returns:
            str: The matching option.
        """
        # Get the matching options
        matches = [option for option in list(CURRENT_OPTION['children'].keys()) if option.startswith(text)]

        # Return the matching option
        if state < len(matches):
            return matches[state]
        else:
            return None        


    def cli_options(self):
        """
        Display and handle CLI options.
        """
        global CURRENT_OPTION

        select_device('')

        print("")
        loading_animation("Redirecting you to the homepage", 0.5, 3, 'white', 'red')

        while True:        
            try:
                # Clear the screen
                clear()
                # Print the title
                print_title()
                # Print the shortcut keys
                device_id = get_session_device_id()
                device_model = get_session_device_model()

                device_info = ""
                options_list = list(CURRENT_OPTION['children'].keys())

                if device_id:
                    device_info = f"\U0001F4F1 {device_model} ({device_id})"
                    # Initialize the prompt completer with the children of the current option
                else:
                    device_info = "\u274C NO DEVICE"
                    options_list = [k for k in options_list if (k in ['back','home'] or not CURRENT_OPTION['children'][k]['device_needed'])]

            
                # Initialize the prompt completer with the children of the current option
                self._prompt_completer = WordCompleter(options_list)

                print_formatted_text(HTML("<option> > CTRL+S to see shortcuts</option>"), style=self._style)
                
                # Get terminal width
                terminal_width = get_terminal_size()
    
                # Create a line that spans the full terminal width
                line = '━' * terminal_width
                print(f"\n{line}\n")
                
                # Print the description of the current option
                if len(CURRENT_OPTION['children']) == 2:
                    
                    print_formatted_text(HTML(f"<descr>{CURRENT_OPTION['description'][0]}</descr>"), style=self._style)
                
                    for x in CURRENT_OPTION['description'][1:]:
                        print_formatted_text(HTML(f"<input>{x}</input>"), style=self._style)
                
                else:
                    for x in CURRENT_OPTION['description']:
                        print_formatted_text(HTML(f"<descr>{x}</descr>"), style=self._style)

                if len(self._current_path)>1:
                    # Print the current path between functionality
                    print("")
                    path = f"<section{1}> {self._current_path[2]} </section{1}>"
                    
                    for i in range(4,len(self._current_path),2):
                        path+=f"<section{i/2}> {self._current_path[i]} </section{i/2}>"

                else:
                    # Print the home path ('home')
                    path = f"<section> {self._current_path[-1]} </section>"

                if len(CURRENT_OPTION['children']) == 2 and not CURRENT_OPTION['input_needed']:
                    print_formatted_text(HTML(path+" "), style=self._style)
                    f = CURRENT_OPTION

                    self._current_path = self._current_path[:-2]
                    CURRENT_OPTION = self._options[self._current_path[0]]
                    for i in self._current_path[1:]:
                        CURRENT_OPTION = CURRENT_OPTION[i]

                    f['function']("\n")
                    print_formatted_text(HTML("<option>Press ENTER to continue</option>"), style=self._style)

                    x=input()

                else:
                    # Prompt the user for input (tab completion enabled)
                    choice = prompt(HTML(path+" "), completer=self._prompt_completer, style=self._style, multiline=False, bottom_toolbar=device_info, key_bindings=self._kb)

                    if choice == 'shortcuts':
                        print_shortcuts()

                    elif choice in CURRENT_OPTION['children']:
                        # If the input (choice) is a valid option, navigate to the selected level

                        if choice == 'back' and len(self._current_path)>1:
                            # If the input is 'back' and the program is not in the homepage, navigate back to the parent level
                            self._current_path = self._current_path[:-2]
                            CURRENT_OPTION = self._options[self._current_path[0]]
                            for i in self._current_path[1:]:
                                CURRENT_OPTION = CURRENT_OPTION[i]

                        elif choice == 'home' and len(self._current_path)>1:
                            self._current_path = self._current_path[:1]
                            CURRENT_OPTION = self._options[self._current_path[0]]

                        else:
                            # If the input is not 'back', navigate to the selected level
                            self._current_path.append('children')
                            self._current_path.append(choice)
                            CURRENT_OPTION = CURRENT_OPTION['children'][choice]

                        # Update the completer with the new options for the current level
                        self._prompt_completer = WordCompleter(list(CURRENT_OPTION['children'].keys()))
                    
                    elif len(CURRENT_OPTION['children']) == 2:
                        # If the input is a leaf node with input needed, execute the associated function
                        CURRENT_OPTION['function'](choice)
                        # Wait for the user to press ENTER to continue
                        print_formatted_text(HTML("<option>Press ENTER to continue</option>"), style=self._style)
                        x=input()

            except OptionNotAvailable:
                print(colored("Invalid choice. Please select a valid device.", 'red'))
                print_formatted_text(HTML("<option>Press ENTER to continue</option>"), style=self._style)
                x= input()
                
            except ADBConnectionException:
                print(colored("No mobile device available.", 'red'))
                print_formatted_text(HTML("<option>Press ENTER to continue</option>"), style=self._style)
                
                x = input()
                
            except KeyboardInterrupt:
                # Cancel the current operation (input insertion by a user)
                pass

            except EOFError:
                # Clear the screen
                clear()
                # Print the title
                print_title()
                print_formatted_text(HTML(f"<descr>Thank you for using the program!!!</descr>"), style=self._style, end='\n\n')
                
                del_session_device_id()
                break

            except Exception as e:
                print(colored(f"An error occurred: {e}", 'red'))
                print_formatted_text(HTML("<option>Press ENTER to continue</option>"), style=self._style)
                x = input()
                
        # Stop all the tasks
        DAEMONS_MANAGER.stop_all_tasks()
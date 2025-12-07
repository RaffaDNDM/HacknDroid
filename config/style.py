"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import os
from termcolor import colored
from pyfiglet import Figlet

STYLE = {
    'section': 'bg:#ffffff bold black',
    'section1': 'bg:#dd0000 bold white',
    'section2': 'bg:#dd5500 bold white',
    'section3': 'bg:#dd8800 bold white',
    'section4': 'bg:#80ea80 bold black',
    'shell_user': 'bg:#dd0000 bold white',
    'shell_pwd': 'bg:#ffffff bold black',
    'option': 'ansigreen bold',
    'descr': 'ansiyellow bold',
    'error':'bg:#ff0000 bold white',
    'completion-menu.completion': 'bg:#008888 #ffffff',
    'completion-menu.completion.current': 'bg:#00aaaa #000000',
    'scrollbar.background': 'bg:#88aaaa',
    'scrollbar.button': 'bg:#222222',
    'space':'white',
    'input': 'ansiwhite bold',
}

import sys
import threading
import time
from functools import wraps

def with_progress(initial_message="Working"):
    """
    Decorator that shows a spinner with a message and ensures DONE is printed only once.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            done = False
            done_printed = False
            message = [initial_message]
            lock = threading.RLock()  # reentrant lock

            def clear_line():
                sys.stdout.write("\r" + " " * 100 + "\r")
                sys.stdout.flush()

            def animate():
                dots = ["", ".", "..", "..."]
                i = 0
                while not done:
                    with lock:
                        clear_line()
                        sys.stdout.write(f"{message[0]}{dots[i % len(dots)]}")
                        sys.stdout.flush()
                    time.sleep(0.3)
                    i += 1
                with lock:
                    if not done_printed:
                        clear_line()
                        sys.stdout.write(f"{message[0]}... DONE\n")
                        sys.stdout.flush()

            thread = threading.Thread(target=animate, daemon=True)
            thread.start()

            # Safe input/print replacements
            def safe_print(*args, **kwargs):
                with lock:
                    clear_line()
                    print(*args, **kwargs)

            def safe_input(prompt=""):
                with lock:
                    clear_line()
                    value = input(prompt)
                return value

            # Temporarily inject safe versions into the function
            func_globals = func.__globals__
            old_vals = {k: func_globals.get(k) for k in ["print", "input"]}
            func_globals.update({"print": safe_print, "input": safe_input})

            try:
                result = func(*args, **kwargs)
            finally:
                done = True
                thread.join()
                # Restore originals
                for k, v in old_vals.items():
                    if v is None:
                        func_globals.pop(k, None)
                    else:
                        func_globals[k] = v

            return result

        return wrapper
    return decorator

def print_title():
    title = "HacknDroid"
    title_f = colored(Figlet(font='slant').renderText(title), 'red')
    print(title_f)

def get_terminal_size():
    size = os.get_terminal_size()
    return size.columns

def loading_animation(loading_str, gap, max_time, color_str = None, color_dots = None):
    dots = ['.', '..', '...']
    
    if color_str:
        loading_str = colored(loading_str, color=color_str)

    if color_dots:
        dots = [colored(d, color=color_dots) for d in dots]

    time_steps = int(max_time // gap)
    for i in range(time_steps):
        sys.stdout.write(f"\r{loading_str}{len(dots)*' '}")  # Carriage return to overwrite the line
        sys.stdout.write(f'\r{loading_str}{dots[(i%len(dots))]}')  # Carriage return to overwrite the line
        sys.stdout.flush()  # Ensure it prints immediately
        time.sleep(gap)  # Delay between dots

    sys.stdout.write(f"\r{loading_str}{len(dots)*'.'}")
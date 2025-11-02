"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

from termcolor import colored
from modules import utility
import os
from modules.tasks_management import Task
from modules.adb import get_session_device_id

def mobile_exists(paths : list):
    '''
        Check if every mobile path in a list exists

        Args:
            paths (list): list of mobile paths to be checked

        Returns:
            bool: True if every path exists, False otherwise
    '''

    # Initialize a variable to keep track of the existence of all paths
    check = True
    
    # Iterate over each mobile path in the list
    for mobile_path in paths:
        # Define the adb shell command to check if the mobile path is a file or directory
        command = ['adb', '-s', get_session_device_id(), 'shell']
        
        # Define the shell input commands to check if the path is a file or directory and echo "1" if true
        shell_input = ["su root", f"""(test -f "{mobile_path}" || test -d "{mobile_path}") && echo "1" """, "exit"]
        
        # Run the shell commands and capture the output and error
        output, error = Task().run(command, input_to_cmd=shell_input)
        
        # Update the check variable based on whether the output is "1"
        check = check and (output.strip() == "1")
        
        # If the path does not exist, print an error message and return False
        if not check:
            print(f"{mobile_path} NOT FOUND")
            return check
    
    # Return True if all paths exist, otherwise False
    return check

def is_mobile_folder(mobile_path : str):
    '''
        Check if a mobile path is a folder

        Args:
            mobile_path (str): mobile path to be checked

        Returns:
            bool: True if the path is a folder, False otherwise
    '''
    
    # Define the adb shell command to check if the mobile path is a directory
    command = ['adb', '-s', get_session_device_id(), 'shell']
    # Define the shell input commands to check if the path is a directory and echo "1" if true
    shell_input = ["su root",f"""(test -d "{mobile_path}") && echo "1" """, "exit"]
    # Run the shell commands and capture the output and error
    output, error = Task().run(command, input_to_cmd=shell_input)

    # Return True if the output is "1", indicating the path is a directory, otherwise return False
    return output.strip() == "1"


def is_mobile_file(mobile_path : str):
    '''
        Check if a mobile path is a file

        Args:
            mobile_path (str): mobile path to be checked

        Returns:
            bool: True if the path is a file, False otherwise
    '''

    # Define the adb shell command to check if the mobile path is a file
    command = ['adb', '-s', get_session_device_id(), 'shell']
    
    # Define the shell input commands to check if the path is a file and echo "1" if true
    shell_input = ["su root", f"""(test -f "{mobile_path}") && echo "1" """, "exit"]
    
    # Run the shell commands and capture the output and error
    output, error = Task().run(command, input_to_cmd=shell_input)
    
    # Return True if the output is "1", indicating the path is a file, otherwise return False
    return output.strip() == "1"


def upload(user_input):
    '''
    Upload a file/folder from PC to mobile device

    Args:
        user_input (str): user input containing the source path of the file/folder to be uploaded followed by the destination path in the mobile device
                            (separated by one or more spaces)
    Example:
        upload("/path/to/local/file_or_folder /data/local/tmp")
    '''
    # Split the user input into individual paths
    paths = utility.split_user_input(user_input)

    # If only one path is provided
    if len(paths) == 1:
        # Check if the provided path exists on the PC
        if os.path.exists(paths[0]):
            # Upload the file/folder to the default destination on the mobile device
            upload_to_dest(file_folder=paths[0])
        else:
            # Print an error message if the path does not exist
            print(f"Path {paths[0]} NOT FOUND!!!")
    
    # If two paths are provided
    elif len(paths) == 2:
        # Check if the source path exists on the PC
        if not os.path.exists(paths[0]):
            # Print an error message if the source path is invalid
            print("Invalid PC Source path")
        # Check if the destination path exists on the mobile device
        elif not mobile_exists([paths[1],]):
            # Print an error message if the destination path is invalid
            print("Invalid Mobile Destination path")
        else:
            # Upload the file/folder to the specified destination on the mobile device
            upload_to_dest(paths[0], paths[1])
    else:
        # Print an error message if more than two paths are provided
        print("Too many arguments specified!!!")


def upload_to_dest(file_folder, dest_folder="/data/tmp"):
    """
    Uploads a file or folder from the PC to a specified destination folder on a mobile device.
    
    Args:
        file_folder (str): The path to the file or folder on the PC that needs to be uploaded.
        dest_folder (str, optional): The destination folder on the mobile device where the file or folder should be moved. Defaults to "/data/tmp".

    Example:
        upload_to_dest("/path/to/local/file_or_folder", "/data/tmp")
    """

    # Get the SD card path on the mobile device
    sdcard = utility.sd_path()
    
    # Push the file/folder from PC to the SD card on the mobile device
    command = ['adb', '-s', get_session_device_id(), 'push', file_folder, sdcard]
    output, error = Task().run(command)
    
    # Get the resource name from the file/folder path
    rsc_name = utility.rsc_from_path(file_folder)
    
    # Move the file/folder from the SD card to the desired destination folder on the mobile device
    command = ['adb', '-s', get_session_device_id(), 'shell']
    shell_input = ["su root", f"mv {sdcard}/{rsc_name} {dest_folder}", "exit"]
    output, error = Task().run(command, input_to_cmd=shell_input)

    print("Upload done!!!")

def download_from_user_input(user_input):
    """
    Downloads files from a mobile device to a specified directory on the PC based on user input.

    Args:
        user_input (str): A string containing paths separated by spaces. 
                          The paths should include one or more mobile file/folder paths followed by a PC directory path.

    Example:
        user_input = "mobile_path1 mobile_path2 pc_directory"
        download_from_user_input(user_input)
    """

    # Split the user input into individual paths
    paths = user_input.split(" ")
    
    # Loop until valid paths are provided
    while len(paths) < 2 or not (mobile_exists(paths[:-1]) and os.path.exists(paths[-1]) and os.path.isdir(paths[-1])):
        # Prompt the user to input paths again if the conditions are not met
        user_input = input(colored("""Insert at least two paths separated by spaces:\n > list of the paths of mobile files/folders to be downloaded\n > pc folder where the files will be downloaded\n\n""", "green"))
        paths = user_input.split(" ")
   
    # Iterate over each mobile path (excluding the last path which is the PC destination folder)
    for mobile_path in paths[:-1]:
        print(mobile_path)

        choice = ""

        while True:
            choice = input("Do you want to delete tempory files/folder created in external storage [y|n]?")

            if choice.lower() in ['y','n']:
                break
            else:
                print(f"Option '{choice}' not available")

        # Download each mobile path to the specified PC destination folder
        download(mobile_path, paths[-1], remove_from_sd=(choice.lower() == 'y'))

def download(mobile_path, dest_path, remove_from_sd=False, permissions_check=True):
    """
    Downloads a file or folder from a mobile device to a PC using adb pull command.
    
    Args:
        mobile_path (str): The path of the file or folder on the mobile device.
        dest_path (str): The destination path on the PC where the file or folder will be saved.
        permissions_check (bool, optional): If True, checks for permission errors and prompts the user to download as Super User if needed. Defaults to True.
    
    Example:
        download("/data/local/tmp/file.txt", "C:/Users/username/Downloads")
    """

    # Construct the adb pull command to download the file/folder from the mobile device to the PC
    command = ['adb', '-s', get_session_device_id(), 'pull', mobile_path, dest_path]
    output, error = Task().run(command)

    # Check if permissions check is enabled
    if permissions_check:
        print(error.strip() if error else output, end='\n\n')

        if "permission denied" in output.lower() or "0 files pulled" in output.lower() or "permission denied" in error.lower() or "0 files pulled" in error.lower():
            
            while True:
                # Prompt the user to decide if they want to download the file/folder as Super User
                x = input(colored("[PERMISSION DENIED] ", 'red')+colored("Do you want to download the file/folder as Super User (y/n)? ", "green"))


                # If the user chooses to proceed as Super User
                if x.lower() == "y":
                    # Call the su_download function to handle the download with elevated permissions
                    su_download(mobile_path, dest_path, remove_from_sd)
                elif x.lower() == "n":
                    return
                else:
                    print(f"Option '{x}' not available")


def su_download(mobile_path, dest_path, remove_from_sd):
    """
    Downloads a file or folder from a mobile device to a destination path on the PC using adb and superuser permissions.
    
    Args:
        mobile_path (str): The path of the file or folder on the mobile device.
        dest_path (str): The destination path on the PC where the file or folder will be downloaded.
    
    Example:
        su_download('/data/data/com.example.app/files/myfile.txt', 'C:/Users/username/Downloads/myfile.txt')
    """


    # Define the adb shell command
    command = ['adb', '-s', get_session_device_id(), 'shell']
    
    # Get the SD card path on the mobile device
    sdcard = utility.sd_path()
    
    # Get the resource name from the mobile path
    rsc_name = utility.rsc_from_path(mobile_path)

    # Check if the mobile path is a folder
    if is_mobile_folder(mobile_path):
        # Define shell commands to copy the folder to the SD card with appropriate permissions
        shell_input = ["su root",
                       f'if [ -d "{sdcard}/{rsc_name}" ]; then rm -r "{sdcard}/{rsc_name}"; fi',  # Remove existing folder on SD card if it exists
                       f"cp -r {mobile_path} {sdcard}/{rsc_name}",  # Copy the folder to the SD card
                       f"chmod 666 {sdcard}/{rsc_name}",  # Change permissions of the copied folder
                       "exit"]
        
        # Print the shell commands for debugging
        print("\n".join(shell_input))
        
        # Run the shell commands
        output, error = Task().run(command, input_to_cmd=shell_input)
        
        # Download the copied folder from the SD card to the destination path on the PC
        download(f"{sdcard}/{rsc_name}", dest_path, permissions_check=False)

        if remove_from_sd:
            output, error = Task().run(command, input_to_cmd=[f"rm -r {sdcard}/{rsc_name}", "exit"])

    # Check if the mobile path is a file
    elif is_mobile_file(mobile_path):
        # Define shell commands to copy the file to the SD card with appropriate permissions
        shell_input = ["su root",
                       f'if [ -f "{sdcard}/{rsc_name}"]; then rm "{sdcard}/{rsc_name}"; fi',  # Remove existing file on SD card if it exists
                       f"cp {mobile_path} {sdcard}/{rsc_name}",  # Copy the file to the SD card
                       f"chmod 666 {sdcard}/{rsc_name}",  # Change permissions of the copied file
                       "exit"]
        
        # Print the shell commands for debugging
        print("\n".join(shell_input))
        
        # Run the shell commands
        output, error = Task().run(command, input_to_cmd=shell_input)
        
        # Download the copied file from the SD card to the destination path on the PC
        download(f"{sdcard}/{rsc_name}", dest_path, permissions_check=False)

        if remove_from_sd:
            output, error = Task().run(command, input_to_cmd=[f"rm {sdcard}/{rsc_name}", "exit"])
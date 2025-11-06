"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import os
from modules.adb import get_session_device_id
from modules.tasks_management import Task
from modules.utility import app_id_from_user_input, current_date
from modules.file_transfer import mobile_exists, download

def reset_app_data(user_input):
    """
    Reset data of an application on the mobile device.

    Args:
        user_input (str): The App ID of the application to reset.
    """
    # Retrieve App ID from user input
    app_id = app_id_from_user_input(user_input)
    
    # Reset App data for the application with App ID <app_id>
    command = ['adb','-s', get_session_device_id(), 'shell',"pm","clear",app_id]
    print(command)
    output, error = Task().run(command, is_shell=True)


def collect_data_storage(user_input):
    """
    Collect data of an application on the mobile device.

    Args:
        user_input (str): The App ID of the application you want to collect data from.
    """
    # Retrieve App ID from user input
    app_id = app_id_from_user_input(user_input)

    dest_folder = os.path.join("results", app_id, "data_storage")
    os.makedirs(dest_folder, exist_ok=True)

    now = current_date()
    download(mobile_path=f"/data/data/{app_id}/", dest_path=dest_folder,  remove_from_sd=True)
    print(f"renaming {dest_folder} to {dest_folder.replace(app_id, now)}")
    os.rename(os.path.join(dest_folder, app_id), os.path.join(dest_folder, now))
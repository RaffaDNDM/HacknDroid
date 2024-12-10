import subprocess
import threading
from modules.utility import cmd_to_subprocess_string 
from tabulate import tabulate

class DaemonTask():
    def __init__(self):
        self._PROCESS = None
        self._THREAD = None

    def run(self, command, args=tuple()):
        if not self._PROCESS:
            if callable(command):
                self._THREAD = threading.Thread(target=command, args=args)
            else:
                self._THREAD = threading.Thread(target=self.thread_function, args=(command,))

            self._THREAD.daemon = True
            self._THREAD.start()

    def thread_function(self, command):
        self._PROCESS = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ,text=True)
        output, error = self._PROCESS.communicate()
        # Process stoped before by the user
        self._PROCESS = None
    
    def stop(self):
        if self._PROCESS:
            self._PROCESS.terminate()
            self._THREAD.join()
        elif self._THREAD:
            self._THREAD = None
        else:
            print("The process was already finished!!!")

class DaemonTaskManager():
    def __init__(self):
        self._TOOL_TASKS = {}
        self._ID = 0
        self._HEADERS = ['Functionality', 'Task ID']

    def add_task(self, functionality, command, args=None):
        task = DaemonTask()
        if args:
            task.run(command, args)
        else:
            task.run(command)

        if functionality not in self._TOOL_TASKS:
            self._TOOL_TASKS[functionality] = {}
        
        id = self._ID
        self._TOOL_TASKS[functionality][id] = {'task': task, 'additional info': {}}
        self._ID += 1

        return id

    def stop_task(self, functionality, id):
        if functionality in self._TOOL_TASKS:
            if id in self._TOOL_TASKS[functionality]:
                self._TOOL_TASKS[functionality][id]['task'].stop()
                del self._TOOL_TASKS[functionality][id]

            if not self._TOOL_TASKS[functionality].keys():
                del self._TOOL_TASKS[functionality]
        else:
            print("No running daemon tasks!!!")

    def stop_all_tasks(self):
        tasks_info = []
        for functionality in self._TOOL_TASKS:
            for id in self._TOOL_TASKS[functionality]:
                tasks_info.append((functionality, id))

        for func_id in tasks_info:
            self.stop_task(func_id[0], func_id[1])

    def get_dict(self):
        return self._TOOL_TASKS
    
    def get_next_id(self):
        return self._ID
    
    def add_info(self, functionality, id, dict_info):
        for k in dict_info:
            if k not in self._HEADERS:
                self._HEADERS.append(k)

        self._TOOL_TASKS[functionality][id]['additional info']=dict_info

    def get_headers(self):
        return self._HEADERS
        

class Task():
    def __init__(self):
        pass

    def run(self, command : list, is_shell : bool = False, input_to_cmd : list = None):
        if is_shell:
            self._PROCESS = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE ,shell=True)
        else:
            self._PROCESS = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE ,text=True)
        
        if input_to_cmd:
            output, error = self._PROCESS.communicate(cmd_to_subprocess_string(input_to_cmd))
        else:
            output, error = self._PROCESS.communicate()

        return output, error

DAEMONS_MANAGER = DaemonTaskManager()

def list_daemons(user_input):
    global DAEMONS_MANAGER
    
    headers = DAEMONS_MANAGER.get_headers()
    row_list = []
    TASKS_DICT = DAEMONS_MANAGER.get_dict()

    functionalities = list(TASKS_DICT.keys())
    
    if user_input in functionalities:
        functionalities = [functionality,]
    
    for functionality in functionalities:        
        for id in TASKS_DICT[functionality]:
            row = []

            for k in headers:
                if k=="Functionality":
                    row.append(functionality)
                elif k=="Task ID":
                    row.append(id)
                elif TASKS_DICT[functionality][id]['additional info'] and k in TASKS_DICT[functionality][id]['additional info']:
                        row.append(TASKS_DICT[functionality][id]['additional info'][k])
                else:
                    row.append("")


            row_list.append(row)


    print(tabulate(row_list, headers=headers, tablefmt='fancy_grid'))

    return row_list
"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

from modules import adb, apk_analyzer, apk_install, app_logs, backup, battery, connectivity, emulator, file_transfer, frida_integration, mem_info, merge_apks, mirroring, proxy, shell, signature, useful_stuff
import modules.tasks_management
from modules import utility

OPTIONS =   {
                'home': { 
                    "description":['',],
                    'children':{
                        "apk": {
                            'description': ['Several APKs related operations:',
                                            ' > Analysis',
                                            ' > Get APK from the mobile device'
                                            ' > APP info from APK/Android Manifest'
                                            ' > Compiling',
                                            ' > Decompiling',
                                            ' > Launch JADX-GUI on APK file',
                                            ' > JAR from APK file',
                                            ' > Merge APKs',
                                            ' > Sign APK',],
                            'device_needed': False,
                            'children' : {
                                "apk_analysis": { 
                                    'description': [
                                        'Analysis of the APKs related to the application:', 
                                        ' > search for common Certificate Pinning strings or SHA1-SHA256 hash string in smali files',
                                        ' > search for common Root Detection strings in smali files', 
                                        ' > signature scheme verifier',
                                        ' > full analysis'
                                        ],
                                    'device_needed': False,
                                    'children': {
                                        "certificate_pinning_hints" : { 
                                            'description': ['Search for common Certificate Pinning strings or SHA1-SHA256 hash string in smali files',],
                                            'device_needed': False,
                                            'children': {
                                                "from_apk_on_pc" : { 
                                                    'description': ["Certificate pinning hints on an apk file on your PC",
                                                                    "Write the path of the apk on your PC",],
                                                    'device_needed': False,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function' : apk_analyzer.certificate_pinning_hints_from_file
                                                },
                                                "from_mobile_device" : { 
                                                    'description': ["Certificate pinning hints on an application on your mobile device",
                                                                    "Write the app id or a part of the app name to be analysed",],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function': apk_analyzer.certificate_pinning_hints_from_device
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                        },
                                        "root_detection_hints" : { 
                                            'description': ['Search for common Root Detection strings in smali files',],
                                            'device_needed': False,
                                            'children': {
                                                "from_apk_on_pc" : { 
                                                    'description': ["Root detection hints on an apk file on your PC",
                                                                    "Write the path of the apk on your PC",],
                                                    'device_needed': False,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function' : apk_analyzer.root_detection_hints_from_file
                                                },
                                                "from_mobile_device" : { 
                                                    'description': ["Root detection hints on an application on your mobile device",
                                                                    "Write the app id or a part of the app name to be analysed",],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function': apk_analyzer.root_detection_hints_from_device
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                        },
                                        "signature_scheme" : { 
                                            'description': ["Signature scheme verifier"
                                                            ],
                                            'device_needed': False,
                                            'children': {
                                                "from_apk_on_pc" : { 
                                                    'description': ["Signature scheme verifier on an apk file on your PC",
                                                                    "Write the path of the apk on your PC"],
                                                    'device_needed': False,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function' : apk_analyzer.signature_verifier_from_apk
                                                },
                                                "from_mobile_device" : { 
                                                    'description': ["Signature scheme verifier on an application on your mobile device",
                                                                    "Write the app id or a part of the app name to be analysed"],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function' : apk_analyzer.signature_verifier_from_mobile
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            }
                                        },
                                        "full_analysis" : { 
                                            'description': [
                                                            'Full Analysis of the APKs related to the application, including:', 
                                                            ' > search for common Certificate Pinning strings or SHA1-SHA256 hash string in smali files',
                                                            ' > search for common Root Detection strings in smali files', 
                                                            ' > signature scheme verifier'
                                                            ],
                                            'device_needed': False,
                                            'children': {
                                                "from_apk_on_pc" : { 
                                                    'description': ["Analyze an apk file on your PC",
                                                                    "Write the path of the apk on your PC",],
                                                    'device_needed': False,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function' : apk_analyzer.apk_analysis_from_file
                                                },
                                                "from_mobile_device" : { 
                                                    'description': ["Analyze an apk file of an application on your mobile device",
                                                                    "Write the app id or a part of the app name to be analysed",],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    'function': apk_analyzer.apk_analysis_from_device
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                        },
                                        "back" : dict(),
                                        "home" : dict()                                        
                                    }
                                },
                                "get_apk_from_mobile": { 
                                    'description': ["Get APK of an application on your mobile device",
                                                    'Write the app id or a part of the app name to be extracted and analysed'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    'function': apk_analyzer.get_apk_from_device
                                },
                                "app_info": { 
                                    'description': ['App info from the APK',],
                                    'device_needed': False,
                                    'children': {
                                        "from_apk_on_pc": { 
                                            'description': ['App info from the APK',
                                                            'Write the path of the APK file on the PC to be analysed',],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            'function' : apk_analyzer.print_app_info_from_pc
                                        },
                                        "from_mobile_device": { 
                                            'description': ['App info from the APK',
                                                            'Write the app id or a part of the app name to be analysed',],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function' : apk_analyzer.print_app_info_from_device
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                },
                                "apk_from_aab": { 
                                    'description': ['APK from the AAB file',
                                                    'Write the filepath of the AAB file',],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function' : apk_analyzer.aab_to_apk
                                },
                                "compile_sign": { 
                                    'description': ['Compile an apk file from the folder with decompiled and modified code',],
                                    'device_needed': False,
                                    'children': {
                                        "compile": { 
                                            'description': ['Compile an apk file from the folder with decompiled and modified code',
                                                            'Write the path of the decompiled folder on the PC to be compiled',
                                                            '(the folder should contain the apktool.yml file and all the other smali files)'],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            'function' : apk_analyzer.apk_compile_from_folder
                                        },
                                        "compile_and_sign": { 
                                            'description': ['Compile and sign an apk file from the folder with decompiled and modified code',
                                                            'Write the path of the decompiled folder on the PC to be compiled',
                                                            '(the folder should contain the apktool.yml file and all the other smali files)'],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function' : apk_analyzer.apk_compile_and_sign_from_folder
                                        },
                                        "sign_apk":{
                                            'description': ['Sign an apk on your PC.',
                                                            'Write the path of the APK file on the PC to be signed'],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': signature.sign_apk
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "decompile": { 
                                    'description': ['Decompile an apk file',],
                                    'device_needed': False,
                                    'children': {
                                        "from_apk_on_pc" : { 
                                            'description': ["Decompile the apk file into smali code",
                                                            "Write the path of the apk on your PC (or the folder with all the APKs related to the app)"],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function' : apk_analyzer.apk_decompiler_from_file
                                        },
                                        "from_mobile_device" : { 
                                            'description': ["Decompile the apk file into smali code",
                                                            "Write the app id or a part of the app name to be extracted and analysed"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home":dict()
                                            },
                                            
                                            'function': apk_analyzer.apk_decompiler_from_device
                                        },
                                        "back" : dict(),
                                        "home":dict()
                                    },
                                    
                                },
                                "jadx_run_on_apk" : { 
                                    'description': ["Open an APK in JADX-GUI"],
                                    'device_needed': False,
                                    'children': {
                                        "jadx_create_and_open_file":{
                                            'description': ["Open the reversed apk in JADX-GUI.",
                                                            "Write the path of the apk on your PC (or the folder with all the APKs related to the app)",],
                                            'device_needed': False,
                                            'children':{
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': apk_analyzer.jadx_from_file
                                        },
                                        "from_mobile_device":{
                                            'description': ["Open the reversed apk in JADX-GUI",
                                                            "Write the app id or a part of the app name to be extracted and analysed",],
                                            'device_needed': True,
                                            'children':{
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': apk_analyzer.jadx_from_device
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "jar_from_apk" : { 
                                    'description': ["Convert an apk file from the mobile device to a jar file"],
                                    'device_needed': True,
                                    'children': {
                                        "from_apk_on_pc":{
                                            'description': ["Convert an apk file on the PC to a jar file.",
                                                            "Write the path of the apk on your PC (or the folder with all the APKs related to the app)",],
                                            'device_needed': False,
                                            'children':{
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': apk_analyzer.jar_from_file
                                        },
                                        "from_mobile_device":{
                                            'description': ["Convert the apk to a jar file",
                                                            "Write the app id or a part of the app name to be extracted and analysed"],
                                            'device_needed': True,
                                            'children':{
                                                "back" : dict(),
                                                "home" : dict()
                                            },        
                                            'function': apk_analyzer.jar_from_device
                                        },

                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                },
                                "merge_apks": {
                                    'description': ['Merge several APKs'],
                                    'device_needed': False,
                                    'children': {
                                        "from_directory" : {
                                            'description' : ["Merge several APKs from a directory",
                                                             "Write the path of the directory with APKs to be merged",],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': merge_apks.merge_from_dir
                                        },
                                        "from_list" : {
                                            'description' : ["Merge several APKs",
                                                             "Write the list of APKs paths to be merged (separated by spaces):",],
                                            'device_needed': False,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': merge_apks.merge_from_list
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                        },
                        "app_data_and_logs" : {
                            'description' : ['Analysis of app data and logs:',
                                             ' > Backup/Reset data of an application',
                                             ' > Dump application memory information',
                                             ' > Force App stop',
                                             ' > Track logs of an application',],
                            'device_needed': True,
                            'children' : {
                                "backup_and_data" : {
                                    'description': ['Backup/Reset data of an application',],
                                    'device_needed': True,
                                    'children': {
                                        "backup_device" : { 
                                            'description': ["Backup the mobile device"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function' : backup.device_backup
                                        },
                                        "backup_specific_app" : { 
                                            'device_needed': True,
                                            'description': ["Backup a specific app",
                                                            "Write its app id or a keyword to identify it"],
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': backup.app_backup
                                        },
                                        "backup_restore" : { 
                                            'description': ["Restore a backup file on your mobile device",
                                                            "Write the file path of the .ab file to be extracted"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': backup.restore_backup
                                        },
                                        "backup_to_folder" : { 
                                            'description': ["Extract a backup file on your system",
                                                            "Write the file path of the .ab file to be extracted"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': backup.tar_extract
                                        },
                                        "reset_app_data" : { 
                                            'description': ["Reset App data",
                                                            "Write the app id or a part of the app name to reset its data"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': backup.app_data_reset
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                            
                                },
                                "dump_mem_info" : {
                                    'description': ['Dump the memory information for an application',],
                                    'device_needed': True,
                                    'children': {
                                        "run_app_meminfo" : { 
                                            'description': ["Run and dump the memory information for an application.",
                                                            "Write the app id or a part of the app name to be launched"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function' : mem_info.run_app_meminfo
                                        },
                                        "running_app_meminfo" : { 
                                            'description': ["Dump the memory information for a running application",
                                                            "Write the app id or a part of the app name"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': mem_info.running_app_meminfo
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "force_app_stop" :  { 
                                    'description': ["Force the stop of a running application",
                                                    "Write the app id or a part of the app name"],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.force_app_stop
                                },
                                "track_logs" : {
                                    'description': ['Process for logs gathering:',
                                                    ' > automated mode: the application will be launched by the script',
                                                    ' > manual mode: the application needs to be launched by the user'],
                                    'device_needed': True,
                                    'children': {
                                        "run_and_log" : {
                                            'description' : ["Run the app and logs it using the tool",
                                                             "Write the app id or a part of the app name"],
                                            'device_needed': True,
                                            'children': {
                                                "normal_logs" : {
                                                    'description' : ["Launch an application and log all the events",
                                                                     "Write the app id or a part of the app name"],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    
                                                    'function': app_logs.run_and_logs
                                                },
                                                "crash_logs" : {
                                                    'description' : ["Launch an application and log its crash events",
                                                                     "Write the app id or a part of the app name"],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    
                                                    'function': app_logs.run_and_crash_logs
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                        },
                                        "running_app_log" : {
                                            'description' : ["Log a running app",],
                                            'device_needed': True,
                                            'children': {
                                                "normal_logs" : {
                                                    'description' : ["Log all the events of a running application",
                                                                     "Write the app id or a part of the app name"],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    
                                                    'function': app_logs.logs_from_running_process
                                                },
                                                "crash_logs" : {
                                                    'description' : ["Log the crash events of a running application",
                                                                     "Write the app id or a part of the app name"],
                                                    'device_needed': True,
                                                    'children': {
                                                        "back" : dict(),
                                                        "home" : dict()
                                                    },
                                                    
                                                    'function': app_logs.crash_logs_from_running_process
                                                },
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                        },
                                        "log_sessions" : {
                                            'description' : ["List logging sessions",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': app_logs.list_daemons
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                          
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                                      
                        },
                        "device_info": {
                            'description' : ["Get mobile device information",],
                            'device_needed': True,
                            'children': {
                                "apps_list": {
                                    'description' : ["Get list of all the installed apps",],
                                    'device_needed': True,
                                    'children': {
                                        "3rd_party_apps": {
                                            'description' : ["Get list of all the installed 3rd-party apps",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': useful_stuff.third_party_apps
                                        },
                                        "system_apps": {
                                            'description' : ["Get list of all the installed system apps",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': useful_stuff.system_apps
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "battery_status" : {
                                    'description' : ["Battery Status",
                                                             "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': battery.check_battery_status
                                },
                                "cpu_info": {
                                    'description' : ["Get CPU information",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.cpu_info
                                },
                                "general_info": {
                                    'description' : ["Get mobile device general information",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.general_info
                                },
                                "network_info": {
                                    'description' : ["Get Network information",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.network_info
                                },
                                "ram_info": {
                                    'description' : ["Get RAM information",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.ram_info
                                },
                                "storage_info": {
                                    'description' : ["Get Storage information",
                                                     "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.storage_info
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                        },
                        'devices':{
                            'description': ["Select one of the available mobile devices\n(the current one is highlighted with a different background)",
                                            "Press ENTER to continue..."],
                            'device_needed': False,
                            'children': {
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                            'function': adb.select_device

                        },
                        "emulator":{
                            'description': ['Emulators management'],
                            'device_needed': False,
                            'children': {
                                "avd_create":{
                                    'description': ['Create a new AVD.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': emulator.create_avd_device
                                },
                                "avd_delete":{
                                    'description': ['Delete an existing AVD.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': emulator.delete_avd
                                },
                                "avd_list":{
                                    'description': ['List all the available AVDs.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': emulator.list_available_avds_pretty
                                },
                                "emulator_launch":{
                                    'description': ['Launch the emulator for an available AVD.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': emulator.launch_avd_emulator
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                            'function': signature.sign_apk
                        },
                        'file_transfer' : {
                            'description' : ['Transfer files from/to mobile devices'],
                            'device_needed': True,
                            'children': {
                                "download_from_mobile" :  { 
                                    'description': ["Doenload a file/folder from the mobile device",
                                                    "Write the following two strings (separated by space):",
                                                    " > the path of the file/folder on the mobile device",
                                                    " > the PC folder (where the file will be downloaded)"],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': file_transfer.download_from_user_input
                                },
                                "upload_to_mobile" : { 
                                    'description': ["Upload a file/folder to the mobile device",
                                                    "Write the following two strings (separated by space):",
                                                    " > the path of the file/folder on the PC",
                                                    " > the mobile device folder (where the file will be uploaded)"],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': file_transfer.upload
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                        },
                        "frida":{
                            'description': ['Frida management'],
                            'device_needed': True,
                            'children': {
                                "install":{
                                    'description': ['Install Frida via PIP and the Frida Server on the device.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': frida_integration.install_frida
                                },
                                "start_server":{
                                    'description': ['Start the Frida Server on the device.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': frida_integration.start_frida
                                },
                                "run_script":{
                                    'description': ['Run Frida scripts on a specific application.',
                                                    'Write its app id or a keyword to identify it.'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': frida_integration.run_script
                                },
                                "uninstall":{
                                    'description': ['Uninstall Frida and the related Frida Server.',
                                                    'Press ENTER to continue...'],
                                    'device_needed': False,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': frida_integration.run_script
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                            'function': signature.sign_apk
                        },
                        "install_uninstall" : {
                            'description': ['Install an app on the mobile device.',],
                            'device_needed': True,
                            'children': {
                                "install_from_apk" : {
                                    'description' : ["Install an APK file on the mobile device",
                                                     "Write the path of the apk on your PC",],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': apk_install.install_from_apk
                                },
                                "install_from_playstore" : {
                                    'description' : ["Install an app from the Play Store",
                                                     "Write the app id of the app to be installed",
                                                     "(the Play Store will be opened on the mobile device and then you can manually install it)",],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': apk_install.install_from_playstore
                                },                                
                                "uninstall" : {
                                    'description' : ["Uninstall an app from the mobile device",
                                                     "Write the app id of the app to be uninstalled",],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': apk_install.uninstall_app
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                        },
                        "interactive_shell" :{
                            'description': ['Interactive shell for the mobile device',
                                            "Press ENTER to continue..."],
                            'device_needed': True,
                            'children': {
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                            'function': shell.interactive_adb_shell
                        },
                        "mirroring" : {
                            'description': ['Mirroring management',],
                            'device_needed': True,
                            'children': {
                                "mirroring" : {
                                    'description': ['Launch scrcpy for mobile device mirroring',
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': mirroring.mirroring
                                },
                                "stop_mirroring" : {
                                    'description': ['Stop scrcpy session for mobile device mirroring',
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': mirroring.stop_mirroring
                                },
                                "screenshot_video" : {
                                    'description' : ["Screenshot/Video on the mobile device",],
                                    'device_needed': True,
                                    'children': {
                                        "screenshot" : {
                                            'description' : ["Screenshot",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': mirroring.screenshot
                                        },
                                        "video_record" : {
                                            'description' : ["Start Video Recording",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': mirroring.record_video
                                        },
                                        "stop_video_record" : {
                                            'description' : ["Stop Video recording",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': mirroring.stop_recording
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                        },
                        "mobile_settings" : {
                            'description' : ['Management of mobile device modes (battery saver, do not disturb, connectivity)',],
                            'device_needed': True,
                            'children' : {
                                "battery_saver" : {
                                    'description' : ["Battery Saver mode",],
                                    'device_needed': True,
                                    'children': {
                                        "off" : {
                                            'description' : ["Turn off battery saver mode",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': battery.battery_saver_off
                                        },
                                        "on" : {
                                            'description' : ["Turn on battery saver mode",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': battery.battery_saver_on
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "do_not_disturb_mode" : {
                                    'description' : ["Do Not Disturb mode",],
                                    'device_needed': True,
                                    'children': {
                                        "off" : {
                                            'description' : ["Turn off Do Not Disturb mode",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.donotdisturb_disabled
                                        },
                                        "alarms_only" : {
                                            'description' : ["Turn on Do Not Disturb mode with alarms only",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.donotdisturb_alarms_only
                                        },
                                        "priority_only" : {
                                            'description' : ["Turn on Do Not Disturb mode with priority only",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.donotdisturb_priority_only
                                        },
                                        "total_silence" : {
                                            'description' : ["Turn on Do Not Disturb mode with total silence",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.donotdisturb_total_silence
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "connectivity" : {
                                    'description' : ["Connectivity options management (Wifi, airplane mode)",],
                                    'device_needed': True,
                                    'children': {
                                        "wifi_off" : {
                                            'description' : ["Turn off Wifi option",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.disable_wifi
                                        },
                                        "wifi_on" : {
                                            'description' : ["Turn on Wifi option",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.enable_wifi
                                        },
                                        "airplane_off" : {
                                            'description' : ["Turn off Airplane mode",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.disable_airplane_mode
                                        },
                                        "airplane_on" : {
                                            'description' : ["Turn on Airplane mode",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': connectivity.enable_airplane_mode
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                            
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                                          
                        },
                        "processes_list" : {
                            'description' : ["List all the processes",
                                             'Press ENTER to continue',],
                            'device_needed': False,
                            'children': {
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                            'function': modules.tasks_management.list_daemons
                        },
                        "proxy" : {
                            'description': ['Set proxy on the mobile device (using the current PC IP or another IP):',
                                            ' > DNS spoofer (Invisible)',
                                            ' > IPTables Proxy (Invisible)'
                                            ' > System Proxy',],
                            'device_needed': True,
                            'children': {
                                "dns" : {
                                    'description': ['Set proxy routes using a DNS server'],
                                    'device_needed': True,
                                    'children': {
                                        "get_current_proxy" : {
                                            'description' : ["List current DNS proxy settings",
                                                             "Press ENTER to see current DNS proxy settings"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.get_current_dns_proxy
                                        },
                                        "set_proxy_with_current_ip" : {
                                            'description' : ["Start the DNS spoofing with the current PC IP (on the same Wi-fi network of the mobile device)",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_current_pc_dns_proxy
                                        },
                                        "set_proxy_with_other_ip" : {
                                            'description' : ["Start the DNS spoofing with a specific IP address",
                                                             "Write the IP address to be used in the proxy for DNS spoofing",],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_generic_dns_proxy
                                        },
                                        "del_proxy" : {
                                            'description' : ["Reset current DNS Proxy configuration"
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.del_dns_proxy
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "invisible_proxy" : {
                                    'description': ['Set global proxy on the mobile device:',
                                                    ' > using the current PC IP',
                                                    ' > using another IP'],
                                    'device_needed': True,
                                    'children': {
                                        "get_current_proxy" : {
                                            'description' : ["See the current invisible proxy settings",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.get_current_invisible_proxy
                                        },
                                        "set_proxy_with_current_ip" : {
                                            'description' : ["Set the current PC IP as invisible proxy",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_current_pc_invisible_proxy
                                        },
                                        "set_proxy_with_other_ip" : {
                                            'description' : ["Set an IP address as invisible proxy",
                                                             "Insert the IP address you want to select as invisible proxy"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_generic_invisible_proxy
                                        },
                                        "del_proxy" : {
                                            'description' : ["Reset current invisible proxy configuration",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.del_invisible_proxy
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                },
                                "system_proxy" : {
                                    'description': ['Set global proxy on the mobile device:',
                                                    ' > using the current PC IP',
                                                    ' > using another IP'],
                                    'device_needed': True,
                                    'children': {
                                        "get_current_proxy" : {
                                            'description' : ["Press ENTER to see current proxy settings"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.get_current_proxy_settings
                                        },
                                        "set_proxy_with_current_ip" : {
                                            'description' : ["Set the current PC IP as proxy",
                                                             "Write the port number for the proxy on the current PC",],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_current_pc_proxy
                                        },
                                        "set_proxy_with_other_ip" : {
                                            'description' : ["Set the remote IP address to be used as proxy",
                                                             "Write the remote IP address and the port number of the proxy (e.g. 127.0.0.1:8080)"],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.set_generic_proxy
                                        },
                                        "del_proxy" : {
                                            'description' : ["Reset current proxy configuration",
                                                             "Press ENTER to continue..."],
                                            'device_needed': True,
                                            'children': {
                                                "back" : dict(),
                                                "home" : dict()
                                            },
                                            
                                            'function': proxy.del_proxy
                                        },
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                            
                                },
                                "back" : dict(),
                                "home" : dict()
                            },
                            
                                            
                        },
                        "shutdown_reboot" : {
                            'description' : ["Reboot/shutdown the device with several options:",
                                            ' > Shutdown',
                                            ' > Reboot'
                                            ' > Reboot in recovery mode',
                                            ' > Reboot in bootloader mode',],
                            'device_needed': True,
                            'children': {
                                "shutdown" : {
                                    'description' : ["Shutdown the mobile device",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.shutdown
                                },
                                "reboot" : {
                                    'description' : ["Reboot the mobile device",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.reboot
                                },
                                "reboot_recovery" : {
                                    'description' : ["Reboot the mobile device in recovery mode",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.reboot_recovery
                                },
                                "reboot_bootloader" : {
                                    'description' : ["Reboot the mobile device in bootloader mode",
                                                    "Press ENTER to continue..."],
                                    'device_needed': True,
                                    'children': {
                                        "back" : dict(),
                                        "home" : dict()
                                    },
                                    
                                    'function': useful_stuff.reboot_bootloader
                                },
                                "back" : dict(),
                                "home" : dict()
                            }
                        }
                    }
                }
            }
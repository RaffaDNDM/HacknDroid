# HacknDroid
The script is used for the automation of some MAPT activities and the interaction with the mobile Android device. The script was created to solve many problems:
- the command `adb root` is not enabled after device rooting on many production mobile devices;
- the files need to be shared before on the external SD Card and then on the device;
- the retrieving of the application data (APKs, Shared preferences, Stored data) needs to be found and retrieved with several commands;
- the unpacking process of the application APK need a merge phase for application with multiple APKs in `/data/app/{app_id}_{base64_unique_id}` for efficency purpouses

---

## Pre-requisites
Install the following programs and add their folder with binary files in the `PATH` environment variable:
- [***ADB***](https://developer.android.com/tools/adb) for interaction with the mobile device in Developer Mode;
- [***scrcpy***](https://github.com/Genymobile/scrcpy) for mirroring and remote control of the mobile device over ADB connection;
- [***JADX***](https://github.com/skylot/jadx) to explore source obtained from the decompiled code from the APK;
- [**Apktool**](https://apktool.org/) to compile and decompile APKs;
- [**APKEditor**]() to merge APKs.
- [**ABE**](https://github.com/nelenkov/android-backup-extractor) Android Backup Extractor to create TAR from Android Backup.

### APKEditor and Apktool
For the following programs, create the wrapper to call the program without writing `java -jar`.
As described for Apktool [here](https://apktool.org/docs/install), rename the tools JAR files as:
- `apktool.jar`
- `APKEditor.jar`
- `abe.jar`

Create a wrapper for both the JAR files.
For APKEditor and ABE, you can create one of the following wrappers depending on the Operating System:
- Windows (`APKEditor.bat`)
```bash
@echo off
setlocal

REM Set the path to your APKEditor.jar
set APKEDITOR_P="C:/Windows/APKEditor.jar"

REM Run APKEditor.jar
java -jar %APKEDITOR_P% %*

endlocal
```

Insert the wrapper and the JAR in one of the paths registered in the `PATH` environment variable (e.g. `C:\Windows\`).

- UNIX-based systems (`APKEditor`)
```bash
$APKEDITOR_PATH = "./APKEditor.jar"
java -jar $APKEDITOR_PATH "$@"
```
Insert the wrapper and the JAR in `/usr/local/bin`.

## Install
Install python requirements using the following command:
```bash
pip install -r requirements.txt
```

---

## Run the program
```bash
python main.py
```
![Run Example](.img/run_example_0.png)
![Run Example](.img/run_example_1.png)
![Run Example](.img/run_example_2.png)

### Proxy via DNS Spoofing (on Windows)
To run DNS Server using the tool, ensure that the Windows Firewall is disabled on the PC where the script will be run:
![Run Example](.img/disable_windows_firewall_0.png)
![Run Example](.img/disable_windows_firewall_1.png)

If everything was set successfully, you can intercept the traffic on ports 80, 443 in Burp Suite as follows:
![Run Example](.img/dns_proxy_intercept.png)

---


## Script features
- [ ] ***Task Manager***
  - [] Daemon tasks
    - [x] logcat
    - [x] mirroring
    - [ ] proxy with dns spoofing
  - [x] Sequential tasks

- [ ] ***Functionalities***
- [ ] `apk_analysis`<br>Analysis of the APKs (signature schema verifier, apk decompiling, search for common Root Detection, Certificate Pinning, SHA1-SHA256 strings in smali files, etc.)
  - [ ] `from_apk_on_pc`
  - [ ] `from_mobile_device`
    - [ ] Cordova
    - [ ] Flutter
- [x] `apk_compiling`<br>Compile an APK file from the folder with decompiled and modified code
  - [x] `compile`: Compile an apk file from the folder with decompiled and modified code
  - [x] `compile_and_sign`: Compile and sign an apk file from the folder with decompiled and modified code
- [x] `apk_decompiling`<br>Decompile an APK file
  - [x] `from_apk_on_pc`: 
  - [x] `from_mobile_device`: 
- [x] `apk_to_jar`<br>Convert the apk to a jar file
  - [x] `from_apk_on_pc`: 
    - [x] `create_jar_file`: 
    - [x] `jadx_create_and_open_file`: 
  - [x] `from_mobile_device`: 
    - [x] `create_jar_file`: 
    - [x] `jadx_create_and_open_file`: 
- [x] `backup_and_data`<br>Backup the mobile device or an application
  - [x] `backup_device`: Backup the mobile device
  - [x] `backup_specific_app`: Backup a specific app specifing its app ID
  - [x] `backup_restore`: Specify the backup file path on your system
  - [x] `backup_to_folder`: Convert the AB file to an unpacked folder
  - [x] `reset_app_data`: Reset App data
- [x] `download_from_mobile`<br>Download file from the mobile device
- [ ] `frida`: Use Frida for several functionalities
  - [ ] `function_hooking`
  - [ ] `script`
- [x] `install_uninstall`<br>Install/Uninstall an app on the mobile device
  - [x] `install_from_apk`
  - [x] `install_from_playstore`
  - [x] `uninstall`
- [x] `merge_apks`<br>Merge several APKs using APKEditor
  - [x] `from_directory`
  - [x] `from_list`
- [x] `mirroring`<br>Launch scrcpy for mobile device mirroring
- [x] `proxy`<br>Set global proxy on the mobile device
  - [x] `system_proxy`
    - [x] `get_current_proxy`
    - [x] `set_proxy_with_current_ip`
    - [x] `set_proxy_with_other_ip`
    - [x] `del_proxy`
  - [ ] `invisible_proxy`
    - [ ] `ip_tables`
      - [ ] `get_current_proxy`
      - [ ] `set_proxy_with_current_ip`
      - [ ] `set_proxy_with_other_ip`
      - [ ] `del_proxy`
    - [x] `dns`
      - [x] `get_current_proxy`
      - [x] `dns_server_with_current_ip`
      - [x] `dns_server_with_another_ip`
  - [ ] `install_certificates`
    - [ ] install depending on android
      - [ ] Android <=10
      - [ ] Android 10+
    - [ ] Install without Rooted device
      - [ ] MDM install 
      - [ ] install certificates on user land and modify android manifest
      - [ ] VPN certificate in userland 
- [x] `sign_apk`<br>Sign an apk on your PC. Write the path of the apk you want to test
- [ ] `system_mount_for_root`: Device rooting
  - [ ] Android <=10
  - [ ] Android 10+
- [ ] `track_logs`<br>Logs gathering
  - [x] `all_logs`
  - [ ] `all_crash_logs`
- [x] `upload_to_mobile`<br>Upload a file from PC to mobile device
- [x] `useful_staffs`
  - [x] `device_info`
    - [x] `apps_list`
      - [x] `3rd_party_apps`: Get list of all the installed 3rd-party apps
      - [x] `system_apps`: Get list of all the installed system apps
    - [x] `cpu_info`: Get CPU information
    - [x] `general_info`: Get mobile device general information
    - [x] `ram_info`: Get RAM information
    - [x] `storage_info`: Get Storage information
  - [x] `battery_saver`: Battery Saver mode (ON/OFF)
  - [x] `do_not_disturb_mode`: Do Not Disturb mode (ON/OFF)
  - [x] `connectivity`: Connectivity options management
    - [x] `wifi`: Wifi option Management (ON/OFF)
    - [x] `airplane`: Airplane mode Management (ON/OFF)
  - [ ] `screenshot_video`: Screenshot/Video on the mobile device
    - [ ] `screenshot`
    - [ ] `video`
  - [x] `shutdown`<br>Shutdown/Reboot the device with several options
    - [x] `shutdown`: Shutdown the mobile device
    - [x] `reboot`: Reboot the mobile device
    - [x] `reboot_recovery`: Reboot the mobile device in recovery mode
    - [x] `reboot_bootloader`: Reboot the mobile device in bootloader mode

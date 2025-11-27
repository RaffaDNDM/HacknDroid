// Delay to ensure VM is ready
setTimeout(function() {
    if (!Java.available) {
        console.log("[-] Java VM not ready, retrying...");
        setTimeout(arguments.callee, 1000);
        return;
    }

    Java.perform(function() {
        console.log("[*] Hooking Android developer settings checks...");

        try {
            const androidSettings = [
                "adb_enabled",
                "development_settings_enabled",
                "play_protect_enabled"
            ];

            const SDK = Java.use("android.os.Build$VERSION").SDK_INT.value;
            console.log("[+] Android SDK Version:", SDK);

            const Secure = Java.use("android.provider.Settings$Secure");
            const Global = Java.use("android.provider.Settings$Global");
            const System = Java.use("android.provider.Settings$System");

            // Helper to patch getInt method for a given class
            function patchSettingsClass(SettingsClass, className) {
                SettingsClass.getInt.overload(
                    "android.content.ContentResolver",
                    "java.lang.String",
                    "int"
                ).implementation = function (cr, name, def) {
                    if (androidSettings.indexOf(name) !== -1) {
                        console.log(`[+] ${className} Bypass for: ${name}`);
                        if (name === "play_protect_enabled") return 1;
                        return 0;
                    }
                    return this.getInt(cr, name, def);
                };
            }

            patchSettingsClass(Secure, "Settings.Secure");
            patchSettingsClass(Global, "Settings.Global");
            patchSettingsClass(System, "Settings.System");

            console.log("[+] Developer/USB/PlayProtect bypass active ✅");
        } catch (e) {
            console.log("[-] Error in Developer mode bypass:", e);
        }
    });
}, 0);

send({ type: "log", payload: "1. Hook script loaded! Waiting for Java.perform..." });

// Let Frida natively handle the VM attachment
Java.perform(function() {
    send({ type: "log", payload: "2. [SUCCESS] Inside native Dalvik/ART VM!" });
    
    try {
        var File = Java.use("java.io.File");
        File.renameTo.overload('java.io.File').implementation = function(dest) {
            var src = this.getAbsolutePath();
            var dst = dest.getAbsolutePath();
            
            // Log every rename so we can see the exact paths
            send({ type: "log", payload: "Renaming: " + src + " -> " + dst });
            
            if (src.indexOf("Ransomware") !== -1 || dst.indexOf(".enc") !== -1) {
                send({ type: "rename", src: src, dst: dst });
            }
            return this.renameTo(dest);
        };
        send({ type: "log", payload: "3. java.io.File hook deployed successfully." });
    } catch (e) {
        send({ type: "log", payload: "[-] Failed to hook File: " + e.message });
    }
});

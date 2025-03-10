import frida

JS_CODE = """
Interceptor.attach(Module.findExportByName(null, 'CreateFileA'), {
    onEnter: function(args) {
        send("File opened: " + Memory.readUtf8String(args[0]));
    }
});
Interceptor.attach(Module.findExportByName(null, 'InternetOpenA'), {
    onEnter: function(args) {
        send("Network request: " + Memory.readUtf8String(args[0]));
    }
});
"""

def hook_process(target_process):
    try:
        session = frida.attach(target_process)
    except Exception as e:
        print(f"Error attaching to process {target_process}: {e}")
        return

    try:
        script = session.create_script(JS_CODE)
    except Exception as e:
        print(f"Error creating script: {e}")
        return

    script.on("message", lambda message, data: print("[API CALL]", message["payload"]))
    script.load()
    print(f"Successfully monitoring {target_process}...")

    input()

if __name__ == "__main__":
    target = input("Enter process name to monitor: ")
    hook_process(target)

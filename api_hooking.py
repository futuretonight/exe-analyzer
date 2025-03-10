import tkinter as tk
import sys

# Check if frida is available
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

# JavaScript code for API hooking
JS_CODE = """
Interceptor.attach(Module.findExportByName(null, 'CreateFileA'), {
    onEnter: function(args) {
        send("File opened: " + Memory.readUtf8String(args[0]));
    }
});

Interceptor.attach(Module.findExportByName(null, 'CreateFileW'), {
    onEnter: function(args) {
        send("File opened (W): " + Memory.readUtf16String(args[0]));
    }
});

Interceptor.attach(Module.findExportByName(null, 'InternetOpenA'), {
    onEnter: function(args) {
        send("Network request: " + Memory.readUtf8String(args[0]));
    }
});

Interceptor.attach(Module.findExportByName(null, 'socket'), {
    onEnter: function(args) {
        send("Socket created");
    }
});

Interceptor.attach(Module.findExportByName(null, 'connect'), {
    onEnter: function(args) {
        send("Connection attempt");
    }
});

Interceptor.attach(Module.findExportByName(null, 'RegOpenKeyExA'), {
    onEnter: function(args) {
        if (args[1]) {
            send("Registry access: " + Memory.readUtf8String(args[1]));
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'RegOpenKeyExW'), {
    onEnter: function(args) {
        if (args[1]) {
            send("Registry access (W): " + Memory.readUtf16String(args[1]));
        }
    }
});
"""

def on_message(message, data, result_text):
    """Handle messages from the Frida script"""
    if message['type'] == 'send':
        result_text.insert(tk.END, f"[API HOOK] {message['payload']}\n")
        result_text.see(tk.END)
    elif message['type'] == 'error':
        result_text.insert(tk.END, f"[API HOOK] Error: {message['stack']}\n")
        result_text.see(tk.END)

def hook_process(target_process, result_text):
    """Hook into a process to monitor API calls"""
    if not FRIDA_AVAILABLE:
        result_text.insert(tk.END, "[API HOOK] Error: Frida library not available. API hooking disabled.\n")
        result_text.see(tk.END)
        return
        
    try:
        result_text.insert(tk.END, f"[API HOOK] Attaching to process {target_process}...\n")
        session = frida.attach(target_process)
        
        result_text.insert(tk.END, "[API HOOK] Creating script...\n")
        script = session.create_script(JS_CODE)
        
        # Set up message handler
        script.on("message", lambda message, data: on_message(message, data, result_text))
        
        result_text.insert(tk.END, "[API HOOK] Loading script...\n")
        script.load()
        
        result_text.insert(tk.END, f"[API HOOK] Successfully monitoring process {target_process}\n")
        result_text.see(tk.END)
        
    except Exception as e:
        result_text.insert(tk.END, f"[API HOOK] Error setting up API hooking: {str(e)}\n")
        result_text.see(tk.END)
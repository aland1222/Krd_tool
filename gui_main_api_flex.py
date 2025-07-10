import tkinter as tk
from tkinter import messagebox
import importlib

def run_tool(module_name, label):
    try:
        tool = importlib.import_module(f"modules.{module_name}")
        tool.run()
    except Exception as e:
        messagebox.showerror("Error", f"❌ Failed to run {label}:\n{str(e)}")

root = tk.Tk()
root.title("KRD")
root.geometry("300x250")
tk.Label(root, text="KRD Tool", font=("Helvetica", 14, "bold")).pack(pady=10)

tk.Button(root, text="🕷️ Web Exploit", width=25, command=lambda: run_tool("web_exploit", "Web Exploit")).pack(pady=5)
tk.Button(root, text="🧠 Ultra Vuln Scanner", command=lambda: run_tool("vulan_scanner", "Vuln Scanner")).pack(pady=5)
tk.Button(root, text="🌐 IP Scanner", command=lambda: run_tool("ip_scanner", "IP Scanner")).pack(pady=5)
tk.Button(root, text="🛰️ Subfinder + HTTPX", command=lambda: run_tool("subfinder_httox", "Subfinder + HTTPX")).pack(pady=5)

tk.Label(root, text="Lostseckrd v1.0 © 2025", font=("Arial", 8)).pack(side="bottom", pady=8)
root.mainloop()

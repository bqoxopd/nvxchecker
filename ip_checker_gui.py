import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import subprocess
import platform
import threading
import socket
import os
import re

CONFIG_FILE = "config.txt"
AUTO_REFRESH_INTERVAL = 10  # в секундах

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return []
    config = []
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = re.match(r'^([^\s]+)\s+\(([^)]+)\)$', line)
            if match:
                domain, desc = match.groups()
                config.append((domain, desc))
    return config

def get_netstat_output():
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(["netstat", "-n"], capture_output=True, text=True)
        else:
            result = subprocess.run("netstat -n", shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Ошибка: {e}"

def check_dns(domain):
    try:
        if platform.system() != 'Windows':
            return False
        result = subprocess.run("netsh dns show dnsservers", shell=True, capture_output=True, text=True)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def check_ips(config_entries, netstat_output):
    matched = []
    for domain, desc, ip in config_entries:
        if ip is None:
            continue
        pattern = re.compile(rf"\b{re.escape(ip)}(:\d+)?\b")
        if pattern.search(netstat_output):
            matched.append((domain, desc, ip))
    return matched

class IPCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NVX IP Monitor")
        self.root.geometry("640x580")
        self.root.configure(bg="#121822")
        self.root.resizable(False, False)

        self.style = ttk.Style()
        self.style.theme_use('default')

        self.style.configure('TButton',
                             font=('Segoe UI', 13, 'bold'),
                             foreground='#ffffff',
                             background='#1e90ff',
                             padding=12)
        self.style.map('TButton',
                       background=[('active', '#3399ff'), ('pressed', '#0d75d8')],
                       foreground=[('disabled', '#888888')])

        self.style.configure('TLabel',
                             background='#121822',
                             foreground='#e1f0ff',
                             font=('Segoe UI', 10))

        self.style.configure('Header.TLabel',
                             font=('Segoe UI', 18, 'bold'),
                             foreground='#00c8ff',
                             background='#121822')

        self.menu_frame = tk.Frame(self.root, bg="#0a3d62", height=80)
        self.menu_frame.pack(fill=tk.X)

        try:
            img = Image.open("nvx_logo.png").resize((70, 70), Image.Resampling.LANCZOS)
            self.logo_img = ImageTk.PhotoImage(img)
            logo_label = tk.Label(self.menu_frame, image=self.logo_img, bg="#0a3d62")
            logo_label.pack(side=tk.LEFT, padx=15, pady=5)
        except Exception as e:
            print(f"Логотип не загружен: {e}")

        title_label = ttk.Label(self.menu_frame, text="NVX IP Monitor", style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=10, pady=20)

        self.btn_check = ttk.Button(self.root, text="Проверить подключения", command=self.start_check_thread)
        self.btn_check.pack(pady=(20, 15), ipadx=15, ipady=8)

        self.output_frame = tk.Frame(self.root, bg="#182a45")
        self.output_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.text_output = tk.Text(self.output_frame,
                                   bg='#182a45',
                                   fg='#d0eaff',
                                   font=("Consolas", 12),
                                   relief=tk.FLAT,
                                   wrap=tk.WORD,
                                   insertbackground='#00c8ff')
        self.text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)

        self.scrollbar = ttk.Scrollbar(self.output_frame, orient=tk.VERTICAL, command=self.text_output.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        self.text_output.config(yscrollcommand=self.scrollbar.set)

        self.text_output.tag_configure("intro", foreground="#00c8ff", font=("Consolas", 13, "bold"))
        self.text_output.tag_configure("checking", foreground="#40e0d0")
        self.text_output.tag_configure("found", foreground="#7fff00", font=("Consolas", 12, "bold"))
        self.text_output.tag_configure("notfound", foreground="#ffaa00", font=("Consolas", 12, "bold"))
        self.text_output.tag_configure("error", foreground="#ff5555", font=("Consolas", 12, "bold"))

        self.text_output.config(state=tk.DISABLED)

        self.print_intro()
        self.schedule_auto_check()

    def print_intro(self):
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete('1.0', tk.END)
        self.text_output.insert(tk.END, "by @nvxproject aka sonyloon\n\n", "intro")
        self.text_output.config(state=tk.DISABLED)

    def start_check_thread(self):
        threading.Thread(target=self.check_all_gui, daemon=True).start()

    def check_all_gui(self):
        self.btn_check.state(['disabled'])
        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, "▶ Проверка IP и DNS...\n", "checking")
        self.text_output.see(tk.END)
        self.text_output.config(state=tk.DISABLED)

        config_entries = load_config()
        if not config_entries:
            messagebox.showwarning("Внимание", "Файл config.txt пуст или не найден.\nДобавьте домены с описаниями.")
            self.btn_check.state(['!disabled'])
            return

        resolved_entries = []
        for domain, desc in config_entries:
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = None
            resolved_entries.append((domain, desc, ip))

        netstat_data = get_netstat_output()

        results = []
        for domain, desc, ip in resolved_entries:
            found_dns = False
            found_netstat = False

            if ip is not None:
                found_dns = True

            if ip is not None:
                pattern = re.compile(rf"\b{re.escape(ip)}(:\d+)?\b")
                if pattern.search(netstat_data):
                    found_netstat = True

            if found_dns:
                results.append((domain, desc, ip, "dns", True))
            elif found_netstat:
                results.append((domain, desc, ip, "netstat", True))
            else:
                results.append((domain, desc, ip, None, False))

        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, "\nРезультаты:\n", "intro")
        for domain, desc, ip, method, found in results:
            if found:
                self.text_output.insert(tk.END, f"✅ {domain} ({desc}) — НАЙДЕН методом: {method}\n", "found")
            elif ip is None:
                self.text_output.insert(tk.END, f"❌ {domain} ({desc}) — НЕ НАЙДЕН: не удалось резолвить\n", "error")
            else:
                self.text_output.insert(tk.END, f"❌ {domain} ({desc}) — НЕ НАЙДЕН\n", "notfound")
        self.text_output.insert(tk.END, "\n")
        self.text_output.see(tk.END)
        self.text_output.config(state=tk.DISABLED)

        self.btn_check.state(['!disabled'])

    def schedule_auto_check(self):
        self.start_check_thread()
        self.root.after(AUTO_REFRESH_INTERVAL * 1000, self.schedule_auto_check)

def main():
    root = tk.Tk()
    try:
        root.iconbitmap(default='')
    except Exception:
        pass
    root.attributes('-toolwindow', True)
    app = IPCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

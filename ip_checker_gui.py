import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import subprocess
import platform
import threading
import time
import os
import re

CONFIG_FILE = "config.txt"
AUTO_REFRESH_INTERVAL = 10  # в секундах

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return []
    with open(CONFIG_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def get_netstat_output():
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(["netstat", "-n"], capture_output=True, text=True)
        else:
            result = subprocess.run("netstat -n", shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Ошибка: {e}"

def check_ips(config_ips, netstat_output):
    matched = []
    for ip in config_ips:
        pattern = re.compile(rf"\b{re.escape(ip)}(:\d+)?\b")
        if pattern.search(netstat_output):
            matched.append(ip)
    return matched

class IPCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NVX IP Monitor")
        self.root.geometry("640x580")
        self.root.configure(bg="#121822")
        self.root.resizable(False, False)

        self.style = ttk.Style(self.root)
        self.style.theme_use('default')

        self.style.configure('TButton',
                             font=('Segoe UI', 13, 'bold'),
                             foreground='#ffffff',
                             background='#1e90ff',
                             borderwidth=0,
                             focusthickness=3,
                             focuscolor='none',
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
            img = Image.open("nvx_logo.png").resize((70, 70), Image.ANTIALIAS)
            self.logo_img = ImageTk.PhotoImage(img)
            # Для изображения используем tk.Label без style
            logo_label = tk.Label(self.menu_frame, image=self.logo_img, bg="#0a3d62")
            logo_label.pack(side=tk.LEFT, padx=15, pady=5)
        except Exception as e:
            print(f"Логотип не загружен: {e}")

        # Заголовок — ttk.Label с применением стиля
        title_label = ttk.Label(self.menu_frame, text="NVX IP Monitor", style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=10, pady=20)

        self.btn_check = ttk.Button(self.root, text="Проверить подключения", command=self.start_check_thread)
        self.btn_check.pack(pady=(20, 15), ipadx=15, ipady=8)

        self.output_frame = tk.Frame(self.root, bg="#182a45", bd=0, relief=tk.FLAT)
        self.output_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.text_output = tk.Text(self.output_frame,
                                   bg='#182a45',
                                   fg='#d0eaff',
                                   font=("Consolas", 12),
                                   relief=tk.FLAT,
                                   wrap=tk.WORD,
                                   insertbackground='#00c8ff')
        self.text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0), pady=10)

        self.scrollbar = ttk.Scrollbar(self.output_frame, orient=tk.VERTICAL, command=self.text_output.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,10), pady=10)
        self.text_output.config(yscrollcommand=self.scrollbar.set)

        self.text_output.tag_configure("intro", foreground="#00c8ff", font=("Consolas", 13, "bold"))
        self.text_output.tag_configure("checking", foreground="#40e0d0")
        self.text_output.tag_configure("found", foreground="#7fff00", font=("Consolas", 12, "bold"))
        self.text_output.tag_configure("notfound", foreground="#ffaa00", font=("Consolas", 12, "bold"))

        self.text_output.config(state=tk.DISABLED)

        self.print_intro()
        self.schedule_auto_check()

    def print_intro(self):
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete('1.0', tk.END)
        self.text_output.insert(tk.END, "by @nvxproject aka sonyloon\n\n", "intro")
        self.text_output.config(state=tk.DISABLED)

    def start_check_thread(self):
        threading.Thread(target=self.check_ips_gui, daemon=True).start()

    def check_ips_gui(self):
        self.btn_check.state(['disabled'])
        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, "▶ Проверка IP...\n", "checking")
        self.text_output.see(tk.END)
        self.text_output.config(state=tk.DISABLED)

        config_ips = load_config()
        if not config_ips:
            messagebox.showwarning("Внимание", "Файл config.txt пуст или не найден.\nДобавьте IP-адреса в файл.")
            self.btn_check.state(['!disabled'])
            return

        netstat_data = get_netstat_output()
        matched = check_ips(config_ips, netstat_data)

        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, "\nРезультаты:\n", "intro")
        if matched:
            for ip in matched:
                self.text_output.insert(tk.END, f"✅ {ip} — НАЙДЕН\n", "found")
        else:
            self.text_output.insert(tk.END, "❌ Нет совпадений\n", "notfound")
        self.text_output.insert(tk.END, "\n")
        self.text_output.see(tk.END)
        self.text_output.config(state=tk.DISABLED)

        self.btn_check.state(['!disabled'])

    def schedule_auto_check(self):
        self.start_check_thread()
        self.root.after(AUTO_REFRESH_INTERVAL * 1000, self.schedule_auto_check)

def main():
    root = tk.Tk()
    # Убираем системное меню (перышко) только для Windows
    if platform.system() == 'Windows':
        root.attributes('-toolwindow', True)
    app = IPCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

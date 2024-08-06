import tkinter as tk
from tkinter import scrolledtext
import threading
import ids_logic  
import threading
import time
stop_event = threading.Event()

def update_gui(message):
    log_display.config(state=tk.NORMAL)
    log_display.insert(tk.END, message + "\n\n")
    log_display.config(state=tk.DISABLED)
    log_display.yview(tk.END)

def start_sniffing_thread():
    global stop_event
    stop_event.clear()  
    threading.Thread(target=ids_logic.start_sniffing, args=(update_gui, stop_event)).start()


def stop_sniffing():
    stop_event.set()
    update_gui("Sniffing stopped...")

root = tk.Tk()
root.title("Intrusion Detection System")

log_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30, state=tk.DISABLED)
log_display.pack(padx=10, pady=10)

start_button = tk.Button(root, text="Start IDS", command=start_sniffing_thread)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop IDS", command=stop_sniffing)
stop_button.pack(pady=5)

root.mainloop()

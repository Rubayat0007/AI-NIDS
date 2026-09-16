# ============================================================
# AI-NIDS PROFESSIONAL DASHBOARD
# ============================================================

import os
import csv
import threading
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

from predict import (
    load_model,
    capture_network_traffic,
    predict_traffic,
)

load_model()


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_FILE = os.path.join(
    BASE_DIR,
    "results",
    "detection_log.csv"
)


# ============================================================
# COLORS
# ============================================================

BG = "#0f172a"
CARD = "#1e293b"
CARD_LIGHT = "#334155"
TEXT = "#f8fafc"
MUTED = "#94a3b8"
GREEN = "#22c55e"
RED = "#ef4444"
YELLOW = "#f59e0b"
BLUE = "#38bdf8"
WHITE = "#ffffff"


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title("AI-NIDS | Network Intrusion Detection System")
root.geometry("1100x720")
root.minsize(950, 650)

root.configure(bg=BG)


# ============================================================
# STYLE
# ============================================================

style = ttk.Style()

try:
    style.theme_use("clam")
except Exception:
    pass

style.configure(
    "Treeview",
    background=CARD,
    foreground=TEXT,
    fieldbackground=CARD,
    rowheight=32,
    borderwidth=0,
    font=("Segoe UI", 10)
)

style.configure(
    "Treeview.Heading",
    background=CARD_LIGHT,
    foreground=TEXT,
    font=("Segoe UI", 10, "bold"),
    relief="flat"
)

style.map(
    "Treeview",
    background=[
        ("selected", CARD_LIGHT)
    ],
    foreground=[
        ("selected", WHITE)
    ]
)


# ============================================================
# VARIABLES
# ============================================================

status_var = tk.StringVar(
    value="SYSTEM READY"
)

prediction_var = tk.StringVar(
    value="WAITING"
)

confidence_var = tk.StringVar(
    value="--"
)

risk_var = tk.StringVar(
    value="--"
)

severity_var = tk.StringVar(
    value="--"
)

packets_var = tk.StringVar(
    value="--"
)

duration_var = tk.StringVar(
    value="--"
)

timestamp_var = tk.StringVar(
    value="--"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def create_card(parent, row, column, title, variable):

    frame = tk.Frame(
        parent,
        bg=CARD,
        highlightthickness=1,
        highlightbackground=CARD_LIGHT
    )

    frame.grid(
        row=row,
        column=column,
        padx=8,
        pady=8,
        sticky="nsew"
    )

    title_label = tk.Label(
        frame,
        text=title,
        bg=CARD,
        fg=MUTED,
        font=("Segoe UI", 10)
    )

    title_label.pack(
        anchor="w",
        padx=18,
        pady=(15, 3)
    )

    value_label = tk.Label(
        frame,
        textvariable=variable,
        bg=CARD,
        fg=TEXT,
        font=("Segoe UI", 21, "bold")
    )

    value_label.pack(
        anchor="w",
        padx=18,
        pady=(0, 15)
    )

    return value_label


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=30,
    pady=(25, 10)
)


title = tk.Label(
    header,
    text="AI-NIDS",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 30, "bold")
)

title.pack(
    anchor="w"
)


subtitle = tk.Label(
    header,
    text="AI-Based Network Intrusion Detection System",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 12)
)

subtitle.pack(
    anchor="w",
    pady=(2, 0)
)


# ============================================================
# STATUS BAR
# ============================================================

status_frame = tk.Frame(
    root,
    bg=CARD
)

status_frame.pack(
    fill="x",
    padx=30,
    pady=(5, 10)
)


status_indicator = tk.Label(
    status_frame,
    text="●",
    bg=CARD,
    fg=GREEN,
    font=("Segoe UI", 14)
)

status_indicator.pack(
    side="left",
    padx=(15, 5),
    pady=10
)


status_label = tk.Label(
    status_frame,
    textvariable=status_var,
    bg=CARD,
    fg=TEXT,
    font=("Segoe UI", 10, "bold")
)

status_label.pack(
    side="left",
    pady=10
)


# ============================================================
# METRIC CARDS
# ============================================================

cards_frame = tk.Frame(
    root,
    bg=BG
)

cards_frame.pack(
    fill="x",
    padx=22
)

for i in range(6):
    cards_frame.columnconfigure(
        i,
        weight=1
    )


prediction_label = create_card(
    cards_frame,
    0,
    0,
    "PREDICTION",
    prediction_var
)

confidence_label = create_card(
    cards_frame,
    0,
    1,
    "CONFIDENCE",
    confidence_var
)

risk_label = create_card(
    cards_frame,
    0,
    2,
    "RISK SCORE",
    risk_var
)

severity_label = create_card(
    cards_frame,
    0,
    3,
    "SEVERITY",
    severity_var
)

packets_label = create_card(
    cards_frame,
    0,
    4,
    "PACKETS",
    packets_var
)

duration_label = create_card(
    cards_frame,
    0,
    5,
    "DURATION",
    duration_var
)


# ============================================================
# MAIN RESULT PANEL
# ============================================================

result_frame = tk.Frame(
    root,
    bg=CARD,
    highlightthickness=1,
    highlightbackground=CARD_LIGHT
)

result_frame.pack(
    fill="x",
    padx=30,
    pady=15
)


result_title = tk.Label(
    result_frame,
    text="LIVE DETECTION STATUS",
    bg=CARD,
    fg=MUTED,
    font=("Segoe UI", 10, "bold")
)

result_title.pack(
    pady=(18, 5)
)


result_label = tk.Label(
    result_frame,
    text="SYSTEM READY",
    bg=CARD,
    fg=TEXT,
    font=("Segoe UI", 26, "bold")
)

result_label.pack(
    pady=(0, 5)
)


warning_label = tk.Label(
    result_frame,
    text="Click RUN NETWORK DETECTION to capture live traffic.",
    bg=CARD,
    fg=MUTED,
    font=("Segoe UI", 11)
)

warning_label.pack(
    pady=(0, 18)
)


# ============================================================
# CONTROL BUTTON
# ============================================================

button_frame = tk.Frame(
    root,
    bg=BG
)

button_frame.pack(
    fill="x",
    padx=30
)


detect_button = tk.Button(
    button_frame,
    text="RUN NETWORK DETECTION",
    command=lambda: start_detection(),
    bg=BLUE,
    fg="#000000",
    activebackground=WHITE,
    activeforeground="#000000",
    font=("Segoe UI", 12, "bold"),
    relief="flat",
    cursor="hand2",
    padx=25,
    pady=12
)

detect_button.pack(
    pady=5
)


# ============================================================
# LAST DETECTION
# ============================================================

last_frame = tk.Frame(
    root,
    bg=BG
)

last_frame.pack(
    fill="x",
    padx=30,
    pady=(5, 5)
)


timestamp_text = tk.Label(
    last_frame,
    text="Last Detection:",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 9)
)

timestamp_text.pack(
    side="left"
)


timestamp_value = tk.Label(
    last_frame,
    textvariable=timestamp_var,
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 9, "bold")
)

timestamp_value.pack(
    side="left",
    padx=5
)


# ============================================================
# DETECTION HISTORY
# ============================================================

history_title = tk.Label(
    root,
    text="RECENT DETECTION HISTORY",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 11, "bold")
)

history_title.pack(
    anchor="w",
    padx=30,
    pady=(8, 5)
)


history_frame = tk.Frame(
    root,
    bg=BG
)

history_frame.pack(
    fill="both",
    expand=True,
    padx=30,
    pady=(0, 20)
)


columns = (
    "timestamp",
    "prediction",
    "confidence",
    "severity",
    "packets",
    "duration"
)

history_tree = ttk.Treeview(
    history_frame,
    columns=columns,
    show="headings",
    height=5
)


history_tree.heading(
    "timestamp",
    text="Timestamp"
)

history_tree.heading(
    "prediction",
    text="Prediction"
)

history_tree.heading(
    "confidence",
    text="Confidence"
)

history_tree.heading(
    "severity",
    text="Severity"
)

history_tree.heading(
    "packets",
    text="Packets"
)

history_tree.heading(
    "duration",
    text="Duration"
)


history_tree.column(
    "timestamp",
    width=180
)

history_tree.column(
    "prediction",
    width=110,
    anchor="center"
)

history_tree.column(
    "confidence",
    width=120,
    anchor="center"
)

history_tree.column(
    "severity",
    width=100,
    anchor="center"
)

history_tree.column(
    "packets",
    width=100,
    anchor="center"
)

history_tree.column(
    "duration",
    width=100,
    anchor="center"
)


history_tree.pack(
    side="left",
    fill="both",
    expand=True
)


scrollbar = ttk.Scrollbar(
    history_frame,
    orient="vertical",
    command=history_tree.yview
)

scrollbar.pack(
    side="right",
    fill="y"
)


history_tree.configure(
    yscrollcommand=scrollbar.set
)


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history():

    if not os.path.exists(LOG_FILE):
        return

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            rows = list(reader)

            # Show newest first
            rows = rows[-10:][::-1]

            for row in rows:

                prediction = row.get(
                    "prediction",
                    ""
                )

                prediction_text = (
                    "ATTACK"
                    if prediction == "1"
                    else "NORMAL"
                )

                history_tree.insert(
                    "",
                    "end",
                    values=(
                        row.get("timestamp", ""),
                        prediction_text,
                        f"{row.get('confidence', '--')}%",
                        row.get("severity", ""),
                        row.get("packets_captured", ""),
                        f"{row.get('capture_duration', '--')}s"
                    )
                )

    except Exception as error:

        print(
            f"History loading error: {error}"
        )


# ============================================================
# REFRESH HISTORY
# ============================================================

def refresh_history():

    for item in history_tree.get_children():

        history_tree.delete(item)

    load_history()


# ============================================================
# UPDATE GUI
# ============================================================

def update_gui(result):

    prediction = result.get(
        "prediction",
        0
    )

    confidence = result.get(
        "confidence",
        0.0
    )

    severity = result.get(
        "severity",
        "LOW"
    )

    packets = result.get(
        "packet_count",
        0
    )

    duration = result.get(
        "duration",
        0
    )

    confidence_percent = confidence * 100

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    if prediction == 1:

        prediction_var.set("ATTACK")

        prediction_label.config(
            fg=RED
        )

        result_label.config(
            text="ATTACK DETECTED",
            fg=RED
        )

        warning_label.config(
            text="Suspicious network traffic detected!",
            fg=RED
        )

    else:
       if severity == "SUSPICIOUS":
        prediction_var.set("UNCERTAIN")
        prediction_label.config(fg=YELLOW)
        result_label.config(
            text="SUSPICIOUS TRAFFIC",
            fg=YELLOW
        )
        warning_label.config(
            text="Traffic may require further investigation.",
            fg=YELLOW
        )
       else:
        prediction_var.set("NORMAL")
        prediction_label.config(fg=GREEN)
        result_label.config(
            text="NORMAL TRAFFIC",
            fg=GREEN
        )
        warning_label.config(
            text="Network traffic appears normal.",
            fg=GREEN
        )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence_var.set(
        f"{confidence_percent:.2f}%"
    )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk_percent = result.get(
    "attack_probability",
    0.0,
    ) * 100

    risk_var.set(
    f"{risk_percent:.2f}%"
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity_var.set(
        severity
    )

    if severity == "HIGH":

        severity_label.config(
            fg=RED
        )

    elif severity == "MEDIUM":

        severity_label.config(
            fg=YELLOW
        )

    else:

        severity_label.config(
            fg=GREEN
        )

    # --------------------------------------------------------
    # Packets
    # --------------------------------------------------------

    packets_var.set(
        str(packets)
    )

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    duration_var.set(
        f"{duration:.2f}s"
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    timestamp_var.set(
        timestamp
    )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    status_var.set(
        "DETECTION COMPLETE"
    )

    status_indicator.config(
        fg=GREEN
    )

    # --------------------------------------------------------
    # Refresh history
    # --------------------------------------------------------

    refresh_history()

    # --------------------------------------------------------
    # Enable button
    # --------------------------------------------------------

    detect_button.config(
        state="normal",
        text="RUN NETWORK DETECTION"
    )


# ============================================================
# DETECTION WORKER
# ============================================================

def detection_worker():

    try:

        # ----------------------------------------------------
        # Capture live traffic
        # ----------------------------------------------------

        packets, duration = capture_network_traffic(
            seconds=8
        )

        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        result = predict_traffic(
            packets,
            duration
        )

        # ----------------------------------------------------
        # Update GUI safely
        # ----------------------------------------------------

        root.after(
            0,
            lambda: update_gui(result)
        )

    except Exception as error:

        print()
        print("DASHBOARD ERROR")
        print(error)

        root.after(
            0,
            lambda: detection_error(str(error))
        )


# ============================================================
# START DETECTION
# ============================================================

def start_detection():

    detect_button.config(
        state="disabled",
        text="CAPTURING NETWORK..."
    )

    status_var.set(
        "CAPTURING LIVE NETWORK TRAFFIC..."
    )

    status_indicator.config(
        fg=YELLOW
    )

    result_label.config(
        text="CAPTURING...",
        fg=YELLOW
    )

    warning_label.config(
        text="Please wait. Capturing network packets for 8 seconds...",
        fg=MUTED
    )

    prediction_var.set(
        "CAPTURING"
    )

    confidence_var.set(
        "--"
    )

    risk_var.set(
        "--"
    )

    severity_var.set(
        "--"
    )

    packets_var.set(
        "--"
    )

    duration_var.set(
        "--"
    )

    # --------------------------------------------------------
    # Run capture in background thread
    # --------------------------------------------------------

    thread = threading.Thread(
        target=detection_worker,
        daemon=True
    )

    thread.start()


# ============================================================
# ERROR HANDLER
# ============================================================

def detection_error(error_message):

    status_var.set(
        "DETECTION ERROR"
    )

    status_indicator.config(
        fg=RED
    )

    result_label.config(
        text="ERROR",
        fg=RED
    )

    warning_label.config(
        text="Network detection failed. Check the terminal.",
        fg=RED
    )

    detect_button.config(
        state="normal",
        text="RUN NETWORK DETECTION"
    )

    messagebox.showerror(
        "AI-NIDS Error",
        error_message
    )


# ============================================================
# WINDOW CLOSE
# ============================================================

def on_close():

    root.destroy()


root.protocol(
    "WM_DELETE_WINDOW",
    on_close
)


# ============================================================
# INITIAL HISTORY
# ============================================================

load_history()


# ============================================================
# START GUI
# ============================================================

root.mainloop()
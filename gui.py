import csv
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

import pytesseract
from PIL import Image

from Scam_shield import analyze_message as core_analyzer


CSV_FILE = "scam_history.csv"


# -------------------- HELPERS --------------------

def get_recommendation(message, result):
    text = message.lower()
    flags = result["detected_flags"]
    recommendations = []

    if any(x in text for x in ["otp", "pin", "cvv", "password"]):
        recommendations.append("Do not share OTP, PIN, CVV or password.")

    if any(x in flags for x in ["pay", "payment", "registration fee", "processing fee"]):
        recommendations.append("Do not send money without independent verification.")

    if "http://" in text or "https://" in text or "www." in text or "click here" in text:
        recommendations.append("Do not click suspicious links.")

    if any(x in flags for x in ["you won", "prize", "reward"]):
        recommendations.append("Verify the prize or reward through an official source.")

    if "blocked" in text or "kyc" in text:
        recommendations.append(
            "Check account status only through the official app or website."
        )

    if not recommendations:
        recommendations.append("Verify the sender and source before taking action.")

    return " ".join(recommendations)


def extract_sender(message):
    phone = re.search(r"\+?\d[\d\s-]{8,}\d", message)
    if phone:
        return phone.group(0).strip()

    lines = [line.strip() for line in message.splitlines() if line.strip()]

    if lines:
        first = lines[0]

        if len(first) <= 40 and not re.search(r"https?://|www\.", first):
            return first

    return "Not detected"


def analyze_source(message):
    urls = re.findall(r"(?:https?://|www\.)\S+", message)
    domains = []

    for url in urls:
        domain = re.sub(r"^(?:https?://|www\.)", "", url)
        domain = domain.split("/")[0].strip()
        domains.append(domain)

    financial = []

    if re.search(r"(₹|rs\.?|inr)\s*[\d,]+", message, re.I):
        financial.append("Amount detected")

    if re.search(r"\bupi\b", message, re.I):
        financial.append("UPI detected")

    if any(x in message.lower() for x in ["payment", "transfer", "bank"]):
        financial.append("Payment/Bank reference")

    sensitive = []

    for item in ["OTP", "PIN", "CVV", "password", "KYC"]:
        if item.lower() in message.lower():
            sensitive.append(item)

    return {
        "urls": urls,
        "domains": domains,
        "financial": financial,
        "sensitive": sensitive,
        "sender": extract_sender(message),
    }


def calculate_coverage(message, source):
    message_available = bool(message.strip())
    sender_available = source["sender"] != "Not detected"
    identifier_available = bool(source["domains"] or sender_available)

    if message_available and sender_available and identifier_available:
        return "HIGH"

    if message_available and (sender_available or identifier_available):
        return "MEDIUM"

    return "PARTIAL"


def save_history(message, result, input_type="Text"):
    source = analyze_source(message)
    coverage = calculate_coverage(message, source)
    file_exists = os.path.exists(CSV_FILE)

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(
                [
                    "Date/Time",
                    "Input Type",
                    "Sender",
                    "Scam Type",
                    "Risk Score",
                    "Risk Level",
                    "Detected Flags",
                    "Patterns",
                    "Coverage",
                ]
            )

        writer.writerow(
            [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                input_type,
                source["sender"],
                result["scam_type"],
                result["risk_score"],
                result["risk_level"],
                ", ".join(result["detected_flags"]),
                ", ".join(result["patterns"]),
                coverage,
            ]
        )


def read_history():
    if not os.path.exists(CSV_FILE):
        return []

    with open(CSV_FILE, "r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


# -------------------- MAIN WINDOW --------------------

root = tk.Tk()
root.title("Scam Shield")
root.geometry("1200x850")
root.minsize(1000, 700)
root.configure(bg="#0B1120")


# -------------------- SIDEBAR --------------------

sidebar = tk.Frame(root, bg="#111827", width=220)
sidebar.pack(side="left", fill="y")
sidebar.pack_propagate(False)

logo = tk.Label(
    sidebar,
    text="🛡 SCAM SHIELD",
    font=("Arial", 18, "bold"),
    bg="#111827",
    fg="#38BDF8",
)
logo.pack(pady=30)


def make_menu(text):
    label = tk.Label(
        sidebar,
        text=text,
        font=("Arial", 12),
        bg="#111827",
        fg="#94A3B8",
        anchor="w",
        padx=25,
        pady=15,
        cursor="hand2",
    )
    label.pack(fill="x")

    def on_enter(event):
        label.config(bg="#1E293B", fg="#F8FAFC")

    def on_leave(event):
        label.config(bg="#111827", fg="#94A3B8")

    label.bind("<Enter>", on_enter)
    label.bind("<Leave>", on_leave)

    return label


menu_dashboard = make_menu("⌂ Dashboard")
menu_analyze = make_menu("⌕ Analyze Message")
menu_screenshot = make_menu("▣ Screenshot")
menu_analytics = make_menu("▤ Analytics")
menu_history = make_menu("◷ History")
menu_settings = make_menu("⚙ Settings")


# -------------------- MAIN AREA --------------------

main_area = tk.Frame(root, bg="#0B1120")
main_area.pack(side="left", fill="both", expand=True)


header = tk.Frame(main_area, bg="#0B1120")
header.pack(fill="x", padx=35, pady=(18, 5))

tk.Label(
    header,
    text="Scam Detection Dashboard",
    font=("Arial", 24, "bold"),
    bg="#0B1120",
    fg="#F8FAFC",
).pack(anchor="w")

tk.Label(
    header,
    text="Detect suspicious messages and protect yourself from online scams",
    font=("Arial", 12),
    bg="#0B1120",
    fg="#94A3B8",
).pack(anchor="w", pady=(3, 0))


# -------------------- KPI CARDS --------------------

stats_frame = tk.Frame(main_area, bg="#0B1120")
stats_frame.pack(fill="x", padx=35, pady=10)


def create_card(parent, title, color):
    card = tk.Frame(parent, bg="#172033", height=95)
    card.pack(side="left", fill="both", expand=True, padx=7)
    card.pack_propagate(False)

    tk.Label(
        card,
        text=title,
        font=("Arial", 10),
        bg="#172033",
        fg="#94A3B8",
    ).pack(anchor="w", padx=20, pady=(12, 2))

    value = tk.Label(
        card,
        text="0",
        font=("Arial", 24, "bold"),
        bg="#172033",
        fg=color,
    )
    value.pack(anchor="w", padx=20)

    return value


card1_value = create_card(stats_frame, "MESSAGES ANALYZED", "#38BDF8")
card2_value = create_card(stats_frame, "HIGH / CRITICAL", "#F87171")
card3_value = create_card(stats_frame, "MEDIUM RISK", "#FACC15")
card4_value = create_card(stats_frame, "LOW RISK", "#4ADE80")


# -------------------- INPUT PANEL --------------------

analysis_frame = tk.Frame(main_area, bg="#172033", height=165)
analysis_frame.pack(fill="x", padx=35, pady=(0, 10))
analysis_frame.pack_propagate(False)

tk.Label(
    analysis_frame,
    text="Analyze Suspicious Message",
    font=("Arial", 16, "bold"),
    bg="#172033",
    fg="#F8FAFC",
).pack(anchor="w", padx=20, pady=(10, 5))

message_box = tk.Text(
    analysis_frame,
    height=3,
    font=("Arial", 11),
    bg="#0B1120",
    fg="#F8FAFC",
    insertbackground="#F8FAFC",
    relief="flat",
    wrap="word",
)
message_box.pack(fill="x", padx=20)


button_frame = tk.Frame(analysis_frame, bg="#172033")
button_frame.pack(anchor="e", padx=20, pady=6)


# -------------------- RESULT PANEL --------------------

result_frame = tk.Frame(main_area, bg="#172033", height=285)
result_frame.pack(fill="x", padx=35, pady=(0, 20))
result_frame.pack_propagate(False)

tk.Label(
    result_frame,
    text="Analysis Result",
    font=("Arial", 16, "bold"),
    bg="#172033",
    fg="#F8FAFC",
).pack(anchor="w", padx=20, pady=(10, 5))

top_result_frame = tk.Frame(result_frame, bg="#172033")
top_result_frame.pack(fill="x", padx=20, pady=1)

risk_score_label = tk.Label(
    top_result_frame,
    text="Risk Score: --",
    font=("Arial", 12, "bold"),
    bg="#172033",
    fg="#38BDF8",
)
risk_score_label.pack(side="left", padx=(0, 35))

risk_level_label = tk.Label(
    top_result_frame,
    text="Risk Level: --",
    font=("Arial", 12, "bold"),
    bg="#172033",
    fg="#F87171",
)
risk_level_label.pack(side="left", padx=35)

scam_type_label = tk.Label(
    top_result_frame,
    text="Scam Type: --",
    font=("Arial", 12, "bold"),
    bg="#172033",
    fg="#FACC15",
)
scam_type_label.pack(side="left", padx=35)

red_flags_label = tk.Label(
    result_frame,
    text="Red Flags: --",
    font=("Arial", 11, "bold"),
    bg="#172033",
    fg="#F87171",
    wraplength=900,
    justify="left",
)
red_flags_label.pack(anchor="w", padx=20, pady=1)

patterns_label = tk.Label(
    result_frame,
    text="Patterns: --",
    font=("Arial", 11, "bold"),
    bg="#172033",
    fg="#FACC15",
    wraplength=900,
    justify="left",
)
patterns_label.pack(anchor="w", padx=20, pady=1)

recommendation_label = tk.Label(
    result_frame,
    text="Safety: --",
    font=("Arial", 11, "bold"),
    bg="#172033",
    fg="#4ADE80",
    wraplength=900,
    justify="left",
)
recommendation_label.pack(anchor="w", padx=20, pady=1)

explanation_label = tk.Label(
    result_frame,
    text="Why Suspicious: --",
    font=("Arial", 11),
    bg="#172033",
    fg="#F8FAFC",
    wraplength=900,
    justify="left",
)
explanation_label.pack(anchor="w", padx=20, pady=1)


# -------------------- FUNCTIONS --------------------

def update_kpis():
    history = read_history()

    total = len(history)
    high = sum(
        1
        for row in history
        if row.get("Risk Level") in ["HIGH", "CRITICAL"]
    )
    medium = sum(1 for row in history if row.get("Risk Level") == "MEDIUM")
    low = sum(1 for row in history if row.get("Risk Level") == "LOW")

    card1_value.config(text=str(total))
    card2_value.config(text=str(high))
    card3_value.config(text=str(medium))
    card4_value.config(text=str(low))


def analyze_message(input_type="Text"):
    message = message_box.get("1.0", tk.END).strip()

    if not message:
        messagebox.showwarning(
            "Empty Message",
            "Please enter a message first."
        )
        return

    result = core_analyzer(message)

    risk_score_label.config(
        text=f"Risk Score: {result['risk_score']}"
    )

    risk_level_label.config(
        text=f"Risk Level: {result['risk_level']}"
    )

    scam_type_label.config(
        text=f"Scam Type: {result['scam_type']}"
    )

    flags = (
        ", ".join(result["detected_flags"])
        if result["detected_flags"]
        else "None"
    )

    patterns = (
        ", ".join(result["patterns"])
        if result["patterns"]
        else "None"
    )

    red_flags_label.config(
        text=f"Red Flags: {flags}"
    )

    patterns_label.config(
        text=f"Patterns: {patterns}"
    )

    recommendation = get_recommendation(message, result)

    recommendation_label.config(
        text=f"Safety: {recommendation}"
    )

    if result["detected_flags"] or result["patterns"]:
        explanation = (
            "The message contains suspicious indicators: "
            + ", ".join(
                result["detected_flags"] + result["patterns"]
            )
            + "."
        )
    else:
        explanation = "No major suspicious indicators were detected."

    explanation_label.config(
        text=f"Why Suspicious: {explanation}"
    )

    save_history(message, result, input_type)
    update_kpis()


def upload_screenshot():
    file_path = filedialog.askopenfilename(
        title="Select Screenshot",
        filetypes=[
            ("Image Files", "*.png *.jpg *.jpeg"),
            ("All Files", "*.*"),
        ],
    )

    if not file_path:
        return

    try:
        image = Image.open(file_path)
        text = pytesseract.image_to_string(image).strip()

        if not text:
            messagebox.showwarning(
                "OCR Result",
                "No readable text was found in the screenshot."
            )
            return

        message_box.delete("1.0", tk.END)
        message_box.insert("1.0", text)

        analyze_message("Screenshot")

    except Exception as error:
        messagebox.showerror(
            "Screenshot Error",
            str(error)
        )


def show_history():
    window = tk.Toplevel(root)
    window.title("ScamShield History")
    window.geometry("1050x500")
    window.configure(bg="#0B1120")

    tk.Label(
        window,
        text="Analysis History",
        font=("Arial", 18, "bold"),
        bg="#0B1120",
        fg="#F8FAFC",
    ).pack(anchor="w", padx=20, pady=15)

    columns = (
        "Date/Time",
        "Input Type",
        "Sender",
        "Scam Type",
        "Risk Score",
        "Risk Level",
        "Coverage",
    )

    tree = ttk.Treeview(
        window,
        columns=columns,
        show="headings"
    )

    for column in columns:
        tree.heading(column, text=column)
        tree.column(column, width=135)

    tree.pack(
        fill="both",
        expand=True,
        padx=20,
        pady=10
    )

    for row in read_history():
        tree.insert(
            "",
            "end",
            values=[
                row.get(column, "")
                for column in columns
            ],
        )


def show_analytics():
    history = read_history()

    if not history:
        messagebox.showinfo(
            "Analytics",
            "No analysis data available yet."
        )
        return

    try:
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    except ImportError:
        messagebox.showerror(
            "Matplotlib Missing",
            "Install matplotlib using: pip install matplotlib"
        )
        return

    risk_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    scam_counts = {}

    for row in history:
        level = row.get("Risk Level", "")
        if level in risk_counts:
            risk_counts[level] += 1

        scam = row.get("Scam Type", "Unknown")
        scam_counts[scam] = scam_counts.get(scam, 0) + 1

    analytics_window = tk.Toplevel(root)
    analytics_window.title("ScamShield Analytics")
    analytics_window.geometry("1100x700")
    analytics_window.configure(bg="#0B1120")

    tk.Label(
        analytics_window,
        text="ScamShield Analytics",
        font=("Arial", 20, "bold"),
        bg="#0B1120",
        fg="#F8FAFC",
    ).pack(anchor="w", padx=25, pady=(20, 5))

    tk.Label(
        analytics_window,
        text="Risk and scam category overview",
        font=("Arial", 11),
        bg="#0B1120",
        fg="#94A3B8",
    ).pack(anchor="w", padx=25, pady=(0, 10))

    figure, axes = plt.subplots(1, 2, figsize=(11, 5), facecolor="#0B1120")

    for ax in axes:
        ax.set_facecolor("#172033")
        ax.tick_params(colors="#CBD5E1")
        for spine in ax.spines.values():
            spine.set_color("#334155")

    axes[0].bar(risk_counts.keys(), risk_counts.values())
    axes[0].set_title("Risk Level Distribution", color="#F8FAFC", pad=12)
    axes[0].set_xlabel("Risk Level", color="#CBD5E1")
    axes[0].set_ylabel("Messages", color="#CBD5E1")

    axes[1].bar(scam_counts.keys(), scam_counts.values())
    axes[1].set_title("Scam Category Distribution", color="#F8FAFC", pad=12)
    axes[1].set_xlabel("Scam Type", color="#CBD5E1")
    axes[1].set_ylabel("Messages", color="#CBD5E1")
    axes[1].tick_params(axis="x", rotation=25)

    figure.tight_layout(pad=2)

    canvas = FigureCanvasTkAgg(figure, master=analytics_window)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)

    def close_analytics():
        plt.close(figure)
        analytics_window.destroy()

    analytics_window.protocol("WM_DELETE_WINDOW", close_analytics)


def show_source_info():
    message = message_box.get("1.0", tk.END).strip()

    if not message:
        messagebox.showinfo(
            "Source Analyzer",
            "Analyze a message first."
        )
        return

    source = analyze_source(message)
    coverage = calculate_coverage(
        message,
        source
    )

    urls = (
        ", ".join(source["urls"])
        if source["urls"]
        else "None"
    )

    domains = (
        ", ".join(source["domains"])
        if source["domains"]
        else "None"
    )

    financial = (
        ", ".join(source["financial"])
        if source["financial"]
        else "None"
    )

    sensitive = (
        ", ".join(source["sensitive"])
        if source["sensitive"]
        else "None"
    )

    messagebox.showinfo(
        "Source & Message Analyzer",
        f"Sender: {source['sender']}\n\n"
        f"Links: {urls}\n\n"
        f"Domains: {domains}\n\n"
        f"Financial Info: {financial}\n\n"
        f"Sensitive Info: {sensitive}\n\n"
        f"Coverage: {coverage}"
    )


def show_settings():
    messagebox.showinfo(
        "Settings",
        "ScamShield\n\n"
        "Storage: CSV\n"
        "OCR: Tesseract\n"
        "Analytics: Matplotlib\n"
        "Power BI: CSV compatible"
    )


# -------------------- BUTTON HOVER EFFECTS --------------------

def add_button_hover(button, normal_bg, hover_bg, normal_fg=None, hover_fg=None):
    def on_enter(event):
        button.config(bg=hover_bg)
        if hover_fg:
            button.config(fg=hover_fg)

    def on_leave(event):
        button.config(bg=normal_bg)
        if normal_fg:
            button.config(fg=normal_fg)

    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)


# -------------------- BUTTONS --------------------

upload_button = tk.Button(
    button_frame,
    text="Upload Screenshot",
    font=("Arial", 11, "bold"),
    bg="#1E293B",
    fg="#38BDF8",
    activebackground="#334155",
    activeforeground="#F8FAFC",
    relief="flat",
    padx=20,
    pady=8,
    width=18,
    cursor="hand2",
    command=upload_screenshot,
)
upload_button.pack(side="left", padx=5)
add_button_hover(upload_button, "#1E293B", "#334155", "#38BDF8", "#F8FAFC")

analyze_button = tk.Button(
    button_frame,
    text="Analyze Message",
    font=("Arial", 11, "bold"),
    bg="#38BDF8",
    fg="#0B1120",
    activebackground="#7DD3FC",
    activeforeground="#0B1120",
    relief="flat",
    padx=20,
    pady=8,
    width=18,
    cursor="hand2",
    command=analyze_message,
)
analyze_button.pack(side="left", padx=5)
add_button_hover(analyze_button, "#38BDF8", "#7DD3FC", "#0B1120", "#0B1120")

source_button = tk.Button(
    button_frame,
    text="Source Info",
    font=("Arial", 9),
    bg="#172033",
    fg="#94A3B8",
    activebackground="#334155",
    activeforeground="#F8FAFC",
    relief="flat",
    cursor="hand2",
    command=show_source_info,
)
source_button.pack(side="left", padx=5)
add_button_hover(source_button, "#172033", "#334155", "#94A3B8", "#F8FAFC")


# -------------------- SIDEBAR ACTIONS --------------------

menu_dashboard.bind(
    "<Button-1>",
    lambda event: message_box.focus()
)

menu_analyze.bind(
    "<Button-1>",
    lambda event: message_box.focus()
)

menu_screenshot.bind(
    "<Button-1>",
    lambda event: upload_screenshot()
)

menu_analytics.bind(
    "<Button-1>",
    lambda event: show_analytics()
)

menu_history.bind(
    "<Button-1>",
    lambda event: show_history()
)

menu_settings.bind(
    "<Button-1>",
    lambda event: show_settings()
)


update_kpis()

root.mainloop()

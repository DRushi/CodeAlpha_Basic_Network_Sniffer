import tkinter as tk
from tkinter import ttk, messagebox
import threading

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    get_if_list
)


class DarkSOCSniffer:

    def __init__(self, root):

        self.root = root
        self.root.title("SOC Network Monitor")
        self.root.geometry("1200x700")
        self.root.minsize(1000, 600)

        # -----------------------------
        # Application state
        # -----------------------------
        self.running = False
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        self.packet_details = {}

        # -----------------------------
        # Colors
        # -----------------------------
        self.bg = "#0b1117"
        self.sidebar = "#111923"
        self.panel = "#151f2b"
        self.panel2 = "#1b2735"
        self.text = "#e6edf3"
        self.muted = "#8b9aaa"
        self.green = "#2ecc71"
        self.red = "#ff5c5c"
        self.blue = "#4da6ff"
        self.yellow = "#f1c40f"

        self.root.configure(bg=self.bg)

        self.setup_style()
        self.create_gui()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    # =========================================================
    # STYLE
    # =========================================================

    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=self.panel,
            foreground=self.text,
            fieldbackground=self.panel,
            rowheight=30,
            borderwidth=0,
            font=("Arial", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=self.panel2,
            foreground=self.text,
            font=("Arial", 10, "bold"),
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#264f78")
            ]
        )

        style.configure(
            "TCombobox",
            fieldbackground=self.panel2,
            background=self.panel2,
            foreground=self.text
        )

    # =========================================================
    # MAIN GUI
    # =========================================================

    def create_gui(self):

        # =====================================================
        # TOP HEADER
        # =====================================================

        header = tk.Frame(
            self.root,
            bg=self.sidebar,
            height=70
        )

        header.pack(
            side=tk.TOP,
            fill=tk.X
        )

        title = tk.Label(
            header,
            text="  SOC NETWORK MONITOR",
            bg=self.sidebar,
            fg=self.text,
            font=("Arial", 20, "bold")
        )

        title.pack(
            side=tk.LEFT,
            padx=20
        )

        self.connection_status = tk.Label(
            header,
            text="● DISCONNECTED",
            bg=self.sidebar,
            fg=self.red,
            font=("Arial", 11, "bold")
        )

        self.connection_status.pack(
            side=tk.RIGHT,
            padx=25
        )

        # =====================================================
        # SIDEBAR
        # =====================================================

        sidebar = tk.Frame(
            self.root,
            bg=self.sidebar,
            width=220
        )

        sidebar.pack(
            side=tk.LEFT,
            fill=tk.Y
        )

        sidebar.pack_propagate(False)

        # Sidebar title
        tk.Label(
            sidebar,
            text="CAPTURE",
            bg=self.sidebar,
            fg=self.muted,
            font=("Arial", 10, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(25, 10)
        )

        # Interface
        tk.Label(
            sidebar,
            text="Network Interface",
            bg=self.sidebar,
            fg=self.text,
            font=("Arial", 10)
        ).pack(
            anchor="w",
            padx=20,
            pady=(5, 5)
        )

        interfaces = get_if_list()

        self.interface_combo = ttk.Combobox(
            sidebar,
            values=interfaces,
            state="readonly",
            width=22
        )

        if interfaces:
            self.interface_combo.current(0)

        self.interface_combo.pack(
            padx=20,
            pady=(0, 15)
        )

        # Start button
        self.start_button = tk.Button(
            sidebar,
            text="▶  START CAPTURE",
            command=self.start_capture,
            bg=self.green,
            fg="white",
            activebackground="#27ae60",
            activeforeground="white",
            relief=tk.FLAT,
            font=("Arial", 10, "bold"),
            cursor="hand2",
            height=2
        )

        self.start_button.pack(
            fill=tk.X,
            padx=20,
            pady=5
        )

        # Stop button
        self.stop_button = tk.Button(
            sidebar,
            text="■  STOP CAPTURE",
            command=self.stop_capture,
            bg=self.red,
            fg="white",
            activebackground="#c0392b",
            activeforeground="white",
            relief=tk.FLAT,
            font=("Arial", 10, "bold"),
            cursor="hand2",
            height=2,
            state=tk.DISABLED
        )

        self.stop_button.pack(
            fill=tk.X,
            padx=20,
            pady=5
        )

        # Clear button
        self.clear_button = tk.Button(
            sidebar,
            text="CLEAR PACKETS",
            command=self.clear_packets,
            bg=self.panel2,
            fg=self.text,
            activebackground="#26384a",
            activeforeground="white",
            relief=tk.FLAT,
            font=("Arial", 10, "bold"),
            cursor="hand2",
            height=2
        )

        self.clear_button.pack(
            fill=tk.X,
            padx=20,
            pady=5
        )

        # =====================================================
        # SIDEBAR STATISTICS
        # =====================================================

        tk.Label(
            sidebar,
            text="STATISTICS",
            bg=self.sidebar,
            fg=self.muted,
            font=("Arial", 10, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(30, 10)
        )

        self.total_label = self.create_stat(
            sidebar,
            "TOTAL PACKETS",
            "0"
        )

        self.tcp_label = self.create_stat(
            sidebar,
            "TCP",
            "0"
        )

        self.udp_label = self.create_stat(
            sidebar,
            "UDP",
            "0"
        )

        self.icmp_label = self.create_stat(
            sidebar,
            "ICMP",
            "0"
        )

        # =====================================================
        # CONTENT AREA
        # =====================================================

        content = tk.Frame(
            self.root,
            bg=self.bg
        )

        content.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        # =====================================================
        # DASHBOARD CARDS
        # =====================================================

        cards = tk.Frame(
            content,
            bg=self.bg
        )

        cards.pack(
            fill=tk.X,
            padx=20,
            pady=20
        )

        self.create_dashboard_card(
            cards,
            "CAPTURE STATUS",
            "IDLE",
            self.green
        )

        self.create_dashboard_card(
            cards,
            "PROTOCOL",
            "ALL",
            self.blue
        )

        self.create_dashboard_card(
            cards,
            "MONITOR",
            "LIVE",
            self.yellow
        )

        # =====================================================
        # FILTER BAR
        # =====================================================

        filter_frame = tk.Frame(
            content,
            bg=self.panel,
            height=55
        )

        filter_frame.pack(
            fill=tk.X,
            padx=20
        )

        tk.Label(
            filter_frame,
            text="FILTER:",
            bg=self.panel,
            fg=self.muted,
            font=("Arial", 10, "bold")
        ).pack(
            side=tk.LEFT,
            padx=(15, 5)
        )

        self.search_var = tk.StringVar()

        search_entry = tk.Entry(
            filter_frame,
            textvariable=self.search_var,
            bg=self.panel2,
            fg=self.text,
            insertbackground=self.text,
            relief=tk.FLAT,
            font=("Arial", 10)
        )

        search_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=5,
            pady=10
        )

        search_entry.bind(
            "<KeyRelease>",
            self.filter_packets
        )

        # =====================================================
        # PACKET TABLE
        # =====================================================

        table_container = tk.Frame(
            content,
            bg=self.panel
        )

        table_container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=(10, 20)
        )

        columns = (
            "id",
            "source",
            "destination",
            "protocol",
            "ports",
            "payload"
        )

        self.packet_table = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings"
        )

        self.packet_table.heading(
            "id",
            text="#"
        )

        self.packet_table.heading(
            "source",
            text="SOURCE"
        )

        self.packet_table.heading(
            "destination",
            text="DESTINATION"
        )

        self.packet_table.heading(
            "protocol",
            text="PROTOCOL"
        )

        self.packet_table.heading(
            "ports",
            text="PORTS"
        )

        self.packet_table.heading(
            "payload",
            text="PAYLOAD"
        )

        self.packet_table.column(
            "id",
            width=50,
            anchor=tk.CENTER
        )

        self.packet_table.column(
            "source",
            width=150
        )

        self.packet_table.column(
            "destination",
            width=150
        )

        self.packet_table.column(
            "protocol",
            width=100,
            anchor=tk.CENTER
        )

        self.packet_table.column(
            "ports",
            width=130,
            anchor=tk.CENTER
        )

        self.packet_table.column(
            "payload",
            width=350
        )

        scrollbar = ttk.Scrollbar(
            table_container,
            orient=tk.VERTICAL,
            command=self.packet_table.yview
        )

        self.packet_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.packet_table.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        # Double click
        self.packet_table.bind(
            "<Double-1>",
            self.show_packet_details
        )

    # =========================================================
    # SIDEBAR STAT
    # =========================================================

    def create_stat(
        self,
        parent,
        title,
        value
    ):

        frame = tk.Frame(
            parent,
            bg=self.panel
        )

        frame.pack(
            fill=tk.X,
            padx=15,
            pady=3
        )

        tk.Label(
            frame,
            text=title,
            bg=self.panel,
            fg=self.muted,
            font=("Arial", 8, "bold")
        ).pack(
            anchor="w",
            padx=10,
            pady=(5, 0)
        )

        label = tk.Label(
            frame,
            text=value,
            bg=self.panel,
            fg=self.text,
            font=("Arial", 16, "bold")
        )

        label.pack(
            anchor="w",
            padx=10,
            pady=(0, 5)
        )

        return label

    # =========================================================
    # DASHBOARD CARD
    # =========================================================

    def create_dashboard_card(
        self,
        parent,
        title,
        value,
        color
    ):

        card = tk.Frame(
            parent,
            bg=self.panel,
            width=220,
            height=80
        )

        card.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=5
        )

        card.pack_propagate(False)

        tk.Label(
            card,
            text=title,
            bg=self.panel,
            fg=self.muted,
            font=("Arial", 9, "bold")
        ).pack(
            anchor="w",
            padx=15,
            pady=(12, 0)
        )

        label = tk.Label(
            card,
            text=value,
            bg=self.panel,
            fg=color,
            font=("Arial", 18, "bold")
        )

        label.pack(
            anchor="w",
            padx=15
        )

    # =========================================================
    # PACKET PROCESSING
    # =========================================================

    def process_packet(self, packet):

        if not self.running:
            return

        if not packet.haslayer(IP):
            return

        source = packet[IP].src
        destination = packet[IP].dst

        source_port = "-"
        destination_port = "-"

        if packet.haslayer(TCP):

            protocol = "TCP"

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            self.tcp_count += 1

        elif packet.haslayer(UDP):

            protocol = "UDP"

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            self.udp_count += 1

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

            self.icmp_count += 1

        else:

            protocol = f"IP/{packet[IP].proto}"

        # Payload
        payload = ""

        if packet.haslayer(Raw):

            raw_data = packet[Raw].load

            try:

                payload = raw_data.decode(
                    "utf-8",
                    errors="ignore"
                )

                payload = payload.replace(
                    "\n",
                    " "
                ).replace(
                    "\r",
                    " "
                ).strip()

            except Exception:

                payload = raw_data.hex()

        if len(payload) > 80:
            payload = payload[:80] + "..."

        self.packet_count += 1

        packet_id = self.packet_count

        ports = (
            f"{source_port} → "
            f"{destination_port}"
        )

        data = (
            packet_id,
            source,
            destination,
            protocol,
            ports,
            payload
        )

        self.packet_details[packet_id] = packet

        # GUI update must happen in main thread
        self.root.after(
            0,
            self.add_packet,
            data
        )

    # =========================================================
    # ADD PACKET
    # =========================================================

    def add_packet(self, data):

        self.packet_table.insert(
            "",
            tk.END,
            values=data
        )

        self.total_label.config(
            text=str(self.packet_count)
        )

        self.tcp_label.config(
            text=str(self.tcp_count)
        )

        self.udp_label.config(
            text=str(self.udp_count)
        )

        self.icmp_label.config(
            text=str(self.icmp_count)
        )

        # Auto scroll
        children = self.packet_table.get_children()

        if children:
            self.packet_table.see(
                children[-1]
            )

    # =========================================================
    # START CAPTURE
    # =========================================================

    def start_capture(self):

        if self.running:
            return

        interface = self.interface_combo.get()

        if not interface:

            messagebox.showwarning(
                "Interface",
                "Please select a network interface."
            )

            return

        self.running = True

        self.start_button.config(
            state=tk.DISABLED
        )

        self.stop_button.config(
            state=tk.NORMAL
        )

        self.interface_combo.config(
            state=tk.DISABLED
        )

        self.connection_status.config(
            text="● CAPTURING",
            fg=self.green
        )

        # Background capture thread
        thread = threading.Thread(
            target=self.sniff_packets,
            daemon=True
        )

        thread.start()

    # =========================================================
    # SNIFF
    # =========================================================

    def sniff_packets(self):

        try:

            interface = self.interface_combo.get()

            sniff(
                iface=interface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda packet:
                    not self.running
            )

        except PermissionError:

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Permission Denied",
                    "Run this application with root privileges:\n\n"
                    "sudo python3 sniffer.py"
                )
            )

            self.root.after(
                0,
                self.stop_capture
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Capture Error",
                    str(error)
                )
            )

            self.root.after(
                0,
                self.stop_capture
            )

    # =========================================================
    # STOP
    # =========================================================

    def stop_capture(self):

        self.running = False

        self.start_button.config(
            state=tk.NORMAL
        )

        self.stop_button.config(
            state=tk.DISABLED
        )

        self.interface_combo.config(
            state="readonly"
        )

        self.connection_status.config(
            text="● STOPPED",
            fg=self.red
        )

    # =========================================================
    # CLEAR
    # =========================================================

    def clear_packets(self):

        for item in self.packet_table.get_children():

            self.packet_table.delete(item)

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        self.packet_details.clear()

        self.total_label.config(text="0")
        self.tcp_label.config(text="0")
        self.udp_label.config(text="0")
        self.icmp_label.config(text="0")

    # =========================================================
    # FILTER
    # =========================================================

    def filter_packets(self, event=None):

        search = self.search_var.get().lower()

        for item in self.packet_table.get_children():

            values = self.packet_table.item(
                item,
                "values"
            )

            text = " ".join(
                str(value)
                for value in values
            ).lower()

            if search in text:

                self.packet_table.reattach(
                    item,
                    "",
                    "end"
                )

            else:

                self.packet_table.detach(item)

    # =========================================================
    # PACKET DETAILS
    # =========================================================

    def show_packet_details(self, event=None):

        selected = self.packet_table.selection()

        if not selected:
            return

        values = self.packet_table.item(
            selected[0],
            "values"
        )

        if not values:
            return

        packet_id = int(values[0])

        packet = self.packet_details.get(
            packet_id
        )

        details_window = tk.Toplevel(
            self.root
        )

        details_window.title(
            f"Packet #{packet_id}"
        )

        details_window.geometry(
            "800x500"
        )

        details_window.configure(
            bg=self.bg
        )

        title = tk.Label(
            details_window,
            text=f"PACKET DETAILS  #{packet_id}",
            bg=self.bg,
            fg=self.green,
            font=("Arial", 16, "bold")
        )

        title.pack(
            anchor="w",
            padx=20,
            pady=15
        )

        text = tk.Text(
            details_window,
            bg=self.panel,
            fg=self.text,
            insertbackground=self.text,
            font=("Consolas", 10),
            relief=tk.FLAT,
            wrap=tk.WORD
        )

        text.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=(0, 20)
        )

        if packet:

            packet_info = packet.show(
                dump=True
            )

        else:

            packet_info = (
                "Detailed Scapy packet information "
                "is not available."
            )

        text.insert(
            tk.END,
            packet_info
        )

        text.config(
            state=tk.DISABLED
        )

    # =========================================================
    # CLOSE
    # =========================================================

    def close_application(self):

        self.running = False

        self.root.destroy()


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    root = tk.Tk()

    application = DarkSOCSniffer(
        root
    )

    root.mainloop()

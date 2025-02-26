import scapy.all as scapy
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.tls.all import *
import re
import pickle
import binascii
import datetime
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Optional, List, Dict, Tuple, Any
import threading
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import pandas as pd
from ttkthemes import ThemedStyle
import queue
import matplotlib
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import ipaddress
import sys
import networkx as nx

class PacketAnalyzer:
    SOCIAL_MEDIA_DOMAINS = {
        "facebook.com", "static.xx.fbcdn.net", "twitter.com", "instagram.com", "linkedin.com", "youtube.com",
        "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com", "whatsapp.com", "tumblr.com",
        "telegram.org", "discord.com", "wechat.com", "messenger.com", "twitch.tv", "x.com"
    }

    ECOMMERCE_DOMAINS = {
        "amazon.com", "ebay.com", "aliexpress.com", "etsy.com", "shopify.com", "walmart.com"
    }

    def __init__(self):
        self.capture = []
        self.user_ips = set()
        self.domains_accessed = set()
        self.protocols_used = dict()
        self.urls = set()
        self.packets_per_port = dict()
        
    def open_file(self, file_path):
        try:
            with scapy.PcapReader(file_path) as pcap_reader:
                for packet in pcap_reader:
                    self.capture.append(packet)
            return self.capture
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open pcap file: {str(e)}")
            return None

    def analyze_http_packet(self, packet):
        if packet.haslayer(HTTP):
            if packet.haslayer('HTTPRequest'):
                try:
                    http_layer = packet[HTTPRequest]
                    host = packet[HTTP].Host if hasattr(packet[HTTP], 'Host') and packet[HTTP].Host is not None else None
                    path = http_layer.Path.decode() if http_layer.Path else ''
                    if host and path:
                        host_str = host.decode('utf-8')
                        url = f"http://{host_str}{path}"
                        file_ext = ['.jpg', '.png', '.pdf', '.zip', '.html', '.js', '.css', '.gif', '.txt']
                        if any(path.endswith(ext) for ext in file_ext):
                            print(f"file detected: {url}")
                        if url not in self.urls:
                            self.urls.add(url)
                    if host:
                        host = host.decode()
                        
                        if self.contains_xss(path):
                            messagebox.showwarning("Alert","XSS attack detected.")
                        if self.contains_sql_injection(path):
                            messagebox.showwarning("Alert", "SQL Injection attack detected.")
                        return host
                except Exception as e:
                    messagebox.showerror("Error",f"Can't process HTTP packet: {e}")
                    return None
    
    def contains_xss(self, input_string):
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'on\w+=["\'].?["\']',
            r'javascript:',
            r'vbscript:',
            r'img\s+src\s*=["\'].*?["\'].*?onerror=',
        ]
        for pattern in xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
    
    def contains_sql_injection(self, input_string):
        sql_injection_patterns = [
            r'\'\s*OR\s*1=1',
            r'--',
            r'\'\s*AND\s*1=1',
            r'UNION\s+SELECT',
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE',
            r'EXEC\s*',
            r'INTO\s+OUTFILE',
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
        
    def analyze_https_packet(self, packet):
        try:
            if packet.haslayer(TLS):
                if TLSClientHello in packet:
                    client_hello = packet[TLSClientHello]
                    if hasattr(client_hello, 'ext'):
                        for extension in client_hello.ext:
                            if isinstance(extension, TLS_Ext_ServerName):
                                try:
                                    server_name = extension.servernames[0].servername.decode()
                                    return server_name
                                except Exception as e:
                                    messagebox.showerror("Error",f"Can't process SNI: {e}")
        except Exception as e:
            messagebox.showerror("Error",f"Can't process https packet: {str(e)}")
            return None

    def analyze_dns_packet(self,packet):
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.DNS):
            query_type = packet[scapy.DNS].qr
            if query_type==0:
                domain_name = packet[scapy.DNS].qd.qname.decode() if packet[scapy.DNS].qd else None
                return domain_name
        return "N/A"

    def collect_domains(self):
        for packet in self.capture:
            host = "N/A"
            host = self.analyze_dns_packet(packet)
            if host=="N/A":
                if packet.haslayer(scapy.IP):
                    if packet.haslayer(HTTP):
                        host = self.analyze_http_packet(packet)
                    elif packet.haslayer(TLS):
                        host = self.analyze_https_packet(packet)
            if host != "N/A":
                self.domains_accessed.add(host)
 
    @staticmethod
    def protocol_map(protocol_number):
        protocol_mapp = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            802: 'Ethernet',
            2048: 'ARP',
        }
        return protocol_mapp.get(protocol_number, 'Other')

    def get_packet_protocol(self, packet):
        if packet.haslayer(scapy.IP):
            if packet.haslayer(scapy.TCP):
                return 'TCP'
            elif packet.haslayer(scapy.UDP):
                return 'UDP'
            elif packet.haslayer(scapy.DNS):
                return 'DNS'
            else:
                return self.protocol_map(packet[scapy.IP].proto)
            
        elif packet.haslayer(scapy.IPv6):
            if packet.haslayer(scapy.TCP):
                return 'TCP'
            elif packet.haslayer(scapy.UDP):
                return 'UDP'
            else:
                return self.protocol_map(packet[scapy.IPv6].nh)
            
        elif packet.haslayer(scapy.ARP):
            return 'ARP'
        elif packet.haslayer(scapy.ICMP):
            return 'ICMP'
        else:
            return 'Other'
        
class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.target_domains: List[str] = []
        self.connections: Dict[Tuple, str] = {}
        self.log_handler = LogHandler()
        self.network_attack_detector = NetworkAttackDetector(self.log_handler)
        self.analyzer = PacketAnalyzer()
        self.total_packets = 0
        self.status_label = None
        self.main_paned = None
        self.file_path = ""
        self.sort_col = None
        self.sort_order = True
        self.sent_packets = set()
        self.received_acks = set()
        self.capture_thread = None
        self.capture_running = False
        self.sniff_event = None 
        self.packet_queue = queue.Queue()
        self.interface_choice = None
        self.analysis_window = None
        self.update_job = None
        self.is_window_open = False
        self.update_thread = None
        self.setup_gui()

    def setup_gui(self):
        self.root.title("PCAP Network Analyzer")
        self.root.geometry('1200x800')
        
        # Apply modern theme
        self.style = ThemedStyle(self.root)
        self.style.set_theme("arc")  # Modern, clean theme
        
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        self.create_menu()
        self.create_toolbar()
        self.create_main_interface()
        self.create_status_bar()
        
        self.status_label = ttk.Label(self.root, text='Ready')
        self.status_label.grid(row=3, column = 0, sticky="w", padx=5, pady=2)
        
    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        # File Menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label='File', menu=file_menu)
        file_menu.add_command(label="Open PCAP...", command=self.load_and_analyze_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Save As...", command=lambda: self.save_capture(filedialog.asksaveasfilename(
            defaultextension=".pkl",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        )))
        file_menu.add_separator()
        file_menu.add_command(label="Load PKL", command=lambda: self.load_capture(filedialog.askopenfilename(
            defaultextension=".pkl",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        )))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)

        # Analysis Menu
        analysis_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label='Analysis', menu=analysis_menu)
        analysis_menu.add_command(label="Traffic Patterns", command=self.analyze_traffic_patterns)
        analysis_menu.add_command(label="Security Scan", command=self.security_scan)
        
    def create_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.grid(row=0, column=0, sticky="ew", padx=5, pady=2)
        
        # Quick access buttons
        ttk.Button(toolbar, text="Open", command=self.load_and_analyze_pcap).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)
        ttk.Button(toolbar, text="Save", command=lambda: self.save_capture(filedialog.asksaveasfilename(
            defaultextension=".pkl",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        ))).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)
        ttk.Button(toolbar, text="Load", command=lambda: self.load_capture(filedialog.askopenfilename(
            defaultextension=".pkl",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        ))).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=5, fill=tk.Y)        
        ttk.Button(toolbar, text="Start Live Capture", command=self.start_live_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Stop Live Capture", command=self.stop_live_capture).pack(side=tk.LEFT, padx=2)

    def create_main_interface(self):
        main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.main_paned = main_paned

        # Upper section for packet list
        upper_frame = ttk.Frame(main_paned)
        main_paned.add(upper_frame, weight=3)
        
        self.create_interface_selection(upper_frame)
        
        # Create filter frame
        self.create_filter_frame(upper_frame)
        
        # Create packet list with enhanced columns
        self.create_packet_list(upper_frame)
        
        # Lower section with notebook for different views
        lower_frame = ttk.Frame(main_paned)
        main_paned.add(lower_frame, weight=1)
        
        self.create_details_notebook(lower_frame)

    def create_interface_selection(self, parent):
        interface_label = ttk.Label(parent, text="Select Network Interface:")
        interface_label.pack(padx=5, pady=5)

        # Dropdown for interface selection
        interfaces = scapy.get_if_list()
        self.interface_choice = ttk.Combobox(parent, values=interfaces, state="readonly")
        self.interface_choice.set(interfaces[1])  
        self.interface_choice.pack(padx=5, pady=5)

    def create_filter_frame(self, parent):
        filter_frame = ttk.LabelFrame(parent, text="Display Filter", padding=5)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Filter entry with syntax highlighting
        self.filter_entry = tk.Text(filter_frame, height=1, width=50, wrap=tk.WORD, bd = 1, font=("Consolas", 10))
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        
        apply_button = ttk.Button(filter_frame, text="Apply", command=self.apply_filter)
        apply_button.pack(side=tk.LEFT, padx=5, pady=5)
        filter_frame.pack_propagate(True)
        
    def start_live_capture(self):
        if self.capture_running:
            messagebox.showinfo("Info","Packet capture is already running")
            return
        
        interface = self.interface_choice.get()
        if not interface:
            messagebox.showwarning("Error","No interface selected")
            return
        
        self.capture_running = True
        self.sniff_event = threading.Event()
        self.capture_thread = threading.Thread(target=self.live_capture,args=(interface,),daemon=True)
        messagebox.showinfo("Info","Packet sniffing started!")
        self.packet_treeview.delete(*self.packet_treeview.get_children())
            
        for text_widget in [self.details_text, self.hex_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)
        self.clear_data()
        
        self.capture_thread.start()
        
    def live_capture(self, interface):
        try:
            # Using scapy to start sniffing live packets
            scapy.sniff(iface=interface,prn=self.process_packet, store=False, stop_filter=self.stop_sniff)
        except Exception as e:
            messagebox.showerror("Error", f"Error during packet capture: {e}")
            self.capture_running = False
        
    def process_packet(self, packet):
        self.packet_queue.put(packet)
        
    def update_gui(self):
        # This method runs periodically to update the Treeview with packets from the queue
        if not self.packet_queue.empty():
            packet = self.packet_queue.get_nowait()
            self.analyzer.capture.append(packet)
            self.add_packet_to_treeview(packet)
        
        self.root.after(1, self.update_gui)
        
    def add_packet_to_treeview(self, packet):
        # Update the GUI with the packet data
        packet_time = self.get_packet_time(packet)
        source_ip, dest_ip = self.get_packet_ips(packet)
        protocol = self.analyzer.get_packet_protocol(packet)
        length = len(packet)
        if protocol == "TCP":
            if packet[scapy.TCP].flags=="S":
                self.sent_packets.add(packet[scapy.TCP].seq)
            if packet[scapy.TCP].flags == "A":
                self.received_acks.add(packet[scapy.TCP].ack)
        
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            if any(bad_string in payload for bad_string in ["rm -rf","bash","exec","system"]):
                messagebox.showwarning("Warning!",f"Suspicious payload detected in packet number {self.total_packets+1}.")
                
        self.analyzer.protocols_used[protocol] = self.analyzer.protocols_used.get(protocol, 0) + 1
        self.analyzer.user_ips.add(source_ip)

        packet_data = (self.total_packets + 1, packet_time, source_ip, dest_ip, protocol, length)
        self.total_packets += 1

        # Insert packet data into the Treeview
        self.packet_treeview.insert('', 'end', values=packet_data)
        
    def insert_packet(self, packet_data):
        # Insert the packet into the Treeview safely
        self.packet_treeview.insert('', 'end', values=packet_data)

    def stop_sniff(self, packet):
        return self.sniff_event.is_set()  # Stops sniffing if the event is set

    def stop_live_capture(self):
        if not self.capture_running:
            messagebox.showinfo("Info", "No capture is running.")
            return

        self.sniff_event.set()  # Set the event to stop sniffing
        self.capture_running = False
        messagebox.showinfo("Info", "Packet capture has been stopped.")
        
        self.analyzer.collect_domains()
        self.UDRP()
        
        while not self.packet_queue.empty():
            self.packet_queue.get_nowait()
    
        self.root.after_cancel(self.update_gui) 
        
    def create_packet_list(self, parent):
            # Create packet list with enhanced styling
            columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length")
            self.packet_treeview = ttk.Treeview(parent, columns=columns, show="headings", height=15)
            
            # Configure columns with better formatting
            for col in columns:
                self.packet_treeview.heading(col, text=col, command=lambda col=col:self.sort_by_column(col))
                if col == "No.":
                    self.packet_treeview.column(col, width=60, anchor="center")
                elif col == "Time":
                    self.packet_treeview.column(col, width=100)
                elif col in ("Source", "Destination"):
                    self.packet_treeview.column(col, width=150)
                elif col == "Protocol":
                    self.packet_treeview.column(col, width=80, anchor="center")
                elif col == "Length":
                    self.packet_treeview.column(col, width=70, anchor="center")

            # Add scrollbars
            y_scrollbar = ttk.Scrollbar(self.packet_treeview, orient="vertical", command=self.packet_treeview.yview)
            self.packet_treeview.configure(yscrollcommand=y_scrollbar.set)
            
            # Grid layout for scrollbars
            self.packet_treeview.pack(fill=tk.BOTH, expand=True)
            y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Bind events
            self.packet_treeview.bind('<<TreeviewSelect>>', self.show_pkt_details)
            self.packet_treeview.bind('<Double-1>', self.show_packet_dialog)
            
    def sort_by_column(self, col):
        if self.sort_col == col:
            self.sort_order = not self.sort_order
        else:
            self.sort_col = col
            self.sort_order = True
        rows = [(self.packet_treeview.item(item)['values'],item) for item in self.packet_treeview.get_children()] 
        col_idx = self.packet_treeview['columns'].index(col)
        
        if col in ["Source", "Destination"]:
            rows.sort(key=lambda x:self.ip_to_tuple(x[0][col_idx]), reverse=not self.sort_order)
        else:
            rows.sort(key=lambda x:x[0][col_idx],reverse=not self.sort_order)
        
        for item in self.packet_treeview.get_children():
            self.packet_treeview.delete(item)
            
        for values, item in rows:
            self.packet_treeview.insert('','end',values=values)
        self.update_col_header(col)
        
    def ip_to_tuple(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                # IPv4: Convert to tuple (e.g., "192.168.1.1" -> (192, 168, 1, 1))
                return tuple(map(int, ip.split('.')))
            elif ip_obj.version == 6:
                # IPv6: Convert to a tuple representation
                return tuple(int(part, 16) for part in ip.split(':'))
        except ValueError:
            # If the IP address is invalid, return a tuple of zeros
            return tuple([0] * 8)
               
    def update_col_header(self, col):
        for col_name in self.packet_treeview["columns"]:
            current_text = col_name
            if current_text in ["↑", "↓"]:
                current_text = current_text.replace("↑", "").replace("↓", "")
            self.packet_treeview.heading(col_name, text=current_text)

        # Add the appropriate sorting symbol to the clicked column
        if self.sort_order:
            new_header_text = col + " ↑"  # Ascending
        else:
            new_header_text = col + " ↓"  # Descending

        self.packet_treeview.heading(col, text=new_header_text)

    def create_details_notebook(self, parent):
        self.details_notebook = ttk.Notebook(parent)
        self.details_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet Details tab
        details_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(details_frame, text="Packet Details")
        
        self.details_text = tk.Text(details_frame)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
        
        # Hex View tab
        hex_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(hex_frame, text="Hex View")
        
        self.hex_text = tk.Text(hex_frame, font=("Courier", 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        self.hex_text.config(state=tk.DISABLED)
        
        # user ips
        user_ips_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(user_ips_frame, text="User ips")
        
        self.user_ips_text = tk.Text(user_ips_frame, font=("Courier", 10))
        self.user_ips_text.pack(fill=tk.BOTH, expand=True)
        self.user_ips_text.config(state=tk.DISABLED)
        
        #domains
        domain_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(domain_frame, text="Domains")
        
        self.domain_text = tk.Text(domain_frame, font=("Courier", 10))
        self.domain_text.pack(fill=tk.BOTH, expand=True)
        self.domain_text.config(state=tk.DISABLED)
        
        #protocols
        protocol_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(protocol_frame, text="Protocols")
        
        self.protocol_text = tk.Text(protocol_frame, font=("Courier", 10))
        self.protocol_text.pack(fill=tk.BOTH, expand=True)
        self.protocol_text.config(state=tk.DISABLED)
        
        #urls
        urls_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(urls_frame, text="Urls")
        
        self.urls_text = tk.Text(urls_frame, font=("Courier", 10))
        self.urls_text.pack(fill=tk.BOTH, expand=True)
        self.urls_text.config(state=tk.DISABLED)
        
    def create_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=2, column=0, sticky="ew")
        
        #Status sections        
        self.capture_status_label = ttk.Label(status_frame, text="Load file...")
        self.capture_status_label.pack(side=tk.LEFT, padx=5)
        
    def show_packet_dialog(self, event):
        # Get the item that was clicked
        item_id = self.packet_treeview.identify('item', event.x, event.y)
        if not item_id:
            return
        item_data = self.packet_treeview.item(item_id)
        packet_num = item_data['values'][0]
        
        index = int(packet_num)
        try:
            packet_data = self.get_packet_data(index)
        except Exception as e:
            
            messagebox.showerror("Error", f"Could not retrieve packet data: {str(e)}")
            return

        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Packet Details - #{packet_data['no']}")
        dialog.geometry("800x600")
        dialog.minsize(600, 400)
        
        # Create main container with padding
        main_frame = ttk.Frame(dialog, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different views
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Decoded view tab
        decoded_frame = ttk.Frame(notebook)
        notebook.add(decoded_frame, text="Decoded")
        
        # Add scrollbars to decoded view
        decoded_scroll_y = ttk.Scrollbar(decoded_frame, orient="vertical")
        decoded_scroll_x = ttk.Scrollbar(decoded_frame, orient="horizontal")
        decoded_tree = ttk.Treeview(decoded_frame,  show="tree", yscrollcommand=decoded_scroll_y.set, xscrollcommand=decoded_scroll_x.set)
        
        decoded_scroll_y.config(command=decoded_tree.yview)
        decoded_scroll_x.config(command=decoded_tree.xview)
        
        # Grid layout for decoded view
        decoded_tree.grid(row=0, column=0, sticky="nsew")
        decoded_scroll_y.grid(row=0, column=1, sticky="ns")
        decoded_scroll_x.grid(row=1, column=0, sticky="ew")
        decoded_frame.grid_columnconfigure(0, weight=1)
        decoded_frame.grid_rowconfigure(0, weight=1)
        
        # Populate decoded tree
        self.populate_packet_tree(decoded_tree, '', packet_data['layers'])
        
        # Hex view tab
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex View")
        
        # Add scrollbars to hex view
        hex_scroll_y = ttk.Scrollbar(hex_frame, orient="vertical")
        hex_scroll_x = ttk.Scrollbar(hex_frame, orient="horizontal")
        hex_text = tk.Text(hex_frame, font=("Courier", 10), wrap=tk.WORD, yscrollcommand=hex_scroll_y.set, xscrollcommand=hex_scroll_x.set)
        
        hex_scroll_y.config(command=hex_text.yview)
        hex_scroll_x.config(command=hex_text.xview)
        
        # Grid layout for hex view
        hex_text.grid(row=0, column=0, sticky="nsew")
        hex_scroll_y.grid(row=0, column=1, sticky="ns")
        hex_scroll_x.grid(row=1, column=0, sticky="ew")
        hex_frame.grid_columnconfigure(0, weight=1)
        hex_frame.grid_rowconfigure(0, weight=1)
        
        # Insert hex dump and make read-only
        hex_text.insert('1.0', packet_data['hex_dump'])
        hex_text.config(state=tk.DISABLED)
        
        # Add a close button at the bottom
        close_button = ttk.Button(main_frame, text="Close", command=dialog.destroy)
        close_button.pack(pady=5)
        
        # Bind escape key to close dialog
        dialog.bind('<Escape>', lambda e: dialog.destroy())
        
        # Center the dialog on the screen
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
        
    def populate_packet_tree(self, tree, parent, layer_data):
        for layer_name, attributes in layer_data.items():
            layer_item = tree.insert(parent, "end", text=layer_name, open=True)

            for key, value in attributes.items():
                if isinstance(value,dict):
                    self.populate_packet_tree(tree, layer_item, {key:value})
                else:
                    field_values = f"{key} : {value}"
                    tree.insert(layer_item, "end", text=field_values)
        
    def get_packet_data(self, packet_id):
        try:
            packet_index = int(packet_id) - 1
            if packet_index < 0 or packet_index >= len(self.analyzer.capture):
                return None
            packet = self.analyzer.capture[packet_index]
            
            packet_data = {
                'no': packet_index + 1,  # 1-based packet number
                'layers': {},            # Layer information
                'hex_dump': ''          # Hexadecimal representation
            }
            
            packet_data['layers'] = self._process_packet_layers(packet)
            packet_data['hex_dump'] = self.get_hex_dump(packet)
            
            return packet_data
            
        except Exception as e:
            messagebox.showerror("Error",f"Error getting packet data: {e}")
            return None

    def _process_packet_layers(self, packet):
        layers = {}
        
        # Process each layer
        while packet:
            layer_name = packet.name
            layer_fields = {}
            for field_name, field_value in packet.fields.items():
                if isinstance(field_value, bytes):
                    field_value = field_value.hex()
                layer_fields[field_name] = str(field_value)
            
            # Add layer info to layers dict
            layers[layer_name] = layer_fields
            packet = packet.payload if hasattr(packet, 'payload') else None
            
            if hasattr(packet, 'original') and not hasattr(packet, 'name'):
                break
                
        return layers
        
    def get_hex_dump(self, packet):
        try:
            raw_data = bytes(packet)
            if isinstance(raw_data, bytes):
                hex_data = ' '.join(f"{byte:02x}" for byte in raw_data)
                return hex_data
            else:
                messagebox.showerror("Error", "Unable to extract raw bytes for this packet.\n")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Error extracting hex dump: {str(e)}\n")
        
    def analyze_traffic_patterns(self):
        if not self.analyzer.capture:
            messagebox.showwarning("Analysis", "No packets to analyze")
            return
        try:
            # Create analysis window
            self.analysis_window = tk.Toplevel(self.root)
            self.analysis_window.title("Traffic Pattern Analysis")
            self.analysis_window.geometry("1000x600")
            
            self.is_window_open = True
            # Create notebook for different analyses
            notebook = ttk.Notebook(self.analysis_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Time-based analysis
            self.create_time_analysis(notebook)
            
            # Protocol analysis
            self.create_protocol_analysis(notebook)
            
            self.create_src_ip_analysis(notebook)
            
            # Size analysis
            self.create_size_analysis(notebook)
            
            # Flow analysis
            self.create_flow_analysis(notebook)
            
            self.create_network_graph(notebook)
                        
            self.start_update_thread()

            # Bind window close event to stop automatic updates
            self.analysis_window.protocol("WM_DELETE_WINDOW", self.close_analysis_window)
        except Exception as e:
            messagebox.showerror("Error",f"An error occurred while traffic analysis: {str(e)}")
            
    def start_update_thread(self):
        if self.capture_running:
            if not hasattr(self, 'update_thread') or not self.update_thread:
                self.update_thread = threading.Thread(target=self.periodic_update, daemon=True)
                self.update_thread.start()
        else:
            self.update_analysis()
    
    def periodic_update(self):
        while self.is_window_open:
            time.sleep(5)  # Update after every 5 seconds
            self.update_analysis()
                 
    def update_analysis(self):
        # Here you can update the analysis content with the new captured packets.
        if self.analysis_window:
            # Update the data on your plots here by redrawing them
            self.update_time_analysis()  
            self.update_protocol_analysis()  
            self.update_src_ip_analysis()  
            self.update_size_analysis()  
            self.update_flow_analysis()
            self.update_network_graph()

    def close_analysis_window(self):
        # Stop the updates when the window is closed
        self.is_window_open = False
        self.update_thread = None
        self.analysis_window.destroy()
        
    def create_time_analysis(self, notebook):
        time_frame = ttk.Frame(notebook)
        notebook.add(time_frame, text="Time Analysis")
        
        # Create a figure for time analysis
        self.time_fig = Figure(figsize=(8, 5))
        self.time_canvas = FigureCanvasTkAgg(self.time_fig, time_frame)
        self.time_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for time-based plots
        self.time_ax1 = self.time_fig.add_subplot(211)
        self.time_ax2 = self.time_fig.add_subplot(212)
        
        # Initial empty plots (will be updated)
        self.time_ax1.set_xlabel('Time (seconds)')
        self.time_ax1.set_ylabel('Packets per bin')
        self.time_ax1.set_title('Packet Rate Over Time')
        self.time_ax1.grid(True)
        
        self.time_ax2.set_xlabel('Time (seconds)')
        self.time_ax2.set_ylabel('Cumulative Packets')
        self.time_ax2.set_title('Cumulative Packets Over Time')
        self.time_ax2.grid(True)
        
        self.time_fig.tight_layout()

    def create_protocol_analysis(self, notebook):
        protocol_frame = ttk.Frame(notebook)
        notebook.add(protocol_frame, text="Protocol Analysis")
        
        # Create a figure for protocol analysis
        self.protocol_fig = Figure(figsize=(9, 5))
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, protocol_frame)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for protocol analysis
        self.protocol_axes = self.protocol_fig.subplots(1, 3)
        
        # Initial empty plots (will be updated)
        for ax in self.protocol_axes:
            ax.set_title('Protocol Distribution')
            ax.axis('equal')

        self.protocol_fig.tight_layout()
        self.protocol_fig.subplots_adjust(right=0.75)

    def create_src_ip_analysis(self, notebook):
        src_ip_frame = ttk.Frame(notebook)
        notebook.add(src_ip_frame, text="Source IP Analysis")
        
        # Create a figure for source IP analysis
        self.src_ip_fig = Figure(figsize=(9, 5))
        self.src_ip_canvas = FigureCanvasTkAgg(self.src_ip_fig, src_ip_frame)
        self.src_ip_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for source IP analysis
        self.src_ip_axes = self.src_ip_fig.add_subplot(111)
        
        # Initial empty plot (will be updated)
        self.src_ip_axes.set_title('Source IP Distribution')
        self.src_ip_axes.axis('equal')
        
        self.src_ip_fig.tight_layout()
        self.src_ip_fig.subplots_adjust(right=0.75)

    def create_size_analysis(self, notebook):
        size_frame = ttk.Frame(notebook)
        notebook.add(size_frame, text="Size Analysis")
        
        # Create a figure for size analysis
        self.size_fig = Figure(figsize=(8, 5))
        self.size_canvas = FigureCanvasTkAgg(self.size_fig, size_frame)
        self.size_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for size analysis
        self.size_ax1 = self.size_fig.add_subplot(211)
        self.size_ax2 = self.size_fig.add_subplot(212)
        
        # Initial empty plots (will be updated)
        self.size_ax1.set_xlabel('Packet Size (bytes)')
        self.size_ax1.set_ylabel('Frequency')
        self.size_ax1.set_title('Packet Size Distribution')
        self.size_ax1.grid(True)
        
        self.size_ax2.axis('off')  # This will be used for the table
        self.size_fig.tight_layout()

    def create_flow_analysis(self, notebook):
        # Create a frame for flow analysis within the notebook
        flow_frame = ttk.Frame(notebook)
        notebook.add(flow_frame, text="Flow Analysis")
        
        # Create a figure for flow analysis
        self.flow_fig = Figure(figsize=(9, 5))  # Adjust figure size for better spacing
        self.flow_canvas = FigureCanvasTkAgg(self.flow_fig, flow_frame)
        self.flow_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for flow analysis
        self.flow_axes = self.flow_fig.add_subplot(111)
        
        # Initial title and labels for the graph
        self.flow_axes.set_xlabel('Total Data (KB)')
        self.flow_axes.set_title('Top 10 Flows by Data Volume')
        
        self.flow_fig.tight_layout()
        self.flow_canvas.draw()


    def create_network_graph(self, notebook):
        # Create a frame in the notebook tab for the network graph
        network_graph_frame = ttk.Frame(notebook)
        notebook.add(network_graph_frame, text="Network Graph")
        
        # Create a figure for the network graph
        self.net_graph_fig = plt.Figure(figsize=(9, 5))  # Adjust figure size for better spacing
        self.net_graph_canvas = FigureCanvasTkAgg(self.net_graph_fig, network_graph_frame)
        self.net_graph_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create axes for the network graph visualization
        self.net_graph_axes = self.net_graph_fig.add_subplot(111)
        
        # Set up the canvas interactions
        self.net_graph_canvas.mpl_connect('scroll_event', self.zoom)  # Connect zoom functionality to the scroll event
        self.net_graph_canvas.mpl_connect('button_press_event', self.on_click)  # Connect dragging functionality to mouse press event
        self.net_graph_canvas.mpl_connect('motion_notify_event', self.on_move)  # Dragging while moving the mouse
        self.net_graph_canvas.mpl_connect('button_release_event', self.on_release) 
        
        self.x_press = None
        self.y_press = None
        self.is_dragging = False
        
        # Adjust layout to prevent overlap
        self.net_graph_fig.tight_layout()
        self.net_graph_canvas.draw()

    def update_time_analysis(self):
        timestamps = [float(pkt.time) for pkt in self.analyzer.capture]
        if not timestamps:
            return
        
        start_time = min(timestamps)
        relative_times = [t - start_time for t in timestamps]
        
        # Update packet rate over time plot
        self.time_ax1.clear()  # Clear previous plot
        bin_size = max(relative_times) / 50
        self.time_ax1.hist(relative_times, bins=50, color='blue', alpha=0.7)
        self.time_ax1.set_xlabel('Time (seconds)')
        self.time_ax1.set_ylabel('Packets per bin')
        self.time_ax1.set_title('Packet Rate Over Time')
        self.time_ax1.grid(True)
        
        # Update cumulative packets over time plot
        self.time_ax2.clear()
        self.time_ax2.plot(sorted(relative_times), range(len(relative_times)), color='green')
        self.time_ax2.set_xlabel('Time (seconds)')
        self.time_ax2.set_ylabel('Cumulative Packets')
        self.time_ax2.set_title('Cumulative Packets Over Time')
        self.time_ax2.grid(True)
        
        self.time_fig.tight_layout()
        self.time_canvas.draw()

    def update_protocol_analysis(self):
        protocols = {
            'Layer 3': {},
            'Layer 4': {},
            'Layer 7': {}
        }
        
        for pkt in self.analyzer.capture:
            if 'IP' in pkt:
                l3_proto = 'IPv4'
            elif 'IPv6' in pkt:
                l3_proto = 'IPv6'
            else:
                l3_proto = 'Other'
            protocols['Layer 3'][l3_proto] = protocols['Layer 3'].get(l3_proto, 0) + 1
            
            if 'TCP' in pkt:
                l4_proto = 'TCP'
            elif 'UDP' in pkt:
                l4_proto = 'UDP'
            else:
                l4_proto = 'Other'
            protocols['Layer 4'][l4_proto] = protocols['Layer 4'].get(l4_proto, 0) + 1
            
            if 'TCP' in pkt:
                if pkt['TCP'].dport == 80 or pkt['TCP'].sport == 80:
                    l7_proto = 'HTTP'
                elif pkt['TCP'].dport == 443 or pkt['TCP'].sport == 443:
                    l7_proto = 'HTTPS'
                else:
                    l7_proto = 'Other'
            elif 'UDP' in pkt:
                if pkt['UDP'].dport == 53 or pkt['UDP'].sport == 53:
                    l7_proto = 'DNS'
                else:
                    l7_proto = 'Other'
            else:
                l7_proto = 'Other'
            protocols['Layer 7'][l7_proto] = protocols['Layer 7'].get(l7_proto, 0) + 1
        
        # Update protocol pie charts
        for i, (layer, freq) in enumerate(protocols.items()):
            labels = list(freq.keys())
            sizes = list(freq.values())
            total = sum(sizes)
            percentages = [size/total * 100 for size in sizes]
            
            self.protocol_axes[i].clear()
            patches = self.protocol_axes[i].pie(sizes, labels=None, autopct='', startangle=90)[0]
            self.protocol_axes[i].legend(handles=patches, labels=[f'{label} ({pct:.1f}%)' for label, pct in zip(labels, percentages)], loc='center left', bbox_to_anchor=(1, 0.5), fontsize=10)
            self.protocol_axes[i].axis('equal')
        
        self.protocol_fig.tight_layout()
        self.protocol_fig.subplots_adjust(right=0.75)
        self.protocol_canvas.draw()

    def update_src_ip_analysis(self):
        src_ips = dict()
        
        for packet in self.analyzer.capture:
            src_ip = None
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
            elif packet.haslayer(scapy.IPv6):
                src_ip = packet[scapy.IPv6].src
            elif packet.haslayer(scapy.ARP):
                src_ip = packet[scapy.ARP].psrc
            src_ips[src_ip] = src_ips.get(src_ip, 0) +1
            
        sorted_ips = sorted(src_ips.items(), key=lambda x:x[1], reverse=True)[:10]
        
        ips = [ip for ip, _ in sorted_ips]
        freq = [count for _, count in sorted_ips]
        total  = sum(freq)
        percentages = [fr/total * 100 for fr in freq]
        
        legend_labels = [f'{ip} ({pct:.1f}%)' for ip, pct in zip(ips, percentages)]
        
        # Update the source IP pie chart
        self.src_ip_axes.clear()
        patches = self.src_ip_axes.pie(freq, labels=None, autopct='', startangle=90)[0]
        self.src_ip_axes.legend(patches, legend_labels, title='IP distribution', loc='center left', bbox_to_anchor=(1, 0.5), fontsize=10)
        self.src_ip_axes.axis('equal')
        
        self.src_ip_fig.tight_layout()
        self.src_ip_fig.subplots_adjust(right=0.75)
        self.src_ip_canvas.draw()

    def update_size_analysis(self):
        packet_sizes = [len(pkt) for pkt in self.analyzer.capture]
        if not packet_sizes:
            return
        
        # Update packet size distribution plot
        self.size_ax1.clear()
        self.size_ax1.hist(packet_sizes, bins=50, color='purple', alpha=0.7)
        self.size_ax1.set_xlabel('Packet Size (bytes)')
        self.size_ax1.set_ylabel('Frequency')
        self.size_ax1.set_title('Packet Size Distribution')
        self.size_ax1.grid(True)
        
        # Update the statistics table
        stats_data = [
            ['Minimum Size', f"{min(packet_sizes)} bytes"],
            ['Maximum Size', f"{max(packet_sizes)} bytes"],
            ['Average Size', f"{sum(packet_sizes)/len(packet_sizes):.2f} bytes"],
            ['Total Data', f"{sum(packet_sizes)/1024:.2f} KB"]
        ]
        
        self.size_ax2.clear()
        self.size_ax2.axis('tight')
        self.size_ax2.axis('off')
        table = self.size_ax2.table(cellText=stats_data, loc='center', cellLoc='left')
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1.0, 1.5)
        
        self.size_fig.tight_layout()
        self.size_canvas.draw()

    def update_flow_analysis(self):
        # Analyze flows (unique source-destination pairs)
        flows = {}
        for pkt in self.analyzer.capture:
            if 'IP' in pkt:
                src = pkt['IP'].src
                dst = pkt['IP'].dst
            elif 'IPv6' in pkt:
                src = pkt['IPv6'].src
                dst = pkt['IPv6'].dst
            else:
                continue
                    
            flow_key = f"{src} → {dst}"
            if flow_key not in flows:
                flows[flow_key] = {
                    'packets': 0,
                    'bytes': 0,
                    'start_time': float(pkt.time),
                    'end_time': float(pkt.time)
                }
            
            flows[flow_key]['packets'] += 1
            flows[flow_key]['bytes'] += len(pkt)
            flows[flow_key]['end_time'] = max(flows[flow_key]['end_time'], float(pkt.time))
        
        # Sort flows by total bytes (descending order)
        top_flows = dict(sorted(flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10])
        
        # Create bar chart of top flows
        flow_labels = list(top_flows.keys())
        flow_bytes = [flow['bytes'] / 1024 for flow in top_flows.values()]  # Convert to KB
        
        # Clear the previous bar chart and plot new data
        self.flow_axes.clear()
        bars = self.flow_axes.barh(range(len(flow_labels)), flow_bytes, color='orange', alpha=0.7)
        self.flow_axes.set_yticks(range(len(flow_labels)))
        self.flow_axes.set_yticklabels(flow_labels)
        self.flow_axes.set_xlabel('Total Data (KB)')
        self.flow_axes.set_title('Top 10 Flows by Data Volume')
        
        # Add value labels on bars
        for i, bar in enumerate(bars):
            width = bar.get_width()
            self.flow_axes.text(width, bar.get_y() + bar.get_height() / 2, f'{width:.1f} KB\n({top_flows[flow_labels[i]]["packets"]} pkts)', ha='left', va='center', fontsize=8)
        
        # Update the layout and redraw the canvas
        self.flow_fig.tight_layout()
        self.flow_canvas.draw()

    def update_network_graph(self):
        # Create a directed graph to represent network connections
        self.G = nx.DiGraph()

        # Parse packets and add nodes and edges
        for packet in self.analyzer.capture:
            if packet.haslayer(scapy.IP):  # Ensure it's an IP packet
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                self.G.add_node(src_ip)
                self.G.add_node(dst_ip)
                self.G.add_edge(src_ip, dst_ip)

                # Add more information for TCP/UDP packets, like source/destination ports
                if packet.haslayer(scapy.TCP):
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                    self.G[src_ip][dst_ip]['ports'] = (src_port, dst_port)
                    
        self.net_graph_axes.clear()
        # Draw the graph using NetworkX's draw function
        self.pos = nx.spring_layout(self.G, seed=42)  # Positions of nodes using spring layout
        self.graph_plot = nx.draw(self.G, pos=self.pos, with_labels=True, node_size=2500, node_color="lightblue", font_size=10, ax=self.net_graph_axes)

        # Redraw the canvas to reflect updated graph
        self.net_graph_fig.tight_layout()
        self.net_graph_canvas.draw()

    def zoom(self, event):
        ax = self.net_graph_axes
        xlim, ylim = ax.get_xlim(), ax.get_ylim()
        
        # Zoom in or out based on scroll direction
        factor = 1.1 if event.button == 'down' else 0.9
        
        # Apply zooming by scaling limits
        ax.set_xlim([x * factor for x in xlim])
        ax.set_ylim([y * factor for y in ylim])

        # Redraw the canvas
        self.net_graph_canvas.draw()

    def on_click(self, event):
        if event.button == 1:  # Left click
            self.x_press = event.x
            self.y_press = event.y
            self.is_dragging = True

    def on_move(self, event):
        if self.is_dragging:
            dx = event.x - self.x_press
            dy = event.y - self.y_press
            xlim, ylim = self.net_graph_axes.get_xlim(), self.net_graph_axes.get_ylim()

            # Calculate new limits for x and y axes
            self.net_graph_axes.set_xlim([x + dx * 0.01 for x in xlim])  # Scale the dragging movement
            self.net_graph_axes.set_ylim([y + dy * 0.01 for y in ylim])  # Scale the dragging movement

            # Update previous mouse position
            self.x_press = event.x
            self.y_press = event.y

            # Redraw the canvas
            self.net_graph_canvas.draw()

    def on_release(self, event):
        if event.button == 1:  # Left click
            self.is_dragging = False  
            
    def security_scan(self):
        try:
            if not self.analyzer.capture:
                messagebox.showwarning("Security Scan", "No packets to analyze")
                return
            summary = self.analyze_attacks()
            port_scan_ips = self.port_scan_analysis()
            
            self.check_for_targets()
            if port_scan_ips or summary or self.target_domains:
                # Create security analysis window
                security_window = tk.Toplevel(self.root)
                security_window.title("Security Analysis")
                security_window.geometry("800x600")
                
                self.notebook = ttk.Notebook(security_window)
                self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                if port_scan_ips:
                    self.port_scan_notebook(self.notebook, port_scan_ips)
                    
                if summary: 
                    self.attack_notebook(self.notebook, summary)
                    
                if self.target_domains:
                    self.target_site_notebook(self.notebook)
                
                close_button = ttk.Button(security_window, text="Close", command=security_window.destroy)
                close_button.pack(pady=10) 
                
        except Exception as e:
            messagebox.showerror("Error!",f"An error occurred while security scan: {str(e)}")
            
    def port_scan_notebook(self,parent, port_scan_ips):
        port_scan_frame = ttk.Frame(parent)
        parent.add(port_scan_frame, text="Port Scan")
        
        self.port_scan_text = ScrolledText(port_scan_frame)
        self.port_scan_text.pack(fill=tk.BOTH, expand=True)
        self.port_scan_text.insert(tk.END, f"Port Scan Detection Summary: \n\n")
        for ip in port_scan_ips:
            self.port_scan_text.insert(tk.END, f"Potential port scan from source ip: {ip} \n")
        self.port_scan_text.config(state=tk.DISABLED)
        
    def attack_notebook(self, parent, summary):
        attack_frame = ttk.Frame(parent)
        parent.add(attack_frame, text="Attacks")
        
        self.attack_text = ScrolledText(attack_frame)
        self.attack_text.pack(fill=tk.BOTH, expand=True)
        
        self.attack_text.insert(tk.END, f"Attack Detection Summary: \n\n")
        for attack_type, source_ips in summary.items():
            self.attack_text.insert(tk.END, f"{attack_type}: \n")
            for ip in source_ips:
                self.attack_text.insert(tk.END, f"\t Source ip: {ip} \n")
            self.attack_text.insert(tk.END,f"\n\n")
            
        self.attack_text.config(state=tk.DISABLED)
    
    def target_site_notebook(self, parent):
        target_site_scan_frame = ttk.Frame(parent)
        parent.add(target_site_scan_frame, text="Target Sites")
        
        self.target_site_scan_text = ScrolledText(target_site_scan_frame)
        self.target_site_scan_text.pack(fill=tk.BOTH, expand=True)
        error_msg = "\n\n".join(self.target_domains)
        self.target_site_scan_text.insert(tk.END, f"Target Site Access Summary: \n\n")
        for message in error_msg:
            self.target_site_scan_text.insert(tk.END, f"{message}")
        self.target_site_scan_text.config(state=tk.DISABLED)
    
    def load_and_analyze_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"),("CAP files", "*.cap")])
        if not file_path:
            return
        self.file_path = file_path
        self.log_handler.setup_logger(self.file_path)
        self.clear_data()
        self.capture_status_label.config(text="Starting to load...")

        threading.Thread(target=self._analyze_pcap, args=(file_path,)).start() 

    def _analyze_pcap(self, file_path):
        try:
            self.capture_status_label.config(text="loading file...")   
            capture = self.analyzer.open_file(file_path) 
            if not capture:
                messagebox.showerror("Error", "Failed to open the PCAP file.")
                return
            
            self.packet_treeview.delete(*self.packet_treeview.get_children())
            
            for text_widget in [self.details_text, self.hex_text]:
                text_widget.config(state=tk.NORMAL)
                text_widget.delete(1.0, tk.END)
                text_widget.config(state=tk.DISABLED)
            
            total_packets = len(capture)
            packets_processed = 0
            total_bandwidth = 0
            batch_size = 100
            tree_items = []
            start_time = self.analyzer.capture[0].time
            end_time = self.analyzer.capture[-1].time
            total_time_taken = end_time - start_time
            
            self.analyzer.protocols_used = {}
            self.analyzer.packets_per_port = {}
            
            for i,packet in enumerate(capture):
                packets_processed += 1
                total_bandwidth += len(packet)
                
                packet_data = self._process_packet(i, packet)
                tree_items.append(packet_data)
                
                if len(tree_items) >= batch_size or packets_processed == total_packets:
                    self._batch_update_gui(tree_items, packets_processed, total_packets)
                    tree_items = []

            total_bandwidth /= 10**6
            total_time_taken = int(total_time_taken)
            throughput = total_bandwidth / total_time_taken if total_time_taken else 0
            lost_packets = self.sent_packets - self.received_acks
            loss_ratio = len(lost_packets) / len(self.sent_packets) if self.sent_packets else 0
            self.capture_status_label.config(text=f"Loaded {total_packets} packets. Total bandwidth = {total_bandwidth:.2f} Mb. Throughput = {throughput:.2f} Mbps. ")
            self.analyzer.collect_domains()
            self.UDRP()

        except Exception as e:
            messagebox.showerror("Error",f"An error occurred: {str(e)}")
            
    def _process_packet(self, i, packet):
        packet_time = self.get_packet_time(packet)
        source_ip, destination_ip = self.get_packet_ips(packet)
        protocol = self.analyzer.get_packet_protocol(packet)
        length = len(packet)
        if protocol == "TCP":
            if packet[scapy.TCP].flags=="S":
                self.sent_packets.add(packet[scapy.TCP].seq)
            if packet[scapy.TCP].flags == "A":
                self.received_acks.add(packet[scapy.TCP].ack)
        
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            if any(bad_string in payload for bad_string in ["rm -rf","bash","exec","system"]):
                messagebox.showwarning("Warning!",f"Suspicious payload detected in packet number {i+1}.")
                
        
        self.analyzer.protocols_used[protocol] = self.analyzer.protocols_used.get(protocol, 0) + 1
        self.analyzer.user_ips.add(source_ip)
        
        return (i+1, packet_time, source_ip, destination_ip, protocol, length)

    def _batch_update_gui(self, tree_items, packets_processed, total_packets):
        def update():
            for item in tree_items:
                self.packet_treeview.insert("", "end",str(item[0]), values=item)
            self.capture_status_label.config(
                text=f"Loading {packets_processed}/{total_packets} packets..."
            )
        self.capture_status_label.after(0, update)
   
    def UDRP(self):
        self.list_users()
        self.list_domains()
        self.list_protocols()
        self.list_urls()

    
    def clear_data(self):
        self.analyzer.capture.clear()
        self.analyzer.user_ips.clear()
        self.analyzer.domains_accessed.clear()
        self.analyzer.protocols_used.clear()
        self.analyzer.urls.clear()
        self.target_domains.clear()
        self.connections.clear()
    
    def port_scan_analysis(self):
        if not self.analyzer.capture:
            messagebox.showerror("Error", "No packets loaded. Please load a capture file first.")
            return None
        port_scan_ip_add = self.network_attack_detector.detect_port_scan(self.analyzer.capture)
        if port_scan_ip_add:
            return port_scan_ip_add
        else:
            messagebox.showinfo("Analysis Complete", "No port scans detected in the capture.")
            return None
        
    def analyze_attacks(self):
        if not self.analyzer.capture:
            messagebox.showerror("Error", "No packets loaded. Please load a capture file first.")
            return None
        for packet in self.analyzer.capture:
            timestamp = float(packet.time)
            attacks = self.network_attack_detector.analyze_packet_for_attacks(packet, timestamp)
            for attack_type, attack_packet in attacks:
                self.network_attack_detector.log_attack(attack_type, attack_packet, timestamp)
        summary = self.network_attack_detector.get_attack_summary()
        if summary:
            return summary
        else:
            messagebox.showinfo("Analysis Complete", "No attacks detected in the capture.")
            return None
            
    def refresh_packet_list(self):
        self.packet_treeview.delete(*self.packet_treeview.get_children())
        self.details_text.config(state=tk.NORMAL)
        self.hex_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        self.hex_text.config(state=tk.DISABLED)
        
        num_packets = 0
        for i, packet in enumerate(self.analyzer.capture):
            packet_time = self.get_packet_time(packet)
            source_ip, destination_ip = self.get_packet_ips(packet)
            protocol = self.analyzer.get_packet_protocol(packet)
            
            if protocol not in self.analyzer.protocols_used:
                self.analyzer.protocols_used[protocol] = 1
            else:
                self.analyzer.protocols_used[protocol] += 1

            length = len(packet)
            self.analyzer.user_ips.add(source_ip)
            num_packets += 1

            self.packet_treeview.insert("", "end", values=(i+1, packet_time, source_ip, destination_ip, protocol, length))
        self.capture_status_label.config(text=f"Loaded {num_packets} packets.")
        self.status_label.config(text=f"Showing {num_packets} packets.")

    @staticmethod
    def get_packet_time(packet):
        if isinstance(packet.time, (int, float)):
            return datetime.datetime.fromtimestamp(packet.time)
        elif isinstance(packet.time, datetime.datetime):
            return packet.time
        else:
            return datetime.datetime.fromtimestamp(float(packet.time))

    @staticmethod
    def get_packet_ips(packet):
        if packet.haslayer(scapy.IP):
            return packet[scapy.IP].src, packet[scapy.IP].dst
        elif packet.haslayer(scapy.IPv6):
            return packet[scapy.IPv6].src, packet[scapy.IPv6].dst
        elif packet.haslayer(scapy.ARP):
            return packet[scapy.ARP].psrc, packet[scapy.ARP].pdst
        return "N/A", "N/A"

    def show_pkt_details(self, packet_index=None):
        if not isinstance(packet_index, int):
            selected_item = self.packet_treeview.selection()
            if not selected_item:
                return
            actual_num = self.packet_treeview.item(selected_item,'values')[0]
            packet_index = actual_num
        packet_index = int(packet_index)
        if packet_index < 0 or packet_index >= len(self.analyzer.capture):
            messagebox.showerror("Error",f"Invalid packet index! Index:{packet_index}")
            return

        packet = self.analyzer.capture[packet_index-1]
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        packet_time = self.get_packet_time(packet)
        self.details_text.insert(tk.END, f"Packet {packet_index} Details:\n")
        self.details_text.insert(tk.END, f"Timestamp: {packet_time}\n")
        
        protocol = self.analyzer.get_packet_protocol(packet)
        self.details_text.insert(tk.END, f"Length: {len(packet)} bytes\n")
        
        # Add remaining packet details...
        self.add_packet_details(packet)
        self.details_text.config(state=tk.DISABLED)
        
        # Show hex dump
        self.show_hex_dump(packet)
        
    def add_packet_details(self, packet):
        # Add Ethernet details
        if packet.haslayer(scapy.Ether):
            eth_src = packet[scapy.Ether].src
            eth_dst = packet[scapy.Ether].dst
            self.details_text.insert(tk.END, f"Ethernet Src: {eth_src}\n")
            self.details_text.insert(tk.END, f"Ethernet Dst: {eth_dst}\n")
        
        # Add IP details
        source_ip, destination_ip = self.get_packet_ips(packet)
        ttl = "N/A"
        
        if packet.haslayer(scapy.IP):
            ttl = packet[scapy.IP].ttl
        elif packet.haslayer(scapy.IPv6):
            ttl = packet[scapy.IPv6].hlim
        
        host = "N/A"
        if packet.haslayer(scapy.IP):
            if packet.haslayer(HTTP):
                host = self.analyzer.analyze_http_packet(packet)
            elif packet.haslayer(TLS):
                host = self.analyzer.analyze_https_packet(packet)
        
        self.details_text.insert(tk.END, f"Source IP: {source_ip}\n")
        self.details_text.insert(tk.END, f"Destination IP: {destination_ip}\n")
        self.details_text.insert(tk.END, f"TTL: {ttl}\n")
        
        if host != "N/A":
            self.details_text.insert(tk.END, f"Host/Server name: {host}\n")
        
        # Add port and DNS details
        self.add_port_dns_details(packet)

    def add_port_dns_details(self, packet):
        if packet.haslayer(scapy.TCP):
            self.details_text.insert(tk.END, f"Source Port: {packet[scapy.TCP].sport}\n")
            self.details_text.insert(tk.END, f"Destination Port: {packet[scapy.TCP].dport}\n")
            
        elif packet.haslayer(scapy.UDP):
            self.details_text.insert(tk.END, f"Source Port: {packet[scapy.UDP].sport}\n")
            self.details_text.insert(tk.END, f"Destination Port: {packet[scapy.UDP].dport}\n")
            
        if packet.haslayer(scapy.DNS):
            dns_query = packet[scapy.DNS].qd.qname.decode()
            self.details_text.insert(tk.END, f"DNS Query Name: {dns_query}\n")

    def show_hex_dump(self, packet):
        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete(1.0, tk.END)
        
        try:
            raw_data = bytes(packet)
            if isinstance(raw_data, bytes):
                hex_data = ' '.join(f"{byte:02x}" for byte in raw_data)
                self.hex_text.insert(tk.END, f"Hex Dump:\n{hex_data}")
            else:
                self.hex_text.insert(tk.END, "Unable to extract raw bytes for this packet.\n")
        except Exception as e:
            self.hex_text.insert(tk.END, f"Error extracting hex dump: {str(e)}\n")
            
        self.hex_text.config(state=tk.DISABLED)

    def check_for_targets(self):
        for i, packet in enumerate(self.analyzer.capture):
            host = "N/A"
            src_ip = src_mac = "N/A"
            if packet.haslayer(scapy.IP):
                if packet.haslayer(HTTP):
                    host = self.analyzer.analyze_http_packet(packet)
                    src_ip = packet[scapy.IP].src
                    src_mac = packet[scapy.Ether].src
                elif packet.haslayer(TLS):
                    host = self.analyzer.analyze_https_packet(packet)
                    src_ip = packet[scapy.IP].src
                    src_mac = packet[scapy.Ether].src
            if host != "N/A":
                self.detect_site(i+1, host,src_ip, src_mac)
        if len(self.target_domains) == 0:
            messagebox.showinfo("Information","No target sites detected.")
        else:
            return

    def detect_site(self, packet_number, host_domain, source_ip, source_mac):
        if host_domain:
            for soc_med_domain in self.analyzer.SOCIAL_MEDIA_DOMAINS:
                if host_domain.endswith(soc_med_domain):
                    self.target_domains.append(f"[Social media website] <{host_domain}> accessed in packet #{packet_number} by user {source_ip} ({source_mac})")
                    return
            for ecom_domain in self.analyzer.ECOMMERCE_DOMAINS:
                if host_domain.endswith(ecom_domain):
                    self.target_domains.append(f"[E-Commerce website] <{host_domain}> accessed in packet #{packet_number} by user {source_ip} ({source_mac})")
                    return
            self.check_host_name_in_dataframe(packet_number,source_ip, source_mac, host_domain)
                    
    def check_host_name_in_dataframe(self,packet_number,source_ip, source_mac, host_domain):
        file_path = self.get_file_path("blackbook.csv")
        df = pd.read_csv(file_path, header=None, names=["domain"])
        for domain in df["domain"]:
            if host_domain.endswith(domain):
                self.target_domains.append(f"[Malicious website] <{host_domain}> accessed in packet #{packet_number} by user {source_ip} ({source_mac})")
                return
            
    def get_file_path(self,filename):
        # When running as an executable
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS  # Temporary folder where PyInstaller unpacks files
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))  # Normal script location
        
        return os.path.join(base_path, filename)
    
    def list_users(self):
        self.user_ips_text.config(state=tk.NORMAL)
        self.user_ips_text.delete(1.0, tk.END)
        if len(self.analyzer.user_ips) == 0:
            self.user_ips_text.insert(tk.END, "No users found. Try loading data.")
            return
        users = 0
        for ip in self.analyzer.user_ips:
            if ip != "N/A":
                users += 1
                self.user_ips_text.insert(tk.END, f"User {users} ip: {ip}\n")
        self.user_ips_text.config(state=tk.DISABLED)
        
    def list_domains(self):
        self.domain_text.config(state=tk.NORMAL)
        self.domain_text.delete(1.0, tk.END)
        if len(self.analyzer.domains_accessed) == 0:
            self.domain_text.insert(tk.END, "No accessed domains. Try loading data.")
            self.domain_text.config(state=tk.DISABLED)
            return
        domains = 0
        for domain in self.analyzer.domains_accessed:
            if domain != "N/A":
                domains += 1
                self.domain_text.insert(tk.END, f"Domain {domains}: {domain}\n")
        self.domain_text.config(state=tk.DISABLED)
    
    def list_urls(self):
        self.urls_text.config(state=tk.NORMAL)
        if len(self.analyzer.urls) == 0:
            self.urls_text.insert(tk.END, "No urls. Try loading data.")
            self.urls_text.config(state=tk.DISABLED)
            return
        urls = 0
        for url in self.analyzer.urls:
            if url != "N/A":
                urls += 1
                self.urls_text.insert(tk.END, f"URL {urls}: {url}\n")
        self.urls_text.config(state=tk.DISABLED)

    def list_protocols(self):
        self.protocol_text.config(state=tk.NORMAL)
        self.protocol_text.delete(1.0, tk.END)
        
        if len(self.analyzer.protocols_used) == 0:
            self.protocol_text.insert(tk.END, "No protocols found. Try loading data.")
            self.protocol_text.config(state=tk.DISABLED)
            return
        for proto, number in self.analyzer.protocols_used.items():
            self.protocol_text.insert(tk.END, f"{proto}: {number}\n")
        self.in_or_out()
        self.list_ports()
        self.protocol_text.config(state=tk.DISABLED)
        
    def list_ports(self):
        for packet in self.analyzer.capture:
            dest_port = None
            if packet.haslayer(scapy.TCP):
                dest_port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                dest_port = packet[scapy.UDP].dport
            self.analyzer.packets_per_port[dest_port] = self.analyzer.packets_per_port.get(dest_port, 0) + 1
                
        if len(self.analyzer.packets_per_port)==0:
            return 
        self.protocol_text.insert(tk.END, "\n Packets per port distribution: \n")
        for port, freq in self.analyzer.packets_per_port.items():
            if port is not None:
                self.protocol_text.insert(tk.END, f"{port}: {freq}\n")
    
    def classify_packet(self,packet):
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                sport = packet.sport
                dport = packet.dport
                flow = (src, sport, dst, dport) 
                if flow not in self.connections:
                    self.connections[flow] = "Outgoing"
                    return "Outgoing"
                else:
                    return "Incoming"
        return "Non-TCP/UDP Packet" 
    
    def in_or_out(self):
        incoming = outgoing = others = 0
        for i, packet in enumerate(self.analyzer.capture):
            direction = self.classify_packet(packet)
            if direction == "Outgoing":
                outgoing+=1
            elif direction == "Incoming":
                incoming+=1
            else:
                others+=1
        self.protocol_text.insert(tk.END,f"Incoming: {incoming}, outgoing: {outgoing}, other :{others} \n")

    def save_capture(self, filename):
        try:
            with open(filename, 'wb') as f:
                pickle.dump((self.analyzer.capture, self.analyzer.user_ips, self.analyzer.domains_accessed, self.analyzer.protocols_used, self.analyzer.urls), f)
            messagebox.showinfo("Success", "Capture, user ips, domains, protocols and urls saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save to file: {str(e)}")

    def load_capture(self, filename):
        try:
            self.clear_data()
            
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Loading Capture")
            progress_window.geometry("300x150")
            progress_window.transient(self.root)  # Set as transient to main window
            
            window_width = 300
            window_height = 150
            screen_width = progress_window.winfo_screenwidth()
            screen_height = progress_window.winfo_screenheight()
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2
            progress_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
            
            # Add loading label
            loading_label = ttk.Label(progress_window, text="Loading capture file...", padding=(20, 10))
            loading_label.pack()
            
            # Add progress bar
            progress_bar = ttk.Progressbar(
                progress_window, 
                length=200, 
                mode='determinate',
                style="Horizontal.TProgressbar"
            )
            progress_bar.pack(pady=20)
            
            # Get file size for progress calculation
            file_size = os.path.getsize(filename)
            
            def update_progress(current_position):
                progress = (current_position / file_size) * 100
                progress_bar['value'] = progress
                progress_window.update()
            
            # Load the file with progress updates
            with open(filename, 'rb') as f:
                # Read file in chunks and update progress
                chunk_size = 8192  # 8KB chunks
                data = bytearray()
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data.extend(chunk)
                    update_progress(f.tell())
                
                # Deserialize the data
                (
                    self.analyzer.capture,
                    self.analyzer.user_ips,
                    self.analyzer.domains_accessed,
                    self.analyzer.protocols_used,
                    self.analyzer.urls
                ) = pickle.loads(data)
            
            # Close progress window
            progress_window.destroy()
            
            # Update the main application
            messagebox.showinfo("Success", "Capture, user IPs, domains, protocols and urls loaded successfully.")
            self.file_path = filename
            self.log_handler.setup_logger(self.file_path)
            self.refresh_packet_list()
            self.UDRP()
            
        except Exception as e:
            # Make sure to destroy progress window if there's an error
            if 'progress_window' in locals():
                progress_window.destroy()
            messagebox.showerror("Error", f"Failed to load from file: {str(e)}")

    def apply_filter(self):
        filter_text = self.filter_entry.get(1.0, tk.END).lower().strip()
        filter_status = True
        filtered_packets = []

        if not filter_text:
            filtered_packets = self.analyzer.capture
            filter_status = False
        else:
            filtered_packets = self.filter_packets(filter_text)
        if not self.packet_treeview:
            self.create_packet_list()
        if self.analyzer.capture:
            self.update_packet_display(filtered_packets, filter_status)

    def filter_packets(self, filter_text):
        filtered_packets = []
        and_conditions = re.split(r'\s*&&\s*', filter_text)
        parsed_conditions = [re.split(r'\s*\|\|\s*', and_condition) for and_condition in and_conditions]

        for i, packet in enumerate(self.analyzer.capture):
            if self.packet_matches_conditions(packet, parsed_conditions):
                filtered_packets.append((i+1, packet))

        return filtered_packets

    def packet_matches_conditions(self, packet, parsed_conditions):
        for or_condition_group in parsed_conditions:
            if not self.matches_or_conditions(packet, or_condition_group):
                return False
        return True

    def matches_or_conditions(self, packet, or_conditions):
        for condition in or_conditions:
            condition = condition.strip()
            negate_filter = condition.startswith('!')
            if negate_filter:
                condition = condition[1:].strip()

            match_result = self.check_condition(packet, condition)
            if negate_filter:
                match_result = not match_result
            if match_result:
                return True
        return False

    def check_condition(self, packet, condition):
        if 'ip.src' in condition:
            ip_match = re.match(r'ip.src\s*==\s*(\S+)', condition)
            if ip_match and packet.haslayer(scapy.IP):
                return ip_match.group(1) in packet[scapy.IP].src
        elif 'ip.dst' in condition:
            ip_match = re.match(r'ip.dst\s*==\s*(\S+)', condition)
            if ip_match and packet.haslayer(scapy.IP):
                return ip_match.group(1) in packet[scapy.IP].dst
        elif 'ipv6.src' in condition:
            ipv6_match = re.match(r'ipv6.src\s*==\s*(\S+)', condition)
            if ipv6_match and packet.haslayer(scapy.IPv6):
                return ipv6_match.group(1) in packet[scapy.IPv6].src
        elif 'ipv6.dst' in condition:
            ipv6_match = re.match(r'ipv6.dst\s*==\s*(\S+)', condition)
            if ipv6_match and packet.haslayer(scapy.IPv6):
                return ipv6_match.group(1) in packet[scapy.IPv6].dst
        elif condition in ['tcp', 'udp', 'icmp', 'dns','arp']:
            return self.analyzer.get_packet_protocol(packet).lower() == condition
        elif 'tcp.port' in condition:
            return self.check_tcp_port(packet, condition)
        elif 'udp.port' in condition:
            return self.check_udp_port(packet, condition)
        elif 'tcp.flags.syn' in condition:
            return self.check_tcp_syn_flag(packet)
        elif 'tcp.flags.ack' in condition:
            return self.check_tcp_ack_flag(packet)
        return False

    def check_tcp_port(self, packet, condition):
        port_match = re.match(r'tcp.port\s*==\s*(\d+)', condition)
        if port_match and packet.haslayer(scapy.TCP):
            try:
                port = int(port_match.group(1))
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
                return port == sport or port == dport
            except ValueError:
                messagebox.showerror("Error",f"Invalid port number in filter: {port_match.group(1)}")
        return False

    def check_udp_port(self, packet, condition):
        port_match = re.match(r'udp.port\s*==\s*(\d+)', condition)
        if port_match and packet.haslayer(scapy.UDP):
            try:
                port = int(port_match.group(1))
                sport = packet[scapy.UDP].sport
                dport = packet[scapy.UDP].dport
                return port == sport or port == dport
            except ValueError:
                messagebox.showerror("Error",f"Invalid port number in filter: {port_match.group(1)}")
        return False
    
    def check_tcp_syn_flag(self,packet):
        if packet.haslayer(scapy.TCP):
            return packet[scapy.TCP].flags == 'S' or 'S' in packet[scapy.TCP].flags
        return False
    
    def check_tcp_ack_flag(self,packet):
        if packet.haslayer(scapy.TCP):
            return packet[scapy.TCP].flags == 'A' or 'A' in packet[scapy.TCP].flags
        return False

    def update_packet_display(self, filtered_packets, filter_status):
        self.packet_treeview.delete(*self.packet_treeview.get_children())
        if filter_status:
            if filtered_packets:
                for packet_num, packet in filtered_packets:
                    packet_time = self.get_packet_time(packet)
                    source_ip, destination_ip = self.get_packet_ips(packet)
                    protocol = self.analyzer.get_packet_protocol(packet)
                    length = len(packet)
                    self.packet_treeview.insert("", "end", values=(packet_num, packet_time, source_ip, destination_ip, protocol, length))
                self.status_label.config(text=f"Showing {len(filtered_packets)} packets.")
            else:
                messagebox.showerror("Error", "No packets matched the filter.")
        else:
            if filtered_packets:
                self.refresh_packet_list()
            else:
                messagebox.showerror("Error", "No packets to display. Try loading a file.")

    @staticmethod
    def exit_app():
        messagebox.showwarning("Warning!","Exiting application.")
        exit(0)

class LogHandler:
    def __init__(self):
        self.logger = logging.getLogger("NetworkAnalyzer")
        self.logger.setLevel(logging.INFO)
        self.log_handler = None 

    def setup_logger(self, pcap_file_path):
        # Extract the base name of the PCAP file for log naming
        filename = pcap_file_path.split("/")[-1]
        log_file_name = filename.split(".")[0] + ".log"    
        
        if os.path.exists(log_file_name):
            os.remove(log_file_name)

        # Remove any existing handlers (to avoid duplicate logging)
        if self.log_handler:
            self.logger.removeHandler(self.log_handler)

        # Create a new RotatingFileHandler for the new log file
        self.log_handler = RotatingFileHandler(
            log_file_name,
            maxBytes=10 * 1024 * 1024,  # 10 MB per file
            backupCount=3  # Keep up to 3 backup files
        )
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        self.log_handler.setFormatter(formatter)

        # Add the handler to the logger
        self.logger.addHandler(self.log_handler)

    def log_attack(self, details):
        self.logger.info(f"Attack detected: {details}")

class NetworkAttackDetector:
    def __init__(self,log_handler):
        self.known_macs = {}
        self.log_handler = log_handler
        self.failed_smb_requests = 0
        self.icmpv6_request_count = 0
        self.icmpv6_reply_count = 0
        self.ip_dict = defaultdict(lambda:defaultdict(list))
        self.distinct_port_threshold = 50 #change as per network specs
        self.scan_port_threshold = 10 #change as per network specs
        self.time_threshold = 2
        
        self.thresholds = {
            'smb': {'count': 50, 'window': 1},
            'arp': {'count': 20, 'window': 1},
            'dns': {'count': 100, 'window': 1},
            'dhcp': {'count': 50, 'window': 1},
            'icmpv6': {'count': 50, 'window': 1}
        } #change as per network specs
        
        self.icmp_attackType = {
            0 : '', 
            1 : 'High request Rate',
            2 : 'Request-Reply Mismatch',
            3 : 'Large packet size'
        }
        
        #store timestamped packet arrivals for each protocol
        self.packet_windows: Dict[str, List[float]] = {
            'smb': [], 'arp': [], 'dns': [], 'dhcp': [], 'icmpv6': []
        }
        self.attack_logs: List[Dict] = []
    
    def detect_port_scan(self,capture):
        for packet in capture:
            if packet.haslayer(scapy.IP):
                if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                    src_ip = packet[scapy.IP].src
                    dst_port = packet[scapy.IP].dport
                    timestamp = packet.time
                    self.ip_dict[src_ip][dst_port].append(timestamp)
        port_scan_ips = set()
        for src_ip, ports in self.ip_dict.items():
            distinct_ports = len(ports)
            if distinct_ports >= self.distinct_port_threshold:
                for port, timestamps in ports.items():
                    timestamps.sort()
                    filtered = []
                    for ts in timestamps:
                        filtered = [t for t in filtered if ts - t < self.time_threshold]
                        filtered.append(ts)
                        
                        if len(filtered) > self.scan_port_threshold and (filtered[-1] - filtered[0] <self.time_threshold):
                            port_scan_ips.add(src_ip)
                            break
            else:
                continue
        return port_scan_ips
    
    def analyze_packet_for_attacks(self, packet, timestamp: float) -> List[Tuple[str, Any]]:
        attacks_detected = []
        
        #check smb flooding
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 445 or packet[scapy.TCP].sport == 445):
            raw_data = bytes(packet)
            if raw_data.startswith(b"\x00\xFF") or raw_data.startswith(b"\xFF\x53"):
                #packet is smb
                if self.detect_smb_flood(packet):
                    attacks_detected.append(('SMB Flood Attack', packet))
                
        # Check ARP flooding/spoofing
        if packet.haslayer(scapy.ARP):
            if self.check_flood('arp', timestamp):
                if self.detect_arp_spoofing(packet):
                    attacks_detected.append(('ARP Spoofing Attack', packet))   
                else:
                    attacks_detected.append(('ARP Flood Attack', packet))                 

        # Check DNS flooding/amplification
        if packet.haslayer(scapy.DNS):
            if self.check_flood('dns', timestamp):
                if self.detect_dns_amplification(packet):
                    attacks_detected.append(('DNS Amplification Attack', packet))
                else:
                    attacks_detected.append(('DNS Flood Attack', packet))

        # Check DHCP flooding
        if packet.haslayer(scapy.DHCP):
            if self.detect_dhcp_flood('dhcp', packet):
                attacks_detected.append(('DHCP Flood Attack', packet))

        # Check _ICMPv6 flooding
        if packet.haslayer(scapy.IPv6):
            if packet[scapy.IPv6].nh == 58:
                index, value = self.detect_icmpv6_flood(packet)
                if value:
                    attacks_detected.append((f'ICMPv6 Flood Attack: {self.icmp_attackType[index]}', packet))
        
        return attacks_detected

    def detect_icmpv6_flood(self, packet):
        max_pkt_size = 500
        mismatch_ratio = 5
        timestamp = packet.time  
        index = 0
        value = False 
        #1. High rate of echo requests
        if packet.haslayer(ICMPv6EchoRequest):
            self.icmpv6_request_count += 1
            value = self.check_flood('icmpv6',timestamp)
            
        elif packet.haslayer(ICMPv6EchoReply):
            # Increment the ICMPv6 Echo Reply count
            self.icmpv6_reply_count += 1

        # 2. Mismatch between requests and replies (lack of replies for requests)
        if self.icmpv6_request_count > self.icmpv6_reply_count * mismatch_ratio:
            index = 2
            value = True

        # 3. Unusually large packet sizes
        if len(packet) > max_pkt_size:
            index = 3
            value = True
        
        return index,value
            
    def check_flood(self, protocol: str, timestamp: float) -> bool:
        window = self.thresholds[protocol]['window']
        threshold = self.thresholds[protocol]['count']
        
        self.packet_windows[protocol].append(timestamp)
        self.packet_windows[protocol] = [
            t for t in self.packet_windows[protocol] 
            if timestamp - t <= window
        ]
        
        return len(self.packet_windows[protocol]) >= threshold

    def detect_smb_flood(self,packet):
        raw_data=bytes(packet)
        threshold = self.thresholds['smb']['count']
        if b"NTLMSSP" in raw_data and b"STATUS_LOGON_FAILURE" in raw_data:
            self.failed_smb_requests += 1
        if self.check_flood('smb',packet.time):
            return True
        
        if self.failed_smb_requests >= threshold//2:
            return True
        return False
                  
    def detect_dhcp_flood(self, protocol, packet):
        window = self.thresholds[protocol]['window']
        threshold = self.thresholds[protocol]['count']
        
        # Check if it's a DHCP Discover packet (op=1 indicates client request)
        if packet[scapy.DHCP].options[0][1] == 1:  # DHCP Discover
            timestamp = packet.time  # Packet timestamp
            
            # Track timestamps of DHCP Discover packets
            self.packet_windows[protocol].append(timestamp)
            self.packet_windows[protocol] = [
            t for t in self.packet_windows[protocol] 
            if timestamp - t <= window
            ]            
            return len(self.packet_windows[protocol]) >= threshold
        
        return False
    
    def detect_arp_spoofing(self,packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # ARP reply
            src_mac = packet[scapy.Ether].src  # The MAC address of the device sending the ARP reply
            claimed_mac = packet[scapy.ARP].hwsrc  # The MAC address claimed by the ARP reply

            ip_address = packet[scapy.ARP].psrc  # The IP address the ARP is for
            
            if ip_address in self.known_macs:
                if self.known_macs[ip_address] != claimed_mac:
                    return True
            else:
                self.known_macs[ip_address] = claimed_mac
        return False

    def detect_dns_amplification(self, packet) -> bool:
        if packet.haslayer(scapy.UDP) and packet.haslayer(scapy.DNS):
                if packet[scapy.DNS].qr == 1:   #dns response
                    resp_size = len(packet)
                    query_count = packet[scapy.DNS].qdcount
                    
                    amp_factor = resp_size / query_count if query_count > 0 else 0
                    if amp_factor> 10 and resp_size >= 500:
                        return True
        return False

    def log_attack(self, attack_type: str, packet, timestamp: float):
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src 
            destination_ip = packet[scapy.IP].dst
            
        elif packet.haslayer(scapy.IPv6):
            source_ip = packet[scapy.IPv6].src 
            destination_ip = packet[scapy.IPv6].dst
            
        elif packet.haslayer(scapy.ARP):
            source_ip = packet[scapy.ARP].psrc
            destination_ip = packet[scapy.ARP].pdst
        else:
            source_ip = "N/A"
            destination_ip = "N/A"
        attack_info = {
            'timestamp': timestamp,
            'attack_type': attack_type,
            'source_ip': source_ip,
            'destination_ip':  destination_ip,
        }
        self.log_handler.log_attack(f"Attack detected: {attack_info}")
        self.attack_logs.append(attack_info)

    @staticmethod
    def _get_protocol(packet) -> str:
        if packet.haslayer(scapy.ARP):
            return 'ARP'
        elif packet.haslayer(scapy.DNS):
            return 'DNS'
        elif packet.haslayer(scapy.DHCP):
            return 'DHCP'
        elif packet.haslayer(_ICMPv6):
            return '_ICMPv6'
        return 'Unknown'

    def get_attack_summary(self):
        summary = {} # -> Dict[str, list]
        for log in self.attack_logs:
            attack_type = log['attack_type']
            source_ip = log['source_ip']
            if attack_type not in summary:
                summary[attack_type] = set()
            summary[attack_type].add(source_ip)
        return summary

def main():
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.after(1, app.update_gui)
    root.mainloop()

if __name__ == "__main__":
    main()
    

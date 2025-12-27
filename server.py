import socket
import threading
import time
import sqlite3
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue

# Configuration
TCP_PORT = 5000
UDP_PORT = 6000
MAX_CLIENTS = 64

# Credentials for each campus
CREDENTIALS = {
    "Islamabad": "NU-ISB-123",
    "Lahore": "NU-LHR-123",
    "Karachi": "NU-KHI-123",
    "Peshawar": "NU-PSW-123",
    "CFD": "NU-CFD-123",
    "Multan": "NU-MLT-123"
}

# Static IP mapping for campuses
CAMPUS_IPS = {
    "Islamabad": "10.0.1.11",
    "Lahore": "10.0.1.12",
    "Karachi": "10.0.1.13",
    "Peshawar": "10.0.1.14",
    "CFD": "10.0.1.15",
    "Multan": "10.0.1.16"
}

# Client storage
clients = {}  # campus_name -> {tcp_sock, udp_addr, last_heartbeat, ip, port}
clients_lock = threading.Lock()

# Database connection
db_lock = threading.Lock()

# GUI message queue
log_queue = queue.Queue()
server_gui = None


def init_database():
    """Initialize SQLite database with tables for messages"""
    conn = sqlite3.connect('campus_messages.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            from_campus TEXT NOT NULL,
            from_dept TEXT NOT NULL,
            to_campus TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    
    # Create connection log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connection_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            campus TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            event_type TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[INFO] Database initialized successfully")


def get_db_connection():
    """Get a new database connection"""
    return sqlite3.connect('campus_messages.db', check_same_thread=False)


def now_ts():
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_info(msg):
    log_msg = f"[{now_ts()}] [INFO] {msg}"
    print(log_msg)
    log_queue.put(('info', log_msg))


def log_success(msg):
    log_msg = f"[{now_ts()}] [OK] {msg}"
    print(log_msg)
    log_queue.put(('success', log_msg))


def log_warn(msg):
    log_msg = f"[{now_ts()}] [WARN] {msg}"
    print(log_msg)
    log_queue.put(('warn', log_msg))


def log_error(msg):
    log_msg = f"[{now_ts()}] [ERROR] {msg}"
    print(log_msg)
    log_queue.put(('error', log_msg))


def save_message(from_campus, dept, to_campus, message):
    """Save message to database"""
    with db_lock:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                'INSERT INTO messages (timestamp, from_campus, from_dept, to_campus, message) VALUES (?, ?, ?, ?, ?)',
                (timestamp, from_campus, dept, to_campus, message)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log_error(f"Database error: {e}")


def log_connection(campus, ip, event_type):
    """Log connection events to database"""
    with db_lock:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                'INSERT INTO connection_log (timestamp, campus, ip_address, event_type) VALUES (?, ?, ?, ?)',
                (timestamp, campus, ip, event_type)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log_error(f"Database error: {e}")


def check_credential(campus, password):
    """Verify campus credentials"""
    return CREDENTIALS.get(campus) == password


def forward_message_to(to_campus, payload):
    """Forward message to target campus via TCP"""
    with clients_lock:
        if to_campus not in clients or clients[to_campus]['tcp_sock'] is None:
            log_warn(f"Route failed: {to_campus} not connected")
            return False
        
        try:
            tcp_sock = clients[to_campus]['tcp_sock']
            tcp_sock.send((payload + "\n").encode())
            log_success(f"Routed message to {to_campus}")
            return True
        except Exception as e:
            log_error(f"Failed to forward message: {e}")
            return False


def send_broadcast_to_all(msg):
    """Send broadcast message to all connected clients"""
    count = 0
    with clients_lock:
        for campus, info in clients.items():
            # Send to all connected clients that have UDP port configured
            if info.get('udp_port') and info.get('ip') and info.get('last_heartbeat'):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    broadcast = f"BROADCAST;MSG:{msg}"
                    # Send to the client's UDP listening port, not the ephemeral source port
                    target_addr = (info['ip'], info['udp_port'])
                    sock.sendto(broadcast.encode(), target_addr)
                    sock.close()
                    count += 1
                    log_info(f"Broadcast sent to {campus} at {target_addr[0]}:{target_addr[1]}")
                except Exception as e:
                    log_error(f"Broadcast to {campus} failed: {e}")
            else:
                log_warn(f"Skipping {campus}: UDP not ready (ip={info.get('ip')}, port={info.get('udp_port')})")
    
    if count == 0:
        log_warn("No connected clients to receive broadcast")
    else:
        log_success(f"Broadcast successfully sent to {count} client(s)")
    
    return count


def handle_tcp_client(client_sock, peer_addr):
    """Handle TCP client connection"""
    peer_ip = peer_addr[0]
    campus = None
    
    try:
        # Receive authentication
        data = client_sock.recv(4096).decode().strip()
        
        if not data.startswith("AUTH;"):
            client_sock.close()
            return
        
        # Parse authentication
        parts = data.split(';')
        auth_data = {}
        for part in parts[1:]:
            if ':' in part:
                key, value = part.split(':', 1)
                auth_data[key] = value
        
        campus = auth_data.get('CAMPUS', '')
        password = auth_data.get('PASS', '')
        
        # Verify credentials
        if not campus or not check_credential(campus, password):
            client_sock.send(b"AUTH_FAIL\n")
            client_sock.close()
            log_error(f"Auth failed for connection from {peer_ip}")
            return
        
        # Enforce single connection per campus
        with clients_lock:
            if campus in clients and clients[campus].get('tcp_sock'):
                try:
                    client_sock.send(b"ALREADY_CONNECTED\n")
                except Exception:
                    pass
                existing_ip = clients[campus].get('ip', 'unknown')
                log_warn(f"Duplicate connect attempt for {campus} from {peer_ip}. Existing connection from {existing_ip} remains active.")
                client_sock.close()
                return
            # Register client
            clients[campus] = {
                'tcp_sock': client_sock,
                'udp_addr': None,
                'udp_port': None,
                'last_heartbeat': time.time(),
                'ip': peer_ip,
                'port': peer_addr[1]
            }
        
        client_sock.send(b"AUTH_OK\n")
        log_success(f"[{campus}] authenticated from {peer_ip}")
        log_connection(campus, peer_ip, "CONNECT")
        
        # Message loop
        buffer = ""
        while True:
            data = client_sock.recv(4096).decode()
            if not data:
                break
            
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                
                if not line:
                    continue
                
                if line.startswith("SEND;"):
                    # Parse message
                    parts = line.split(';')
                    msg_data = {}
                    for part in parts[1:]:
                        if ':' in part:
                            key, value = part.split(':', 1)
                            msg_data[key] = value
                    
                    from_campus = msg_data.get('FROM', '')
                    to_campus = msg_data.get('TO', '')
                    dept = msg_data.get('DEPT', '')
                    msg_text = msg_data.get('MSG', '')
                    
                    # Save to database
                    save_message(from_campus, dept, to_campus, msg_text)
                    
                    log_info(f"[MSG] {from_campus} -> {to_campus} ({dept}): {msg_text}")
                    
                    # Forward message
                    forward_payload = f"MESSAGE;FROM:{from_campus};DEPT:{dept};MSG:{msg_text}"
                    forward_message_to(to_campus, forward_payload)
                else:
                    log_warn(f"Unknown TCP payload: {line}")
    
    except Exception as e:
        log_error(f"TCP client error: {e}")
    
    finally:
        # Cleanup
        with clients_lock:
            if campus and campus in clients:
                log_warn(f"Client disconnected: {campus}")
                log_connection(campus, peer_ip, "DISCONNECT")
                del clients[campus]
        client_sock.close()


def tcp_server():
    """TCP server thread"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', TCP_PORT))
    sock.listen(MAX_CLIENTS)
    log_success(f"TCP server listening on port {TCP_PORT}")
    
    while True:
        try:
            client_sock, addr = sock.accept()
            log_info(f"New TCP connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_tcp_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            log_error(f"TCP accept error: {e}")


def udp_server():
    """UDP server thread for heartbeats"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', UDP_PORT))
    log_success(f"UDP server listening on port {UDP_PORT}")
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            message = data.decode().strip()
            
            if message.startswith("HEART;"):
                # Parse heartbeat
                parts = message.split(';')
                heart_data = {}
                for part in parts[1:]:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        heart_data[key] = value
                
                campus = heart_data.get('CAMPUS', '')
                client_port = heart_data.get('PORT', '')
                
                if campus:
                    with clients_lock:
                        if campus in clients:
                            clients[campus]['last_heartbeat'] = time.time()
                            # Update the client's IP from the heartbeat source
                            clients[campus]['ip'] = addr[0]
                            # Store the client's UDP listening port
                            if client_port:
                                try:
                                    clients[campus]['udp_port'] = int(client_port)
                                except:
                                    pass
                            log_info(f"Heartbeat from {campus} at {addr[0]}:{addr[1]}, listening on port {client_port}")
        
        except Exception as e:
            log_error(f"UDP error: {e}")


class ServerGUI:
    """GUI for server management"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Campus Messaging Server")
        self.root.geometry("1000x700")
        
        self.create_widgets()
        self.update_ui()
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Server Status Frame
        status_frame = ttk.LabelFrame(self.root, text="Server Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.status_label = ttk.Label(status_frame, text="Status: Running", foreground="green", font=("Arial", 12, "bold"))
        self.status_label.grid(row=0, column=0, sticky=tk.W, padx=10)
        
        self.clients_count_label = ttk.Label(status_frame, text="Connected Clients: 0", font=("Arial", 10))
        self.clients_count_label.grid(row=0, column=1, sticky=tk.W, padx=20)
        
        self.messages_count_label = ttk.Label(status_frame, text="Total Messages: 0", font=("Arial", 10))
        self.messages_count_label.grid(row=0, column=2, sticky=tk.W, padx=20)
        
        # Notebook for different views
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connected Clients Tab
        clients_frame = ttk.Frame(notebook)
        notebook.add(clients_frame, text="Connected Clients")
        
        # Treeview for clients
        columns = ('Campus', 'IP Address', 'Port', 'Last Heartbeat')
        self.clients_tree = ttk.Treeview(clients_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.clients_tree.heading(col, text=col)
            self.clients_tree.column(col, width=150)
        
        self.clients_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar to clients tree
        clients_scrollbar = ttk.Scrollbar(clients_frame, orient=tk.VERTICAL, command=self.clients_tree.yview)
        self.clients_tree.configure(yscrollcommand=clients_scrollbar.set)
        clients_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        clients_btn_frame = ttk.Frame(clients_frame)
        clients_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(clients_btn_frame, text="Refresh", command=self.refresh_clients).pack(side=tk.LEFT, padx=5)
        
        # Messages Tab
        messages_frame = ttk.Frame(notebook)
        notebook.add(messages_frame, text="Messages History")
        
        # Treeview for messages
        msg_columns = ('Time', 'From', 'Dept', 'To', 'Message')
        self.messages_tree = ttk.Treeview(messages_frame, columns=msg_columns, show='headings', height=15)
        
        self.messages_tree.heading('Time', text='Timestamp')
        self.messages_tree.column('Time', width=150)
        self.messages_tree.heading('From', text='From Campus')
        self.messages_tree.column('From', width=120)
        self.messages_tree.heading('Dept', text='Department')
        self.messages_tree.column('Dept', width=120)
        self.messages_tree.heading('To', text='To Campus')
        self.messages_tree.column('To', width=120)
        self.messages_tree.heading('Message', text='Message')
        self.messages_tree.column('Message', width=350)
        
        self.messages_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar to messages tree
        msg_scrollbar = ttk.Scrollbar(messages_frame, orient=tk.VERTICAL, command=self.messages_tree.yview)
        self.messages_tree.configure(yscrollcommand=msg_scrollbar.set)
        msg_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        msg_btn_frame = ttk.Frame(messages_frame)
        msg_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(msg_btn_frame, text="Show last:").pack(side=tk.LEFT, padx=5)
        self.msg_limit_var = tk.StringVar(value="50")
        ttk.Entry(msg_btn_frame, textvariable=self.msg_limit_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(msg_btn_frame, text="Load Messages", command=self.load_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(msg_btn_frame, text="Refresh", command=self.load_messages).pack(side=tk.LEFT, padx=5)
        
        # Server Log Tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Server Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for colored logging
        self.log_text.tag_config('info', foreground='black')
        self.log_text.tag_config('success', foreground='green')
        self.log_text.tag_config('warn', foreground='orange')
        self.log_text.tag_config('error', foreground='red')
        
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(log_btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # Broadcast Tab
        broadcast_frame = ttk.Frame(notebook)
        notebook.add(broadcast_frame, text="Broadcast Message")
        
        ttk.Label(broadcast_frame, text="Broadcast Message to All Campuses:", font=("Arial", 11, "bold")).pack(pady=10, padx=10, anchor=tk.W)
        
        self.broadcast_text = tk.Text(broadcast_frame, wrap=tk.WORD, height=5, width=70)
        self.broadcast_text.pack(padx=10, pady=10)
        
        broadcast_btn_frame = ttk.Frame(broadcast_frame)
        broadcast_btn_frame.pack(pady=10)
        
        ttk.Button(broadcast_btn_frame, text="Send Broadcast", command=self.send_broadcast).pack(side=tk.LEFT, padx=5)
        ttk.Button(broadcast_btn_frame, text="Clear", command=lambda: self.broadcast_text.delete('1.0', tk.END)).pack(side=tk.LEFT, padx=5)
        
        self.broadcast_status = ttk.Label(broadcast_frame, text="", foreground="green")
        self.broadcast_status.pack(pady=5)
        
        # Connection Log Tab
        conn_log_frame = ttk.Frame(notebook)
        notebook.add(conn_log_frame, text="Connection Log")
        
        conn_columns = ('Time', 'Campus', 'IP', 'Event')
        self.conn_tree = ttk.Treeview(conn_log_frame, columns=conn_columns, show='headings', height=15)
        
        self.conn_tree.heading('Time', text='Timestamp')
        self.conn_tree.column('Time', width=150)
        self.conn_tree.heading('Campus', text='Campus')
        self.conn_tree.column('Campus', width=150)
        self.conn_tree.heading('IP', text='IP Address')
        self.conn_tree.column('IP', width=150)
        self.conn_tree.heading('Event', text='Event')
        self.conn_tree.column('Event', width=150)
        
        self.conn_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        conn_scrollbar = ttk.Scrollbar(conn_log_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=conn_scrollbar.set)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        conn_btn_frame = ttk.Frame(conn_log_frame)
        conn_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(conn_btn_frame, text="Refresh", command=self.load_connection_log).pack(side=tk.LEFT, padx=5)
        
        # Load initial data
        self.refresh_clients()
        self.load_messages()
        self.load_connection_log()
    
    def refresh_clients(self):
        """Refresh connected clients list"""
        # Clear existing items
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)
        
        # Add current clients
        with clients_lock:
            for campus, info in clients.items():
                last_hb = int(time.time() - info['last_heartbeat'])
                self.clients_tree.insert('', tk.END, values=(
                    campus,
                    info['ip'],
                    info['port'],
                    f"{last_hb}s ago"
                ))
    
    def load_messages(self):
        """Load messages from database"""
        # Clear existing items
        for item in self.messages_tree.get_children():
            self.messages_tree.delete(item)
        
        try:
            limit = int(self.msg_limit_var.get())
        except:
            limit = 50
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, from_campus, from_dept, to_campus, message FROM messages ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        for row in reversed(rows):
            self.messages_tree.insert('', tk.END, values=row)
    
    def load_connection_log(self):
        """Load connection log from database"""
        # Clear existing items
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, campus, ip_address, event_type FROM connection_log ORDER BY id DESC LIMIT 100')
        rows = cursor.fetchall()
        conn.close()
        
        for row in reversed(rows):
            self.conn_tree.insert('', tk.END, values=row)
    
    def send_broadcast(self):
        """Send broadcast message"""
        msg = self.broadcast_text.get('1.0', tk.END).strip()
        
        if not msg:
            messagebox.showwarning("Warning", "Please enter a message to broadcast")
            return
        
        count = send_broadcast_to_all(msg)
        
        if count > 0:
            self.broadcast_status.config(text=f"✓ Broadcast sent to {count} campus(es)", foreground="green")
            self.broadcast_text.delete('1.0', tk.END)
            log_success(f"Broadcast sent to {count} campus(es): {msg}")
        else:
            self.broadcast_status.config(text="No clients connected to receive broadcast", foreground="red")
        
        # Clear status after 3 seconds
        self.root.after(3000, lambda: self.broadcast_status.config(text=""))
    
    def clear_log(self):
        """Clear server log"""
        self.log_text.delete('1.0', tk.END)
    
    def update_ui(self):
        """Update UI with queued log messages"""
        # Update client count
        with clients_lock:
            self.clients_count_label.config(text=f"Connected Clients: {len(clients)}")
        
        # Update message count
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM messages')
            count = cursor.fetchone()[0]
            conn.close()
            self.messages_count_label.config(text=f"Total Messages: {count}")
        except:
            pass
        
        # Process log queue
        while not log_queue.empty():
            try:
                log_type, msg = log_queue.get_nowait()
                self.log_text.insert(tk.END, msg + '\n', log_type)
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        
        # Schedule next update
        self.root.after(500, self.update_ui)
    
    def on_closing(self):
        """Handle window close"""
        if messagebox.askokcancel("Quit", "Do you want to shutdown the server?"):
            self.root.destroy()


def main():
    """Main server entry point"""
    global server_gui
    
    # Initialize database
    init_database()
    
    # Start TCP server
    threading.Thread(target=tcp_server, daemon=True).start()
    
    # Start UDP server
    threading.Thread(target=udp_server, daemon=True).start()
    
    # Give servers time to start
    time.sleep(0.5)
    
    log_info("Server started successfully")
    log_info(f"TCP Port: {TCP_PORT}")
    log_info(f"UDP Port: {UDP_PORT}")
    
    # Start GUI
    root = tk.Tk()
    server_gui = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", server_gui.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
 
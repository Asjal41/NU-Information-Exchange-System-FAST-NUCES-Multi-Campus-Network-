import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import queue

# Configuration
TCP_PORT = 5000
UDP_PORT = 6000
SERVER_IP = "127.0.0.1"

# Campus credentials
CREDENTIALS = {
    "Islamabad": "NU-ISB-123",
    "Lahore": "NU-LHR-123",
    "Karachi": "NU-KHI-123",
    "Peshawar": "NU-PSW-123",
    "CFD": "NU-CFD-123",
    "Multan": "NU-MLT-123"
}

CAMPUS_LIST = list(CREDENTIALS.keys())


class CampusClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Campus Messaging System")
        self.root.geometry("900x700")
        
        # Connection state
        self.connected = False
        self.campus = None
        self.tcp_sock = None
        self.udp_sock = None
        self.udp_port = 7000  # Will be dynamically assigned
        self.keep_running = True
        
        # Message queues
        self.inbox_queue = queue.Queue()
        self.broadcast_queue = queue.Queue()
        
        # Create GUI
        self.create_widgets()
        
        # Start UI update loop
        self.root.after(100, self.update_ui)
    
    def create_widgets(self):
        """Create GUI widgets"""
        # Login Frame
        login_frame = ttk.LabelFrame(self.root, text="Login", padding=10)
        login_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(login_frame, text="Campus:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.campus_var = tk.StringVar()
        self.campus_combo = ttk.Combobox(login_frame, textvariable=self.campus_var, 
                                         values=CAMPUS_LIST, state="readonly", width=20)
        self.campus_combo.grid(row=0, column=1, pady=5, padx=5)
        self.campus_combo.current(0)
        
        self.connect_btn = ttk.Button(login_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.grid(row=0, column=2, pady=5, padx=5)
        
        self.status_label = ttk.Label(login_frame, text="Status: Disconnected", foreground="red")
        self.status_label.grid(row=0, column=3, pady=5, padx=20)
        
        # Send Message Frame
        send_frame = ttk.LabelFrame(self.root, text="Send Message", padding=10)
        send_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(send_frame, text="To Campus:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.to_campus_var = tk.StringVar()
        self.to_campus_combo = ttk.Combobox(send_frame, textvariable=self.to_campus_var,
                                            values=CAMPUS_LIST, state="readonly", width=20)
        self.to_campus_combo.grid(row=0, column=1, pady=5, padx=5, sticky=tk.W)
        self.to_campus_combo.current(1)
        
        ttk.Label(send_frame, text="Department:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.dept_entry = ttk.Entry(send_frame, width=30)
        self.dept_entry.grid(row=1, column=1, pady=5, padx=5, sticky=tk.W)
        self.dept_entry.insert(0, "IT")
        
        ttk.Label(send_frame, text="Message:").grid(row=2, column=0, sticky=tk.NW, pady=5)
        self.message_text = tk.Text(send_frame, width=60, height=3)
        self.message_text.grid(row=2, column=1, pady=5, padx=5, sticky=tk.W)
        
        self.send_btn = ttk.Button(send_frame, text="Send Message", command=self.send_message, state=tk.DISABLED)
        self.send_btn.grid(row=3, column=1, pady=5, padx=5, sticky=tk.W)
        
        # Notebook for Inbox and Broadcasts
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Inbox Tab
        inbox_frame = ttk.Frame(notebook)
        notebook.add(inbox_frame, text="Inbox")
        
        self.inbox_text = scrolledtext.ScrolledText(inbox_frame, wrap=tk.WORD, height=20)
        self.inbox_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.inbox_text.config(state=tk.DISABLED)
        
        # Broadcasts Tab
        broadcast_frame = ttk.Frame(notebook)
        notebook.add(broadcast_frame, text="Broadcasts")
        
        self.broadcast_text = scrolledtext.ScrolledText(broadcast_frame, wrap=tk.WORD, height=20)
        self.broadcast_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.broadcast_text.config(state=tk.DISABLED)
    
    def log_info(self, msg):
        """Add log message to inbox"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.inbox_queue.put(f"[{timestamp}] [INFO] {msg}\n")
    
    def connect_to_server(self):
        """Connect to server"""
        if self.connected:
            self.disconnect_from_server()
            return
        
        self.campus = self.campus_var.get()
        if not self.campus:
            messagebox.showerror("Error", "Please select a campus")
            return
        
        password = CREDENTIALS[self.campus]
        
        try:
            # Create TCP socket
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.connect((SERVER_IP, TCP_PORT))
            
            # Send authentication
            auth_msg = f"AUTH;CAMPUS:{self.campus};PASS:{password}"
            self.tcp_sock.send(auth_msg.encode())
            
            # Wait for response
            response = self.tcp_sock.recv(1024).decode().strip()
            
            if response == "AUTH_OK":
                self.connected = True
                self.status_label.config(text=f"Status: Connected as {self.campus}", foreground="green")
                self.connect_btn.config(text="Disconnect")
                self.send_btn.config(state=tk.NORMAL)
                self.campus_combo.config(state=tk.DISABLED)
                
                self.log_info(f"Connected to server as {self.campus}")
                
                # Start threads
                self.keep_running = True
                threading.Thread(target=self.tcp_receiver, daemon=True).start()
                threading.Thread(target=self.heartbeat_loop, daemon=True).start()
                threading.Thread(target=self.udp_listener, daemon=True).start()
            else:
                messagebox.showerror("Error", f"Authentication failed: {response}")
                self.tcp_sock.close()
        
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            if self.tcp_sock:
                self.tcp_sock.close()
    
    def disconnect_from_server(self):
        """Disconnect from server"""
        self.keep_running = False
        self.connected = False
        
        if self.tcp_sock:
            self.tcp_sock.close()
        if self.udp_sock:
            self.udp_sock.close()
        
        self.status_label.config(text="Status: Disconnected", foreground="red")
        self.connect_btn.config(text="Connect")
        self.send_btn.config(state=tk.DISABLED)
        self.campus_combo.config(state="readonly")
        
        self.log_info("Disconnected from server")
    
    def send_message(self):
        """Send message to another campus"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        to_campus = self.to_campus_var.get()
        dept = self.dept_entry.get().strip()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not to_campus or not dept or not message:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            payload = f"SEND;FROM:{self.campus};TO:{to_campus};DEPT:{dept};MSG:{message}\n"
            self.tcp_sock.send(payload.encode())
            
            self.log_info(f"Sent message to {to_campus} ({dept}): {message}")
            self.message_text.delete("1.0", tk.END)
            
            messagebox.showinfo("Success", "Message sent successfully!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
    
    def tcp_receiver(self):
        """Receive TCP messages from server"""
        buffer = ""
        while self.keep_running and self.connected:
            try:
                data = self.tcp_sock.recv(4096).decode()
                if not data:
                    self.log_info("Disconnected from server")
                    self.connected = False
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    
                    if line.startswith("MESSAGE;"):
                        # Parse incoming message
                        parts = line.split(';')
                        msg_data = {}
                        for part in parts[1:]:
                            if ':' in part:
                                key, value = part.split(':', 1)
                                msg_data[key] = value
                        
                        from_campus = msg_data.get('FROM', '')
                        dept = msg_data.get('DEPT', '')
                        msg_text = msg_data.get('MSG', '')
                        
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        inbox_msg = f"[{timestamp}] From {from_campus} ({dept}): {msg_text}\n"
                        self.inbox_queue.put(inbox_msg)
            
            except Exception as e:
                if self.keep_running:
                    self.log_info(f"TCP receiver error: {e}")
                break
    
    def heartbeat_loop(self):
        """Send periodic heartbeat to server"""
        time.sleep(1)  # Wait for UDP listener to start
        
        while self.keep_running and self.connected:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                heartbeat = f"HEART;CAMPUS:{self.campus};PORT:{self.udp_port}"
                sock.sendto(heartbeat.encode(), (SERVER_IP, UDP_PORT))
                sock.close()
                time.sleep(10)
            except Exception as e:
                if self.keep_running:
                    self.log_info(f"Heartbeat error: {e}")
                break
    
    def udp_listener(self):
        """Listen for UDP broadcasts"""
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Ensure exclusive port binding (especially on Windows) so each client
            # gets a unique UDP port and broadcasts can be delivered to all.
            try:
                self.udp_sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_EXCLUSIVEADDRUSE', 0), 1)
            except Exception:
                pass
            
            # Try to bind to UDP port
            bound = False
            for port in range(self.udp_port, self.udp_port + 100):
                try:
                    self.udp_sock.bind(('0.0.0.0', port))
                    self.udp_port = port
                    self.log_info(f"UDP listener bound to port {port}")
                    bound = True
                    break
                except:
                    continue
            
            if not bound:
                self.log_info("Failed to bind UDP port")
                return
            
            while self.keep_running and self.connected:
                try:
                    data, addr = self.udp_sock.recvfrom(4096)
                    message = data.decode().strip()
                    
                    if message.startswith("BROADCAST;"):
                        # Extract broadcast message
                        if "MSG:" in message:
                            msg_text = message.split("MSG:", 1)[1]
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            broadcast_msg = f"[{timestamp}] {msg_text}\n"
                            self.broadcast_queue.put(broadcast_msg)
                
                except Exception as e:
                    if self.keep_running:
                        self.log_info(f"UDP listener error: {e}")
                    break
        
        except Exception as e:
            self.log_info(f"UDP setup error: {e}")
    
    def update_ui(self):
        """Update UI with queued messages"""
        # Process inbox messages
        while not self.inbox_queue.empty():
            try:
                msg = self.inbox_queue.get_nowait()
                self.inbox_text.config(state=tk.NORMAL)
                self.inbox_text.insert(tk.END, msg)
                self.inbox_text.see(tk.END)
                self.inbox_text.config(state=tk.DISABLED)
            except queue.Empty:
                break
        
        # Process broadcast messages
        while not self.broadcast_queue.empty():
            try:
                msg = self.broadcast_queue.get_nowait()
                self.broadcast_text.config(state=tk.NORMAL)
                self.broadcast_text.insert(tk.END, msg)
                self.broadcast_text.see(tk.END)
                self.broadcast_text.config(state=tk.DISABLED)
            except queue.Empty:
                break
        
        # Schedule next update
        self.root.after(100, self.update_ui)
    
    def on_closing(self):
        """Handle window close"""
        if self.connected:
            self.disconnect_from_server()
        self.keep_running = False
        time.sleep(0.5)
        self.root.destroy()


def main():
    """Main client entry point"""
    root = tk.Tk()
    app = CampusClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

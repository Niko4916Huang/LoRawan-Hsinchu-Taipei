# Author: 星宇 Addison，This code is only for debugging and testing purposes. DO NOT use in production.
# Date: 2026-01-05, ALL RIGHTS RESERVED.
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import os
import struct
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from Cryptodome.Util import Counter

# --- Configuration ---
DEFAULT_BAUD_RATE = 115200
RF_OFFSET = 5
RF_GARBAGE_PATTERN = b'\x5A\xA5\x5A\xA5\x5A'

# --- Packet Sizes ---
# Physical LoRa size (TP mode expects this with garbage)
LORA_TOTAL_SIZE = 255
# Effective Data size (GW mode expects this pure payload)
EFFECTIVE_DATA_SIZE = 250 

# [MODIFIED] Timeout increased to 10s for Gateway round-trip
RX_TIMEOUT = 10.0

# --- Default Keys ---
DEFAULT_DEV_EUI = "70B3D57ED005A1B2"
DEFAULT_APP_KEY = "A23C91551BF8D0478922E6047D5A3F11" 
DEFAULT_JOIN_EUI = "0000000000000000"

# --- OpCode Dictionary ---
OP_NAMES = {
    0x00: "Join-Req", 
    0x20: "LED",      
    0xE0: "Trigger",  
    0x10: "Health",   
    0x30: "Config",       
    0x40: "AMP",
    0xA0: "Reboot"
}

# --- Crypto Helpers ---
def cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()[:4]

def aes128_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes128_ctr_encrypt(key, dev_addr, dir_val, fcnt, payload):
    ctr_prefix = b'\x01' + b'\x00'*4 + bytes([dir_val]) + struct.pack('<I', dev_addr) + struct.pack('<I', fcnt) + b'\x00'
    ctr = Counter.new(8, prefix=ctr_prefix, initial_value=1)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(payload)

def derive_session_keys(app_key, join_nonce, net_id, dev_nonce):
    dev_nonce_bytes = struct.pack('<H', dev_nonce)
    data_part = join_nonce + net_id + dev_nonce_bytes
    padding = b'\x00' * 7
    nwk_s_key = aes128_encrypt(app_key, b'\x01' + data_part + padding)
    app_s_key = aes128_encrypt(app_key, b'\x02' + data_part + padding)
    return nwk_s_key, app_s_key

# --- Main UI Class ---
class TransponderCommander:
    def __init__(self, root):
        self.root = root
        self.root.title("Transponder Packet Tester)")
        
        try:
            self.root.state('zoomed') 
        except:
            self.root.attributes('-zoomed', True)
            
        self.root.geometry("1600x900")
        self.root.configure(bg="#2b2b2b")
        
        self.ser = None
        self.log_file = None
        self.is_joined = False
        self.lock = threading.Lock()
        self.stop_auto = False
        
        # Keys
        self.dev_eui = bytes.fromhex(DEFAULT_DEV_EUI)
        self.app_key = bytes.fromhex(DEFAULT_APP_KEY)
        self.join_eui = bytes.fromhex(DEFAULT_JOIN_EUI)
        
        self.nwk_s_key = b''
        self.app_s_key = b''
        self.dev_addr = 0
        self.dev_nonce = 0
        self.fcnt_up = 0
        self.fcnt_down = 0

        self.var_port = tk.StringVar()
        # Mode Selection: "TP" (Direct) or "GW" (Through Gateway)
        self.var_mode = tk.StringVar(value="GW") 
        
        self.var_freq = tk.StringVar(value="204")
        self.var_att = tk.StringVar(value="0")
        self.var_amp_val = tk.IntVar(value=1)
        self.var_led_color = tk.StringVar(value="RED")
        self.var_status_msg = tk.StringVar(value="Ready")
        
        self.setup_ui()
        self.refresh_ports()
        self.open_new_log_file()

    def get_log_filename(self):
        base_name = "Transponder_Log_"
        idx = 1
        while True:
            fname = f"{base_name}{idx:03d}.txt"
            if not os.path.exists(fname):
                return fname
            idx += 1

    def open_new_log_file(self):
        filename = self.get_log_filename()
        self.log_file = open(filename, "w", encoding="utf-8")
        self.log_file.write(f"=== Log Started: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        self.sys_log(f"Log file created: {filename}")

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=('Consolas', 11, 'bold'), padding=5)
        style.configure("Red.TButton", foreground="red")
        
        # Top Bar
        top_frame = tk.Frame(self.root, bg="#333", height=50)
        top_frame.pack(fill="x")
        
        tk.Label(top_frame, text="COM Port:", bg="#333", fg="white", font=("Arial", 12)).pack(side="left", padx=10)
        self.cmb_port = ttk.Combobox(top_frame, textvariable=self.var_port, width=12, font=("Consolas", 11))
        self.cmb_port.pack(side="left", padx=5)
        ttk.Button(top_frame, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)
        
        # Mode Switch
        tk.Label(top_frame, text="| Mode:", bg="#333", fg="white", font=("Arial", 12)).pack(side="left", padx=10)
        ttk.Radiobutton(top_frame, text="Via Gateway (Send 250)", variable=self.var_mode, value="GW").pack(side="left", padx=5)
        ttk.Radiobutton(top_frame, text="Direct UART-TP (Send 255)", variable=self.var_mode, value="TP").pack(side="left", padx=5)

        self.btn_connect = tk.Button(top_frame, text="Connect", command=self.toggle_connection, bg="#ccc", width=12, font=("Arial", 10, "bold"))
        self.btn_connect.pack(side="left", padx=15)
        self.lbl_conn_status = tk.Label(top_frame, text="Disconnected", fg="#ff5555", bg="#333", font=("Arial", 11, "bold"))
        self.lbl_conn_status.pack(side="left", padx=5)

        # Main Layout
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg="#2b2b2b")
        main_pane.pack(fill="both", expand=True, padx=5, pady=5)

        # === Left: Dashboard ===
        dash_frame = tk.LabelFrame(main_pane, text="Session Dashboard", padx=2, pady=5, width=380, font=("Arial", 11, "bold"), bg="#f0f0f0")
        main_pane.add(dash_frame)
        
        self.cv_status = tk.Canvas(dash_frame, width=320, height=50, bg="#f0f0f0", highlightthickness=0)
        self.cv_status.pack(pady=5)
        self.status_circle = self.cv_status.create_oval(15, 15, 35, 35, fill="#ccc")
        self.status_text = self.cv_status.create_text(50, 25, anchor="w", text="OFFLINE", font=("Arial", 14, "bold"), fill="#555")

        self.dash_entries = {}
        self.row_idx = 0

        def create_dash_row(label_text, key, default_val, editable=False):
            bg_col = "#ffffff" if self.row_idx % 2 == 0 else "#e8e8e8"
            f = tk.Frame(dash_frame, bg=bg_col, pady=4, padx=5)
            f.pack(fill="x")
            
            tk.Label(f, text=label_text, font=("Arial", 9, "bold"), bg=bg_col, width=14, anchor="w").pack(side="left")
            ent_bg = "#ffffff" if editable else bg_col
            ent_fg = "#000000" if editable else "#0000aa"
            ent_state = "normal" if editable else "readonly"
            ent_relief = "sunken" if editable else "flat"
            
            ent = tk.Entry(f, font=("Consolas", 10), bd=1 if editable else 0, relief=ent_relief, bg=ent_bg, fg=ent_fg)
            ent.insert(0, default_val)
            ent.config(state=ent_state)
            ent.pack(side="right", fill="x", expand=True)
            self.dash_entries[key] = ent
            self.row_idx += 1

        create_dash_row("DevEUI", "DevEUI", DEFAULT_DEV_EUI, editable=True)
        create_dash_row("AppKey", "AppKey", DEFAULT_APP_KEY, editable=True)
        create_dash_row("JoinEUI", "JoinEUI", DEFAULT_JOIN_EUI, editable=True)
        
        tk.Frame(dash_frame, height=2, bg="#888").pack(fill="x", pady=5)
        
        create_dash_row("DevAddr", "DevAddr", "Wait Join")
        create_dash_row("DevNonce (LE)", "DevNonce", "Wait Join")
        create_dash_row("NwkSKey", "NwkSKey", "-")
        create_dash_row("AppSKey", "AppSKey", "-")
        create_dash_row("FCnt UP", "FCntUp", "0")   
        create_dash_row("FCnt DOWN", "FCntDown", "0")
        
        tk.Frame(dash_frame, height=2, bg="#888").pack(fill="x", pady=5)
        
        create_dash_row("Config Freq", "Freq", "-")
        create_dash_row("Config Att", "Att", "-")

        # === Middle: Controls ===
        ctrl_frame = tk.Frame(main_pane, bg="#f0f0f0")
        main_pane.add(ctrl_frame)

        grp_otaa = tk.LabelFrame(ctrl_frame, text="1. Network Activation", padx=10, pady=5, fg="#0055aa", font=("Arial", 10, "bold"), bg="#f0f0f0")
        grp_otaa.pack(fill="x", padx=5, pady=5)
        ttk.Button(grp_otaa, text="▶ EXECUTE OTAA JOIN", command=lambda: self.run_thread(self.logic_otaa)).pack(fill="x", ipady=8)

        grp_hw = tk.LabelFrame(ctrl_frame, text="2. Hardware Control", padx=10, pady=5, font=("Arial", 10, "bold"), bg="#f0f0f0")
        grp_hw.pack(fill="x", padx=5, pady=5)
        f_led = tk.Frame(grp_hw, bg="#f0f0f0")
        f_led.pack(fill="x", pady=2)
        style.configure("TRadiobutton", background="#f0f0f0", font=("Arial", 10))
        ttk.Radiobutton(f_led, text="RED", variable=self.var_led_color, value="RED").pack(side="left", padx=5)
        ttk.Radiobutton(f_led, text="GREEN", variable=self.var_led_color, value="GREEN").pack(side="left", padx=5)
        ttk.Button(f_led, text="Set LED", command=lambda: self.run_thread(self.logic_led)).pack(side="right")
        ttk.Button(grp_hw, text="⚠ REBOOT DEVICE", command=lambda: self.run_thread(self.logic_reboot), style="Red.TButton").pack(fill="x", pady=5)

        grp_cfg = tk.LabelFrame(ctrl_frame, text="3. RF Configuration", padx=10, pady=5, font=("Arial", 10, "bold"), bg="#f0f0f0")
        grp_cfg.pack(fill="x", padx=5, pady=5)
        f_freq = tk.Frame(grp_cfg, bg="#f0f0f0")
        f_freq.pack(fill="x", pady=2)
        tk.Label(f_freq, text="MHz:", bg="#f0f0f0").pack(side="left")
        ttk.Combobox(f_freq, textvariable=self.var_freq, values=["10", "102", "204", "255", "490", "832", "925"], width=5).pack(side="left", padx=2)
        tk.Label(f_freq, text="dB:", bg="#f0f0f0").pack(side="left", padx=2)
        ttk.Combobox(f_freq, textvariable=self.var_att, values=["0", "1", "2", "4", "8", "16"], width=3).pack(side="left", padx=2)
        ttk.Button(f_freq, text="Set & Check", command=lambda: self.run_thread(self.logic_config)).pack(side="right", padx=5)

        grp_data = tk.LabelFrame(ctrl_frame, text="4. Data & Diagnostics", padx=10, pady=5, font=("Arial", 10, "bold"), bg="#f0f0f0")
        grp_data.pack(fill="x", padx=5, pady=5)
        f_hlth = tk.Frame(grp_data, bg="#f0f0f0")
        f_hlth.pack(fill="x", pady=2)
        tk.Label(f_hlth, text="Health:", bg="#f0f0f0").pack(side="left")
        ttk.Button(f_hlth, text="Send Req", command=lambda: self.run_thread(self.logic_health)).pack(side="right", fill="x", expand=True, padx=5)
        f_amp = tk.Frame(grp_data, bg="#f0f0f0")
        f_amp.pack(fill="x", pady=5)
        tk.Label(f_amp, text="AMP Idx:", bg="#f0f0f0").pack(side="left")
        tk.Spinbox(f_amp, from_=1, to=9, textvariable=self.var_amp_val, width=3).pack(side="left", padx=5)
        ttk.Button(f_amp, text="Send AMP", command=lambda: self.run_thread(self.logic_amp)).pack(side="right", fill="x", expand=True, padx=5)

        grp_auto = tk.LabelFrame(ctrl_frame, text="5. Auto Sequence", padx=10, pady=5, fg="green", font=("Arial", 10, "bold"), bg="#f0f0f0")
        grp_auto.pack(fill="both", expand=True, padx=5, pady=5)
        f_auto_ctrl = tk.Frame(grp_auto, bg="#f0f0f0")
        f_auto_ctrl.pack(fill="x")
        ttk.Button(f_auto_ctrl, text="▶ RUN AUTO TEST", command=lambda: self.run_thread(self.run_auto_sequence)).pack(side="left", fill="x", expand=True)
        ttk.Button(f_auto_ctrl, text="⏹ STOP", command=self.stop_automation).pack(side="left", padx=5)
        self.lst_steps = tk.Listbox(grp_auto, height=8, bg="#f0fff0", selectmode="single", font=("Consolas", 10))
        self.lst_steps.pack(fill="both", expand=True, pady=5)
        
        self.auto_steps = [
            ("OTAA Join", self.logic_otaa),
            ("Health Check", self.logic_health),
            ("Config RF (204, 8)", lambda: self.logic_config_val(204, 8)),
            ("LED RED", lambda: self.logic_led_val("RED")),
            ("LED GREEN", lambda: self.logic_led_val("GREEN")),
            ("AMP Test (Idx 1)", lambda: self.logic_amp_val(1)),
            ("Reboot", self.logic_reboot)
        ]
        for name, _ in self.auto_steps:
            self.lst_steps.insert("end", f" [ ] {name}")

        # === Right: Visual Log ===
        log_frame = tk.LabelFrame(main_pane, text="Protocol Visualization", font=("Arial", 10, "bold"), bg="#1e1e1e", fg="#00ff00")
        main_pane.add(log_frame)
        self.txt_log = scrolledtext.ScrolledText(log_frame, state="disabled", font=("Consolas", 10), bg="#1e1e1e", fg="#cccccc")
        self.txt_log.pack(fill="both", expand=True)
        
        self.txt_log.tag_config("tx_hdr", foreground="#000000", background="#00ffff", font=("Consolas", 10, "bold")) 
        self.txt_log.tag_config("tx_border", foreground="#00ffff")
        self.txt_log.tag_config("rx_hdr", foreground="#000000", background="#00ff00", font=("Consolas", 10, "bold")) 
        self.txt_log.tag_config("rx_border", foreground="#00ff00")
        self.txt_log.tag_config("sys", foreground="#ffff55") 
        self.txt_log.tag_config("err", foreground="#ffffff", background="#aa0000") 
        self.txt_log.tag_config("val", foreground="#ffffff", font=("Consolas", 10, "bold")) 
        self.txt_log.tag_config("dim", foreground="#666666") 
        self.txt_log.tag_config("ascii", foreground="#ffaa00") 

        status_frame = tk.Frame(self.root, relief="sunken", bd=1, bg="#222")
        status_frame.pack(fill="x", side="bottom")
        tk.Label(status_frame, text="Status: ", bg="#222", fg="#888").pack(side="left")
        tk.Label(status_frame, textvariable=self.var_status_msg, bg="#222", fg="#00ff00", font=("Arial", 10, "bold")).pack(side="left")

    # --- INPUT HELPERS ---
    def clean_hex(self, val_str, expected_len):
        s = val_str.strip().upper().replace(" ", "").replace("0X", "").replace(":", "")
        try:
            b = bytes.fromhex(s)
            if len(b) != expected_len:
                raise ValueError(f"Length mismatch: {len(b)} bytes (expected {expected_len})")
            return b
        except Exception as e:
            raise ValueError(f"Invalid Hex: {e}")

    def sync_keys_from_ui(self):
        try:
            self.dev_eui = self.clean_hex(self.dash_entries["DevEUI"].get(), 8)
            self.app_key = self.clean_hex(self.dash_entries["AppKey"].get(), 16)
            self.join_eui = self.clean_hex(self.dash_entries["JoinEUI"].get(), 8)
            
            if self.log_file:
                self.log_file.write(f"[INFO] Keys Sync OK.\n")
            return True
        except Exception as e:
            messagebox.showerror("Key Config Error", str(e))
            return False

    # --- LOGGING SYSTEM ---
    def pretty_log_packet(self, direction, raw_bytes, decrypted_payload=None):
        self.file_deep_log(direction, raw_bytes, decrypted_payload)

        length = len(raw_bytes)
        mode = self.var_mode.get()
        
        # Determine effective data for display
        if mode == "TP":
            # TP Mode: Raw 255 bytes, first 5 are garbage
            if length > RF_OFFSET:
                effective_bytes = raw_bytes[RF_OFFSET:]
                garbage_bytes = raw_bytes[:RF_OFFSET]
            else:
                effective_bytes = raw_bytes
                garbage_bytes = b''
        else:
            # GW Mode: Raw 250 bytes, all are data
            effective_bytes = raw_bytes
            garbage_bytes = b''

        mhdr = effective_bytes[0] if len(effective_bytes) > 0 else 0x00
        pkt_type = "Unknown"
        op_name = ""
        
        if mhdr in [0x40, 0x60, 0x80, 0xA0] and decrypted_payload:
            op1 = decrypted_payload[0]
            op_name = f": {OP_NAMES.get(op1, 'Data')}"
        elif mhdr == 0x20:
             pkt_type = "JOIN-ACC"
        elif mhdr in OP_NAMES:
            op_name = f": {OP_NAMES[mhdr]}"

        if mhdr == 0xE0: pkt_type = "TRIGGER"
        elif mhdr == 0x00: pkt_type = "JOIN-REQ"
        elif mhdr == 0x20: pkt_type = "JOIN-ACC"
        elif mhdr & 0x40: pkt_type = "UPLINK"   
        elif mhdr & 0x60: pkt_type = "DOWNLINK" 
        
        title = f" {direction} ({mode}) | {pkt_type}{op_name} (Len {length}) "
        
        tag_hdr = "tx_hdr" if direction == "TX" else "rx_hdr"
        tag_bdr = "tx_border" if direction == "TX" else "rx_border"
        
        self.write_gui_log(f"┌{'─'*80}┐\n", tag_bdr)
        self.write_gui_log(f"│{title.center(80)}│\n", tag_hdr)
        self.write_gui_log(f"├{'─'*80}┤\n", tag_bdr)
        
        # Display Garbage if TP mode
        if mode == "TP" and len(garbage_bytes) > 0:
            gb_hex = " ".join([f"{b:02X}" for b in garbage_bytes])
            self.write_gui_log(f"│ OFFSET: {gb_hex:<47}{' '*23}│\n", "dim")

        # Display Effective Data
        for i in range(0, len(effective_bytes), 16):
            chunk = effective_bytes[i:i+16]
            hex_chunk = " ".join([f"{b:02X}" for b in chunk])
            self.write_gui_log(f"│ DATA  : {hex_chunk:<47}{' '*23}│\n", "val")
            
        self.write_gui_log(f"├{'─'*80}┤\n", tag_bdr)
        
        def row(key, val, extra=""):
            self.write_gui_log(f"│ {key:<10}: ", tag_bdr)
            self.write_gui_log(f"{val:<25}", "val")
            self.write_gui_log(f"{extra:<42}│\n", "dim")

        if mhdr == 0xE0: 
            row("Type", "Trigger")
            if len(effective_bytes) >= 9: 
                deui_rev = effective_bytes[1:9]
                deui_norm = deui_rev[::-1]
                row("DevEUI", deui_norm.hex().upper(), "(Sent LSB)")

        elif mhdr == 0x00: 
            row("Type", "Join-Request")
            row("JoinEUI", effective_bytes[1:9].hex().upper(), "(LSB)")
            row("DevEUI", effective_bytes[9:17].hex().upper(), "(LSB)")
            nonce = effective_bytes[17:19]
            val = struct.unpack('<H', nonce)[0]
            row("DevNonce", f"{nonce.hex().upper()}", f"-> {val} (LE)")
            row("MIC", effective_bytes[19:23].hex().upper())

        elif mhdr == 0x20:
             row("Type", "Join-Accept")
             row("Payload", "(Encrypted)")

        elif mhdr in [0x40, 0x60, 0x80, 0xA0]: 
            row("MHDR", f"{mhdr:02X}")
            fcnt = effective_bytes[6:8]
            fcnt_val = struct.unpack('<H', fcnt)[0]
            row("FCnt", f"{fcnt.hex().upper()}", f"-> {fcnt_val}")
            
            if decrypted_payload:
                self.write_gui_log(f"│{'='*80}│\n", tag_bdr)
                op1 = decrypted_payload[0]
                length_byte = decrypted_payload[2]
                op_str = OP_NAMES.get(op1, "Unknown")
                
                row("OpCode", f"{op1:02X} {decrypted_payload[1]:02X}", f"-> {op_str}")
                row("Length", f"{length_byte:02X}", f"-> {length_byte}")
                
                p_data = decrypted_payload[3:]
                if len(p_data) > 0:
                    row("Payload", f"({len(p_data)} bytes)")
                    for i in range(0, len(p_data), 16):
                        chunk = p_data[i:i+16]
                        chunk_hex = " ".join([f"{b:02X}" for b in chunk])
                        self.write_gui_log(f"│{' '*12} {chunk_hex:<65}│\n", "val")

                try:
                    txt = decrypted_payload.decode('ascii')
                    if all(32 <= ord(c) < 127 for c in txt):
                         self.write_gui_log(f"│ ASCII     : ", tag_bdr)
                         self.write_gui_log(f'"{txt}"'.ljust(67), "ascii")
                         self.write_gui_log(f"│\n", "dim")
                except: pass

        self.write_gui_log(f"└{'─'*80}┘\n\n", tag_bdr)

    def file_deep_log(self, direction, raw_bytes, decrypted_payload=None):
        if not self.log_file: return
        ts = time.strftime("[%H:%M:%S] ")
        self.log_file.write(f"{ts} {direction} Packet ({len(raw_bytes)} Bytes) ===================\n")
        self.log_file.write(f"RAW (Full): {raw_bytes.hex().upper()}\n")
        
        mode = self.var_mode.get()
        if mode == "TP" and len(raw_bytes) > RF_OFFSET:
            effective = raw_bytes[RF_OFFSET:]
        else:
            effective = raw_bytes

        if len(effective) > 0:
            mhdr = effective[0]
            self.log_file.write(f"EFFECTIVE:  {effective.hex().upper()}\n")
            
            if mhdr == 0x00:
                self.log_file.write(f"   [Type]     Join-Request\n")
            elif mhdr in [0x40, 0x60]:
                if len(effective) >= 8:
                    fcnt = struct.unpack('<H', effective[6:8])[0]
                    self.log_file.write(f"   [FCnt]     {fcnt}\n")
                if decrypted_payload:
                    self.log_file.write(f"   [Decrypted] {decrypted_payload.hex().upper()}\n")
        
        self.log_file.write("\n")
        self.log_file.flush()

    def write_gui_log(self, text, tag=None):
        def _u():
            self.txt_log.config(state="normal")
            self.txt_log.insert("end", text, tag)
            self.txt_log.see("end")
            self.txt_log.config(state="disabled")
        self.root.after(0, _u)

    def sys_log(self, msg, is_err=False):
        ts = time.strftime("[%H:%M:%S] ")
        tag = "err" if is_err else "sys"
        self.write_gui_log(f"{ts}{msg}\n", tag)
        if self.log_file: 
            self.log_file.write(f"{ts} [SYS] {msg}\n")
            self.log_file.flush()

    # --- Core Logic ---
    def send_packet(self, effective_data):
        """
        [FIX] Handles Packet Forming based on Mode
        TP Mode: Add Garbage + Pad to 255
        GW Mode: Pad to 250 (GW adds garbage)
        """
        with self.lock:
            mode = self.var_mode.get()
            
            if mode == "TP":
                # Mode 1: Direct to TP (Simulate GW behavior)
                # Add Garbage
                pkt = RF_GARBAGE_PATTERN + effective_data
                # Pad to 255
                if len(pkt) < LORA_TOTAL_SIZE:
                    pkt += b'\x00' * (LORA_TOTAL_SIZE - len(pkt))
                elif len(pkt) > LORA_TOTAL_SIZE:
                    pkt = pkt[:LORA_TOTAL_SIZE]
            else:
                # Mode 2: To Gateway
                # Just Data
                pkt = effective_data
                # Pad to 250
                if len(pkt) < EFFECTIVE_DATA_SIZE:
                    pkt += b'\x00' * (EFFECTIVE_DATA_SIZE - len(pkt))
                elif len(pkt) > EFFECTIVE_DATA_SIZE:
                    pkt = pkt[:EFFECTIVE_DATA_SIZE]
            
            self.ser.write(pkt)
            self.pretty_log_packet("TX", pkt) 

    def wait_rx_packet(self, timeout=RX_TIMEOUT):
        """
        Reads packet based on Mode.
        TP Mode: 255 Bytes
        GW Mode: 250 Bytes
        """
        start = time.time()
        buffer = b''
        
        mode = self.var_mode.get()
        target_len = LORA_TOTAL_SIZE if mode == "TP" else EFFECTIVE_DATA_SIZE
        
        while (time.time() - start) < timeout:
            if self.ser.in_waiting > 0:
                chunk = self.ser.read(self.ser.in_waiting)
                buffer += chunk
                if len(buffer) >= target_len:
                    return buffer[:target_len]
            time.sleep(0.01)
        return None

    def logic_otaa(self):
        if not self.sync_keys_from_ui(): return False
        self.sys_log(f"--- Starting OTAA Join ({self.var_mode.get()} Mode) ---")
        
        with self.lock:
            self.ser.reset_input_buffer()

        self.set_join_status(False)
        self.update_dash("DevNonce", "Wait Join")
        self.update_dash("FCntUp", 0)
        self.update_dash("FCntDown", 0)
        
        reversed_deui = self.dev_eui[::-1]
        
        # send_packet handles offset/padding based on mode
        self.send_packet(b'\xE0' + reversed_deui)
        
        with self.lock: pkt = self.wait_rx_packet()
        
        if not pkt:
            self.set_status("Join-Req Timeout", True)
            return False
            
        # Determine effective packet based on mode
        if self.var_mode.get() == "TP":
            effective_pkt = pkt[RF_OFFSET:]
        else:
            effective_pkt = pkt
        
        if effective_pkt[0] != 0x00:
            self.set_status(f"Unexpected MHDR: {effective_pkt[0]:02X}", True)
            self.pretty_log_packet("RX", pkt)
            return False
        
        self.pretty_log_packet("RX", pkt)
        
        rx_join_eui = effective_pkt[1:9]
        if rx_join_eui != self.join_eui[::-1]:
             self.sys_log(f"Warn: JoinEUI LSB/MSB mismatch possible.", True)

        dev_nonce = effective_pkt[17:19]
        rx_mic = effective_pkt[19:23]
        
        nonce_val = struct.unpack('<H', dev_nonce)[0]
        self.update_dash("DevNonce", f"0x{dev_nonce.hex().upper()} = {nonce_val}")

        calc_mic = cmac(self.app_key, effective_pkt[0:19])
        if calc_mic != rx_mic:
            self.set_status("Join MIC Fail", True)
            return False

        # Generate Join Accept
        app_nonce = os.urandom(3)
        net_id = b'\x00\x00\x01'
        dev_addr_int = 0x12345678
        dev_addr_bytes = struct.pack('<I', dev_addr_int)
        
        content = b'\x20' + app_nonce + net_id + dev_addr_bytes + b'\x00\x00'
        mic = cmac(self.app_key, content)
        cipher = AES.new(self.app_key, AES.MODE_ECB)
        enc_payload = cipher.decrypt(app_nonce + net_id + dev_addr_bytes + b'\x00\x00' + mic)
        
        self.send_packet(b'\x20' + enc_payload) 
        
        self.nwk_s_key, self.app_s_key = derive_session_keys(self.app_key, app_nonce, net_id, nonce_val)
        self.dev_addr = dev_addr_int
        self.dev_nonce = nonce_val
        self.fcnt_down = 0
        self.fcnt_up = 0
        
        self.update_dash("DevAddr", f"0x{dev_addr_int:08X}")
        self.update_dash("NwkSKey", self.nwk_s_key.hex().upper())
        self.update_dash("AppSKey", self.app_s_key.hex().upper())
        
        self.set_join_status(True)
        self.set_status("Joined OK")
        return True

    def _send_downlink_common(self, op1, op2, data, expect_op1, expect_op2):
        if not self.is_joined:
            self.set_status("Not Joined!", True)
            return None

        with self.lock:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()

        # ★★★ [修正 1] Payload 長度必須是 227 (原本寫成 237 導致總長變 250) ★★★
        # 240(總長) - 9(Header) - 4(MIC) = 227
        PAYLOAD_SIZE = 227 
        
        pay = bytearray(PAYLOAD_SIZE) 
        pay[0]=op1; pay[1]=op2; pay[2]=len(data)
        if data: pay[3:3+len(data)] = data
        
        # 加密這 227 bytes
        enc_payload = aes128_ctr_encrypt(self.app_s_key, self.dev_addr, 1, self.fcnt_down, bytes(pay))
        
        # 建構 Header (9 Bytes)
        mhdr = b'\x60'
        fhdr = struct.pack('<I', self.dev_addr) + b'\x00' + struct.pack('<H', self.fcnt_down & 0xFFFF)
        fport = b'\x0A' # Port 10
        
        # ★★★ [修正 2] 組合 MIC 計算內容 (長度應為 236) ★★★
        msg_no_mic = mhdr + fhdr + fport + enc_payload
        
        # Debug: 這裡印出來確認長度是否為 236
        # print(f"MIC Calc Len: {len(msg_no_mic)}") 
        
        # 計算 MIC
        b0 = b'\x49' + b'\x00'*4 + b'\x01' + struct.pack('<I', self.dev_addr) + struct.pack('<I', self.fcnt_down) + b'\x00' + bytes([len(msg_no_mic)])
        mic = cmac(self.nwk_s_key, b0 + msg_no_mic)
        
        # 最終封包 (240 Bytes)
        effective_pkt = msg_no_mic + mic
        
        # Log 顯示
        if self.var_mode.get() == "TP": log_pkt = RF_GARBAGE_PATTERN + effective_pkt 
        else: log_pkt = effective_pkt 

        # send_packet 會自動在後面補 0 到 250，但有效資料只有前 240
        self.send_packet(effective_pkt)
        self.pretty_log_packet("TX", log_pkt, bytes([op1, op2, len(data)]) + data)

        self.fcnt_down += 1
        self.update_dash("FCntDown", self.fcnt_down)
        
        if expect_op1 is None: return True
        
        pkt = self.wait_rx_packet()
        if not pkt:
            self.set_status("Resp Timeout", True)
            return None
            
        if self.var_mode.get() == "TP": effective_pkt = pkt[RF_OFFSET:]
        else: effective_pkt = pkt
        
        if effective_pkt[0] != 0x40:
            self.set_status(f"Unexpected Header {effective_pkt[0]:02X}", True)
            self.pretty_log_packet("RX", pkt)
            return None
        
        rx_dev_addr = struct.unpack('<I', effective_pkt[1:5])[0]
        rx_fcnt = struct.unpack('<H', effective_pkt[6:8])[0]
        self.fcnt_up = rx_fcnt + 1
        self.update_dash("FCntUp", self.fcnt_up)
        
        # RX 解密時也要用 227 長度 (Index 9 ~ 236)
        # 確保解密長度與加密長度一致
        plain = aes128_ctr_encrypt(self.app_s_key, rx_dev_addr, 0, rx_fcnt, effective_pkt[9:236])
        
        self.pretty_log_packet("RX", pkt, plain)
        
        if plain[0] == expect_op1 and plain[1] == expect_op2:
            return plain[3 : 3+plain[2]]
        else:
            self.set_status(f"OpCode Mismatch", True)
            return None

    def logic_led(self):
        return self.logic_led_val(self.var_led_color.get())
    
    def logic_led_val(self, color_str):
        val = b'\x01' if color_str=="RED" else b'\x02'
        res = self._send_downlink_common(0x20, 0x01, val, None, None)
        if res: self.set_status(f"LED {color_str} Sent")
        return res

    def logic_reboot(self):
        res = self._send_downlink_common(0xA0, 0xA0, b'', None, None)
        self.set_join_status(False)
        self.set_status("Reboot Sent")
        self.sys_log("Wait 2.5s for Reboot...")
        time.sleep(2.5) 
        return res

    def logic_config(self):
        try:
            f = int(float(self.var_freq.get()) * 10)
            a = int(float(self.var_att.get()) * 10)
            return self.logic_config_val(f/10, a/10)
        except: return False

    def logic_config_val(self, freq_float, att_float):
        f = int(freq_float * 10)
        a = int(att_float * 10)
        data = f"{f:04d},{a:03d}".encode('ascii')
        
        resp = self._send_downlink_common(0x30, 0x01, data, 0x30, 0x02)
        if resp:
            try:
                txt = resp.decode('ascii')
                parts = txt.split(',')
                f_val = float(parts[0])/10
                a_val = float(parts[1])/10
                self.update_dash("Freq", f"{f_val} MHz")
                self.update_dash("Att", f"{a_val} dB")
                self.root.after(0, lambda: self.var_freq.set(str(int(f_val)) if f_val.is_integer() else str(f_val)))
                self.root.after(0, lambda: self.var_att.set(str(int(a_val)) if a_val.is_integer() else str(a_val)))
                self.set_status("Config Synced")
                return True
            except: 
                self.set_status("Config Parse Err", True)
                return False
        return False

    def logic_health(self):
        resp = self._send_downlink_common(0x10, 0x11, b'', 0x10, 0x12)
        if resp:
            try:
                txt = resp[0:13].decode('ascii')
                parts = txt.split(',')
                f_val = float(parts[0])/10
                a_val = float(parts[1])/10
                self.update_dash("Freq", f"{f_val} MHz")
                self.update_dash("Att", f"{a_val} dB")
                self.set_status(f"Health: Ver {parts[2]}")
                return True
            except: 
                self.set_status("Health Parse Err", True)
                return False
        return False

    def logic_amp(self):
        return self.logic_amp_val(self.var_amp_val.get())

    def logic_amp_val(self, idx):
        if idx < 1 or idx > 9: return False
        resp = self._send_downlink_common(0x40, 0x01, bytes([idx]), 0x40, 0x02)
        if resp:
            self.set_status(f"AMP {idx} OK")
            return True
        return False

    # --- Automation Sequence ---
    def stop_automation(self):
        self.stop_auto = True
        self.set_status("Stopping Auto Test...")

    def run_auto_sequence(self):
        if not (self.ser and self.ser.is_open):
            messagebox.showerror("Error", "Connect port first")
            return

        self.stop_auto = False
        self.set_status("Starting Auto Sequence...")
        
        for i in range(self.lst_steps.size()):
            self.lst_steps.itemconfig(i, {'bg': 'white'})
            text = self.lst_steps.get(i)
            self.lst_steps.delete(i)
            self.lst_steps.insert(i, text.replace("[V]", "[ ]").replace("[X]", "[ ]"))

        for i, (name, func) in enumerate(self.auto_steps):
            if self.stop_auto: break
            self.lst_steps.itemconfig(i, {'bg': '#ffffcc'}) 
            self.lst_steps.see(i)
            
            result = func()
            
            self.lst_steps.delete(i)
            mark = "[V]" if result else "[X]"
            color = "#ccffcc" if result else "#ffcccc"
            self.lst_steps.insert(i, f" {mark} {name}")
            self.lst_steps.itemconfig(i, {'bg': color})
            
            if not result and name == "OTAA Join":
                break
            time.sleep(1.0)
        self.set_status("Auto Test Finished.")

    # --- UI Helpers ---
    def update_dash(self, key, value):
        def _u():
            if key in self.dash_entries:
                entry = self.dash_entries[key]
                prev_state = entry.cget('state')
                entry.config(state="normal")
                entry.delete(0, "end")
                entry.insert(0, str(value))
                if prev_state == "readonly":
                    entry.config(state="readonly")
        self.root.after(0, _u)

    def set_status(self, msg, is_error=False):
        self.var_status_msg.set(msg)
        if is_error: self.sys_log(f"ERROR: {msg}", True)

    def set_join_status(self, joined):
        self.is_joined = joined
        def _u():
            if joined:
                self.cv_status.itemconfig(self.status_circle, fill="#00FF00")
                self.cv_status.itemconfig(self.status_text, text="JOINED", fill="#008000")
            else:
                self.cv_status.itemconfig(self.status_circle, fill="#ccc")
                self.cv_status.itemconfig(self.status_text, text="OFFLINE", fill="#555")
        self.root.after(0, _u)

    # --- Serial ---
    def refresh_ports(self):
        ports = serial.tools.list_ports.comports()
        self.cmb_port['values'] = [p.device for p in ports]
        if ports: self.cmb_port.current(0)

    def toggle_connection(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.btn_connect.config(text="Connect", bg="#ccc", fg="black")
            self.lbl_conn_status.config(text="Disconnected", fg="#ff5555")
        else:
            try:
                self.ser = serial.Serial(self.var_port.get(), DEFAULT_BAUD_RATE, timeout=0.1)
                self.btn_connect.config(text="Disconnect", bg="#55ff55", fg="black")
                self.lbl_conn_status.config(text="Connected", fg="#55ff55")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def run_thread(self, target):
        if not (self.ser and self.ser.is_open):
            messagebox.showerror("Error", "Port not opened!")
            return
        threading.Thread(target=target, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = TransponderCommander(root)
    root.mainloop()

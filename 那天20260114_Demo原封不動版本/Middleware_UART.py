import serial
import socket
import threading
import json
import time
import base64
import random
import sys
from datetime import datetime

# ==========================================
# 設定區 (Configuration)
# ==========================================
# [Serial Settings] Gateway 連接的 COM Port
# Windows: "COM3", "COM4" ...
# Linux/Mac: "/dev/ttyUSB0", "/dev/tty.usbserial..."
SERIAL_PORT = "COM6"  
BAUD_RATE = 115200

# [ChirpStack Settings]
SERVER_IP = "61.216.140.11"
SERVER_PORT = 1710

# [Gateway Identity]
GATEWAY_EUI_HEX = "aabbccddeeff0001"  # MSB

# [Protocol]
PAYLOAD_SIZE = 250  # 固定傳輸長度
RF_FREQ = 915.2

# [Console Colors]
C_RESET = "\033[0m"
C_GREEN = "\033[92m"
C_BLUE = "\033[94m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"

class SerialLoraBridge:
    def __init__(self):
        self.running = True
        self.sock = None
        self.ser = None
        
        # Stats
        self.cnt_up = 0
        self.cnt_down = 0
        self.cnt_hb = 0

        self.setup_connections()

    def log(self, msg, color=C_RESET):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {msg}{C_RESET}")

    def setup_connections(self):
        # 1. Setup UDP (ChirpStack)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            self.log(f"UDP Socket Ready (Target: {SERVER_IP}:{SERVER_PORT})", C_CYAN)
        except Exception as e:
            self.log(f"UDP Error: {e}", C_RED)
            sys.exit(1)

        # 2. Setup Serial (Gateway)
        try:
            self.ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
            self.log(f"Serial Port Opened: {SERIAL_PORT} @ {BAUD_RATE}", C_CYAN)
        except Exception as e:
            self.log(f"Serial Error: Check Port! ({e})", C_RED)
            sys.exit(1)

    def start(self):
        self.log("=== LoRaWAN UART BRIDGE STARTED ===", C_GREEN)
        self.log("Type 'trigger <DevEUI>' to send OTAA Trigger", C_YELLOW)
        self.log("Type 'status' for stats, 'exit' to quit", C_YELLOW)

        # 啟動多執行緒
        t_serial = threading.Thread(target=self.thread_serial_rx, daemon=True)
        t_udp = threading.Thread(target=self.thread_udp_rx, daemon=True)
        t_hb = threading.Thread(target=self.thread_heartbeat, daemon=True)
        
        t_serial.start()
        t_udp.start()
        t_hb.start()

        # 主執行緒進入輸入迴圈
        self.input_loop()

    # -----------------------------------------------------------
    # Thread 1: Serial RX (Gateway -> PC -> ChirpStack)
    # -----------------------------------------------------------
    def thread_serial_rx(self):
        buffer = b''
        while self.running:
            try:
                if self.ser.in_waiting > 0:
                    chunk = self.ser.read(self.ser.in_waiting)
                    buffer += chunk
                    
                    # 檢查是否收到完整的 250 bytes
                    while len(buffer) >= PAYLOAD_SIZE:
                        packet = buffer[:PAYLOAD_SIZE]
                        buffer = buffer[PAYLOAD_SIZE:]
                        self.handle_gateway_uplink(packet)
            except Exception as e:
                self.log(f"Serial RX Error: {e}", C_RED)
                time.sleep(1)
            time.sleep(0.01)

    def handle_gateway_uplink(self, raw_data):
        # raw_data is 250 bytes
        # 這裡假設 UART 模式下 Gateway 傳送的是純 Payload，沒有那 20 bytes UDP Header
        # 如果你的 C Code 在 Mode 1 還是加了 Header，這裡要切掉
        
        # 假設前 250 Bytes 都是有效/填充數據
        # 我們需要切掉後面的 Padding (0x00) 才能正確計算 MIC
        # 但如果是固定長度協議，通常只取有效部分
        
        # 簡單判定：看第一個 Byte (MHDR)
        mhdr = raw_data[0]
        valid_payload = b''
        
        pkt_type = "UNKNOWN"
        if mhdr == 0x00: # Join Request
            pkt_type = "JOIN_REQ"
            valid_payload = raw_data[:23] # 標準 JoinReq 23 bytes
        elif (mhdr & 0xE0) in [0x40, 0x80]: # Data Up
            pkt_type = "DATA_UP"
            # 這裡簡單處理：去除尾部 0x00，或者如果你有設定有效長度
            # 這裡示範去除尾部連續 0x00
            valid_payload = raw_data.rstrip(b'\x00')
            if len(valid_payload) == 0: valid_payload = raw_data # 防錯
        else:
            # 可能是雜訊或 Keepalive
            return 

        self.log(f"RX SERIAL: {pkt_type} ({len(valid_payload)} bytes)", C_BLUE)
        self.send_udp_to_chirpstack(valid_payload)

    def send_udp_to_chirpstack(self, payload):
        try:
            b64_data = base64.b64encode(payload).decode('utf-8')
            
            # 偽造 RF 參數
            rxpk = {
                "rxpk": [{
                    "tmst": int(time.time() * 1000000) & 0xFFFFFFFF,
                    "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "chan": 0, "rfch": 0, "freq": RF_FREQ,
                    "stat": 1, "modu": "LORA", "datr": "SF7BW125", 
                    "codr": "4/5", "rssi": -60, "lsnr": 9.0,
                    "size": len(payload), "data": b64_data
                }]
            }
            
            json_str = json.dumps(rxpk)
            
            # Semtech UDP Header
            token = random.getrandbits(16).to_bytes(2, 'little')
            eui_bytes = bytes.fromhex(GATEWAY_EUI_HEX)
            # 0x00 = PUSH_DATA
            packet = b'\x02' + token + b'\x00' + eui_bytes + json_str.encode('utf-8')
            
            self.sock.sendto(packet, (SERVER_IP, SERVER_PORT))
            self.cnt_up += 1
            self.log(f"TX UDP: Forwarded to CS", C_GREEN)
            
        except Exception as e:
            self.log(f"UDP TX Error: {e}", C_RED)

    # -----------------------------------------------------------
    # Thread 2: UDP RX (ChirpStack -> PC -> Gateway)
    # -----------------------------------------------------------
    def thread_udp_rx(self):
        while self.running:
            try:
                import select
                ready = select.select([self.sock], [], [], 1.0)
                if ready[0]:
                    data, addr = self.sock.recvfrom(4096)
                    self.handle_chirpstack_downlink(data)
            except:
                pass

    def handle_chirpstack_downlink(self, data):
        if len(data) < 4: return
        msg_type = data[3]
        
        if msg_type == 0x01: # PUSH_ACK
            pass # self.log("Heartbeat ACK", C_GREEN)
        elif msg_type == 0x04: # PULL_ACK
            pass
        elif msg_type == 0x03: # PULL_RESP (Downlink Data)
            self.cnt_down += 1
            try:
                json_data = data[4:]
                obj = json.loads(json_data)
                txpk = obj.get("txpk", {})
                raw_data = base64.b64decode(txpk.get("data", ""))
                
                if raw_data:
                    self.log(f"RX UDP: Downlink received ({len(raw_data)} bytes)", C_BLUE)
                    self.send_serial_to_gateway(raw_data)
                    
                    # Send TX_ACK back to CS
                    token = random.getrandbits(16).to_bytes(2, 'little')
                    ack = b'\x02' + token + b'\x05' + bytes.fromhex(GATEWAY_EUI_HEX)
                    self.sock.sendto(ack, (SERVER_IP, SERVER_PORT))

            except Exception as e:
                self.log(f"Downlink Parse Error: {e}", C_RED)

    def send_serial_to_gateway(self, payload):
        # 填充到 250 Bytes
        target_len = PAYLOAD_SIZE
        if len(payload) < target_len:
            padding = b'\x00' * (target_len - len(payload))
            final_packet = payload + padding
        else:
            final_packet = payload[:target_len]
            
        try:
            self.ser.write(final_packet)
            self.log(f"TX SERIAL: Sent {len(final_packet)} bytes to Gateway", C_GREEN)
        except Exception as e:
            self.log(f"Serial Write Error: {e}", C_RED)

    # -----------------------------------------------------------
    # Thread 3: Heartbeat
    # -----------------------------------------------------------
    def thread_heartbeat(self):
        while self.running:
            try:
                eui_bytes = bytes.fromhex(GATEWAY_EUI_HEX)
                
                # 1. Stat Packet
                stat = {
                    "stat": {
                        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S GMT"),
                        "lati": 24.0, "long": 121.0, "alti": 10,
                        "rxnb": self.cnt_up, "dwnb": self.cnt_down,
                        "ackr": 100.0, "pfw": "2", "upnb": self.cnt_up
                    }
                }
                token = random.getrandbits(16).to_bytes(2, 'little')
                pkt = b'\x02' + token + b'\x00' + eui_bytes + json.dumps(stat).encode('utf-8')
                self.sock.sendto(pkt, (SERVER_IP, SERVER_PORT))
                
                # 2. Keepalive Packet
                token2 = random.getrandbits(16).to_bytes(2, 'little')
                pkt2 = b'\x02' + token2 + b'\x02' + eui_bytes
                self.sock.sendto(pkt2, (SERVER_IP, SERVER_PORT))
                
                self.cnt_hb += 1
                # self.log("Heartbeat Sent", C_GREEN)
                
            except Exception as e:
                self.log(f"HB Error: {e}", C_RED)
                
            time.sleep(10)

    # -----------------------------------------------------------
    # Main Input Loop
    # -----------------------------------------------------------
    def input_loop(self):
        while self.running:
            try:
                cmd = input() # Blocking Input
                parts = cmd.split()
                if not parts: continue
                
                op = parts[0].lower()
                
                if op == "exit":
                    self.running = False
                    if self.sock: self.sock.close()
                    if self.ser: self.ser.close()
                    print("Bye.")
                    break
                    
                elif op == "status":
                    print(f"{C_YELLOW}--- STATUS ---")
                    print(f"UP: {self.cnt_up} | DOWN: {self.cnt_down} | HB: {self.cnt_hb}")
                    print(f"Serial: {self.ser.is_open}")
                    print(f"----------------{C_RESET}")
                    
                elif op == "trigger":
                    if len(parts) < 2:
                        self.log("Usage: trigger <DevEUI_HEX>", C_RED)
                    else:
                        dev_eui_str = parts[1]
                        try:
                            dev_eui = bytes.fromhex(dev_eui_str)
                            # Construct Trigger Packet: 0xE0 + DevEUI
                            payload = b'\xE0' + dev_eui
                            self.log(f"Triggering OTAA for {dev_eui_str}...", C_YELLOW)
                            self.send_serial_to_gateway(payload)
                        except:
                            self.log("Invalid Hex format", C_RED)
                            
                else:
                    print("Unknown command.")
                    
            except Exception as e:
                print(f"Input Error: {e}")

if __name__ == "__main__":
    app = SerialLoraBridge()
    app.start()

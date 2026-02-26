import serial
import socket
import threading
import json
import time
import base64
import random
import sys
import struct
from datetime import datetime

# pip install pycryptodome
#from Crypto.Cipher import AES
#from Crypto.Hash import CMAC
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from Cryptodome.Util import Counter

# ==========================================
# 設定區 (Configuration)
# ==========================================
# [Serial Settings] Gateway 連接的 COM Port
# Windows: "COM3", "COM4" ...
# Linux/Mac: "/dev/ttyUSB0", "/dev/tty.usbserial..."
# SERIAL_PORT = "COM6" 
SERIAL_PORT = "/dev/ttyUSB0"  
BAUD_RATE = 115200

# [ChirpStack Settings]
SERVER_IP = "192.168.50.206"
SERVER_PORT = 1700

# [Gateway Identity]
GATEWAY_EUI_HEX = "aabbccddeeff0001"  # MSB

# [Protocol]
PAYLOAD_SIZE = 250  # 固定傳輸長度
RF_FREQ = 903.9		#// w:915.2   903.9	

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

        # === debug: trigger counter ===
        self.cnt_trigger_sent = 0		#// w:

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
        self.log("Type 'help' for available commands", C_YELLOW)
        self.log("Type 'trigger <DevEUI>' to send OTAA Trigger", C_YELLOW)
        self.log("Type 'poll <DevAddr> <NwkSKey> <AppSKey> [FCntDown]' to send Health_Req", C_YELLOW)
        self.log("Type 'amp <AmpNo> <DevAddr> <NwkSKey> <AppSKey> [FCntDown]' to send amp_command", C_YELLOW)
        
        

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
            # valid_payload = raw_data.rstrip(b'\x00')
            # if len(valid_payload) == 0: valid_payload = raw_data # 防錯

            # 以上星宇原代碼, 改以下
            valid_payload = raw_data[:230]		#// w:
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

            # === debug: try 立即發送 PULL_DATA, downlink channel active ===
            token2 = random.getrandbits(16).to_bytes(2, 'little')		#// w:
            pull_data = b'\x02' + token2 + b'\x02' + eui_bytes		#// w:
            self.sock.sendto(pull_data, (SERVER_IP, SERVER_PORT))		#// w:
            self.log(f"[DBG-MW] PULL_DATA sent after uplink", C_CYAN)		#// w:
            
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
        
        # === debug: check UDP packet type ===		#// w:
        msg_type_names = {0x01: "PUSH_ACK", 0x03: "PULL_RESP", 0x04: "PULL_ACK"}
        type_name = msg_type_names.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")
        self.log(f"[DBG-MW] UDP RX: {type_name}, len={len(data)}", C_CYAN)
        # === debug ===		#// w:

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
            # === debug ===		// w:
            ts_ms = int(time.time() * 1000) % 100000
            self.log(f"[DBG-MW] ser.write() called @{ts_ms}ms, len={len(final_packet)}", C_CYAN)
            # === debug ===		// w:
            self.ser.write(final_packet)
            self.log(f"TX SERIAL: Sent {len(final_packet)} bytes to Gateway", C_GREEN)
        except Exception as e:
            self.log(f"Serial Write Error: {e}", C_RED)

    # -----------------------------------------------------------
    # LoRaWAN crypto functions by Wilson
    # -----------------------------------------------------------
    def lorawan_encrypt(self, payload, key, dev_addr_le, fcnt, direction):
        """
        LoRaWAN AES-CTR 加密/解密
        direction: 0=Uplink, 1=Downlink
        dev_addr_le: 4 bytes, Little-Endian
        """
        result = bytearray(len(payload))
        num_blocks = (len(payload) + 15) // 16
        
        for i in range(num_blocks):
            # A block: 0x01 | 4x0x00 | Dir | DevAddr(LE) | FCnt(4B LE) | 0x00 | block_idx
            a_block = bytes([0x01, 0x00, 0x00, 0x00, 0x00, direction])
            a_block += dev_addr_le
            a_block += struct.pack('<I', fcnt)
            a_block += bytes([0x00, i + 1])
            
            cipher = AES.new(key, AES.MODE_ECB)
            s_block = cipher.encrypt(a_block)
            
            for j in range(16):
                idx = i * 16 + j
                if idx < len(payload):
                    result[idx] = payload[idx] ^ s_block[j]
        
        return bytes(result)

    def lorawan_calc_mic(self, msg, key, dev_addr_le, fcnt, direction):
        """
        計算 LoRaWAN MIC (CMAC 的前 4 bytes)
        direction: 0=Uplink, 1=Downlink
        dev_addr_le: 4 bytes, little-endian
        """
        # B0 block
        b0 = bytes([0x49, 0x00, 0x00, 0x00, 0x00, direction])
        b0 += dev_addr_le
        b0 += struct.pack('<I', fcnt)
        b0 += bytes([0x00, len(msg)])
        
        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(b0 + msg)
        return cmac.digest()[:4]

    def send_downlink_command(self, dev_addr_hex, nwk_skey_hex, app_skey_hex, opcode1, opcode2, ampno, fcnt_down=0):
        """
        Downlink Data 封包
        dev_addr_hex: "01A2B3C4" (big-endian 輸入, 會轉成 little-endian)
        nwk_skey_hex: 32 hex chars (16 bytes)
        app_skey_hex: 32 hex chars (16 bytes)
        opcode1, opcode2: ICD OpCode bytes
        fcnt_down: Downlink Frame Counter
        """
        try:
            # parse
            dev_addr_be = bytes.fromhex(dev_addr_hex)  # big-endian 輸入
            dev_addr_le = dev_addr_be[::-1]            # 轉成 little-endian
            nwk_skey = bytes.fromhex(nwk_skey_hex)
            app_skey = bytes.fromhex(app_skey_hex)
            
            # # === 1. FRMPayload (ICD format) ===
            # # [OpCode1][OpCode2][PayloadLen][Payload][Padding]
            # # 總長度: 227 bytes (240 - 1 MHDR - 7 FHDR - 1 FPort - 4 MIC = 227)
            # frm_payload_plain = bytes([opcode1, opcode2, 0x00])  # OpCode + Length=0
            # frm_payload_plain += b'\x00' * (227 - 3)             # Padding to 227 bytes

            # === 1. FRMPayload (ICD 格式) ===
            # [OpCode1][OpCode2][PayloadLen][Payload][Padding]
            # 總長度: 217 bytes (230 - 1 MHDR - 7 FHDR - 1 FPort - 4 MIC = 217)
            
            # Amp_Req: 0x40 0x01 0x01 0x03 … 0x00
            #       1: 0x40 0x01 長度0x01
            #       2: (0x03) 要求回覆3號指令
            
            if opcode1 == 0x40:
                 frm_payload_plain = bytes([opcode1, opcode2, 0x01, ampno])  # OpCode + Length=1 + 要求回覆3號指令 0x03
                 frm_payload_plain += b'\x00' * (217 - 4)                   # Padding to 217 bytes
            else:
                 frm_payload_plain = bytes([opcode1, opcode2, 0x00])  # OpCode + Length=0
                 frm_payload_plain += b'\x00' * (217 - 3)             # Padding to 217 bytes
            
            # === 2. 加密 FRMPayload (使用 AppSKey, direction=1) ===
            frm_payload_enc = self.lorawan_encrypt(
                frm_payload_plain, app_skey, dev_addr_le, fcnt_down, direction=1
            )
            
            # === 3. FHDR ===
            # DevAddr(4B LE) + FCtrl(1B) + FCnt(2B LE) = 7 bytes
            fctrl = 0x00  # No ACK, No ADR, No FOpts
            fcnt_bytes = struct.pack('<H', fcnt_down & 0xFFFF)
            fhdr = dev_addr_le + bytes([fctrl]) + fcnt_bytes
            
            # === 4. MACPayload ===
            fport = 10  # ICD 指定使用 FPort 10
            mac_payload = fhdr + bytes([fport]) + frm_payload_enc
            
            # === 5. PHYPayload (不含 MIC) ===
            mhdr = 0x60  # Unconfirmed Data Down
            phy_no_mic = bytes([mhdr]) + mac_payload
            
            # === 6. calac MIC (使用 NwkSKey, direction=1) ===
            mic = self.lorawan_calc_mic(phy_no_mic, nwk_skey, dev_addr_le, fcnt_down, direction=1)
            
            # === 7. PHYPayload ===
            phy_payload = phy_no_mic + mic
            
            # === 8. test log ===
            self.log(f"[POLL] DevAddr={dev_addr_hex}, FCnt={fcnt_down}", C_YELLOW)
            self.log(f"[POLL] OpCode={opcode1:02X} {opcode2:02X}", C_YELLOW)
            self.log(f"[POLL] PHYPayload ({len(phy_payload)} bytes)", C_CYAN)
            self.log(f"[POLL] Header: {phy_payload[:13].hex()}", C_CYAN)
            
            # === 9. send to gateway ===
            self.send_serial_to_gateway(phy_payload)
            return True
            
        except Exception as e:
            self.log(f"[POLL] Error: {e}", C_RED)
            import traceback
            traceback.print_exc()
            return False
        
		#// w: end of adding ==============
		
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
                
            time.sleep(10)		#// w:

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

                            # === debug ===		// w:
                            self.cnt_trigger_sent += 1
                            ts_ms = int(time.time() * 1000) % 100000
                            self.log(f"[DBG-MW] ======== TRIGGER #{self.cnt_trigger_sent} ========", C_YELLOW)
                            self.log(f"[DBG-MW] Timestamp: {ts_ms}ms", C_YELLOW)
                            self.log(f"[DBG-MW] DevEUI input: {dev_eui_str}", C_YELLOW)
                            self.log(f"[DBG-MW] Payload[0:9] hex: {payload[0:9].hex()}", C_YELLOW)
                            # === debug ===		// w:

                            self.log(f"Triggering OTAA for {dev_eui_str}...", C_YELLOW)
                            self.send_serial_to_gateway(payload)
                        except:
                            self.log("Invalid Hex format", C_RED)

		#// w: =====
                elif op == "poll":
                    # cmd: poll <DevAddr> <NwkSKey> <AppSKey> [FCntDown]
                    # exp: poll 01A2B3C4 AABBCCDD...16bytes... 11223344...16bytes... 0
                    if len(parts) < 4:
                        self.log("Usage: poll <DevAddr> <NwkSKey> <AppSKey> [FCntDown]", C_RED)
                        self.log("  DevAddr: 4 bytes hex (e.g., 01A2B3C4)", C_YELLOW)
                        self.log("  NwkSKey: 16 bytes hex (32 chars)", C_YELLOW)
                        self.log("  AppSKey: 16 bytes hex (32 chars)", C_YELLOW)
                        self.log("  FCntDown: optional, default=0", C_YELLOW)
                    else:
                        dev_addr = parts[1]
                        nwk_skey = parts[2]
                        app_skey = parts[3]
                        fcnt = int(parts[4]) if len(parts) > 4 else 0
                        
                        # send Health_Req (OpCode 0x10 0x01)
                        self.send_downlink_command(dev_addr, nwk_skey, app_skey, 0x10, 0x11, 0x03, fcnt)  # 0x01還是0x11??

                elif op == "amp":
                    # cmd: amp <AmpNo> <DevAddr> <NwkSKey> <AppSKey> [FCntDown]
                    # exp: amp 03 01A2B3C4 AABBCCDD...16bytes... 11223344...16bytes... 0
                    if len(parts) < 5:
                        self.log("Usage: amp <AmpNo> <DevAddr> <NwkSKey> <AppSKey> [FCntDown]", C_RED)
                        self.log("  AmpNo: 1 bytes hex (e.g., 03)", C_YELLOW)
                        self.log("  DevAddr: 4 bytes hex (e.g., 01A2B3C4)", C_YELLOW)
                        self.log("  NwkSKey: 16 bytes hex (32 chars)", C_YELLOW)
                        self.log("  AppSKey: 16 bytes hex (32 chars)", C_YELLOW)
                        self.log("  FCntDown: optional, default=0", C_YELLOW)
                    else:
                        amp_no = int(parts[1], 16)
                        dev_addr = parts[2]
                        nwk_skey = parts[3]
                        app_skey = parts[4]
                        fcnt = int(parts[5]) if len(parts) > 4 else 0
                        
                        # send Amp_Req (OpCode 0x40 0x01)
                        self.send_downlink_command(dev_addr, nwk_skey, app_skey, 0x40, 0x01, amp_no, fcnt)  # (0x03) 要求回覆3號指令

                elif op == "led":
                    # cmd: led <DevAddr> <NwkSKey> <AppSKey> [FCntDown]
                    # send LED_Test (OpCode 0x20 0x01)
                    if len(parts) < 4:
                        self.log("Usage: led <DevAddr> <NwkSKey> <AppSKey> [FCntDown]", C_RED)
                    else:
                        dev_addr = parts[1]
                        nwk_skey = parts[2]
                        app_skey = parts[3]
                        fcnt = int(parts[4]) if len(parts) > 4 else 0
                        self.send_downlink_command(dev_addr, nwk_skey, app_skey, 0x20, 0x01, 0x03, fcnt)

                elif op == "help":
                    print(f"{C_YELLOW}=== Available Commands ==={C_RESET}")
                    print("  trigger <DevEUI>  - Send OTAA Trigger")
                    print("  poll <DevAddr> <NwkSKey> <AppSKey> [FCnt] - Send Health_Req")
                    print("  amp <AmpNo> <DevAddr> <NwkSKey> <AppSKey> [FCnt] - Send amp_command")
                    print("  led <DevAddr> <NwkSKey> <AppSKey> [FCnt]  - Send LED_Test")
                    print("  status - Show statistics")
                    print("  exit   - Quit program")
 		#// w: ======
 		                           
                else:
                    print("Unknown cmd. Type 'help' for available commands.")
                    
            except Exception as e:
                print(f"Input Error: {e}")

if __name__ == "__main__":
    app = SerialLoraBridge()
    app.start()

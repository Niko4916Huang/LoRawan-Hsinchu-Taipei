# LoRawan-Hsinchu-Taipei

1. 那天20260114_Demo原封不動版本.zip 及解壓縮的目錄，<br/>
    是那天完成OTAA 通訊的源碼。<br/>
    其中包含的，<br/>
    Middleware_UART.py 為 console 版，<br/>
    使用指令：trigger B2A105D07ED5B370<br/>
    源碼版本：<br/>
    Gateway_pureLoRa_v1.3.zip<br/>
    Transponder_202601_V1.5.zip<br/><br/>

2. Middleware_UART_20260120.py 為 GUI 版，<br/>
    增加可以上下行的指令，亦包含OTAA指令。<br/>
    只是，OTAA的Accept封包，由chirpstack server傳回到Transponder時，Transponder判定 "MIC Mismatch"，致使OTAA動作不成功，上下行的指令就無法進行測試。<br/><br/>
    此問題尚未解決。<br/>

3. Middleware_UART.py 不論 console板或是 GUI版，都需要使用 UART 與Gateway UART1 連接，以傳送命令。

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

## Wilson fixed Middleware_UART.py let OTAA workable<br/>
1. 在 目錄："Wilson_OTAA"， 有修正的 Middleware_twoway.py 及 OTAA測試成功的 log檔案。<br/>
2. RF_FREQ = 903.9		#// w:915.2， 經測試，915.2也可以 OTAA 成功。<br/>

## 20260213_Twoway_amp<br/>
增加 amp data request command<br/>
使用 Wilson's Middleware_twoway.py ， 增加 amp data request command 向Transponder 要AMP 的訊息。<br/>
同時 在server端常駐mqtt_chirpstack_sub.c 守聽MQTT上傳的data。<br/>

## 20260226_Twoway_amp_Sqlite<br/>
修改成： amp 第幾個指令的 request command<br/>
amp 指令: 01 ~ 09<br/>
同時 在server端常駐mqtt_chirpstack_sqlite.c 守聽MQTT上傳的data，並存入SQL資料庫中，以供後續讀取用。<br/>

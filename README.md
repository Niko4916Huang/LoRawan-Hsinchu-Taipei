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

## 20260313_Twoway_UDP_amp_Sqlite<br/>
修改成： UDP上行及下行流程<br/>
chirpStack <- `UDP:1700` -> Middleware.py <- `UDP:5001` -> Gateway <- `FSK` -> Transponder <- `UART` -> AMP<br/>
1.	OTAA及 Healthy check的功能，目前還必須是由Middleware.py手動指令輸入來發起。<br/>
	OTAA： trigger B2A105D07ED5B370<br/>
	Healthy check：poll 0008deb0 189c883dd408d15f25048f2783845365 fa3439926c42af5a3cabdbdda602a7be 0<br/>
2.	OTAA及 Healthy check成功後，就可以由chirpStack 的queue 發出AMP #的呼叫指令。<br/>
3.	目前Middleware.py 指向的Gateway IP是寫死在程式內，用UDP：5001溝通。<br/>
    Gateway 改用UDP方式，接收port:5001 的方式，與Middleware.py 溝通。<br/>
    Transponder 內修正處理AMP #的回覆。<br/>
## 20260316_Transponder_UDP_V1.1<br/>
   增加 Transponder 處理從chirpStack queue發出的HealthyCheck封包。<br/>
   HealthyCheck封包從Middleware發出，會自動增加到240bytes，而從chirpStack queue發出的封包，是沒有那麼長的。<br/>
   因此，需要不同的處理方式。<br/>
## 20260401_ACI4台_樣品完成<br/>
1. 目前Transponder頻率參數設定固定為： <br/>
		Tx： 204.1MHz<br/>
		Rx： 257.1MHz<br/>
2.  gateway 將 UDP 和 RF-Rx 分開<br/>
	// 1. Check UDP Input<br/>
		收到UDP封包，傳到 RF-Tx就離開<br/>
	// 2. Check RF - Rx Input<br/>
		守聽RF-Rx 看是否有封包傳來，若有，用UDP傳出。<br/>
3. Transponder Power ON， 自動送出OTAA request，不需要Middleware.py發起。<br/>
4. 一旦OTAA成功，接著發出Healthy Check，用AMP#1,及AMP#2，間隔10秒發送。<br/>
   之後，發AMP#3，每120秒。<br/>
5. 可由 server端對AMP 下達 set 的指令，或是 讀取data 的指令。<br/>
## 20260422_解決Gateway在NAT後面時，與外網chirpStack的UDP連接方式<br/>
1. 解決Gateway在NAT後面時，與外網chirpStack network server的UDP連接方式。<br/>
   方法：在gateway 增加 對Middleware.py 每5秒發 PULLDATA 功能。<br/>
2. gateway 修改，守聽 RF – Rx，<br/>
	RX 讀取時，設定Rx_IsReading = true; 讀完設回false。<br/>
	需要 TX時，設為 RF-TX mode，傳完設回RF-RX mode。<br/>
3. Middleware.py接收端的問題修正<br/>
	在gateway 增加 對Middleware.py 發pulldata & pushdata 功能，造成<br/>
	UDP封包只傳一次，Middleware.py就收不到了。<br/>
4. gateway功能修正<br/>
	1. 將對口的Server IP 及 port，存入EEPROM內，開機時取出。<br/>
	2. 建立AT command from UART1，使用此來更改存入的值。<br/>
		Command List:<br/>
		    1. 基本測試       ：  AT<br/>
		    2. 顯示目前的設定  ： AT+SERVER?<br/>
		    3. 設定 (IP, Port)： AT+SERVER=192.168.50.206,5001  <br/>
5. Middleware功能修正<br/>
 1. SERVER_IP = "127.0.0.1" 設定為與chirpstack 在同一IP address。<br/>
 2. 記錄 gateway address & port，UDP封包從哪來，回哪去。解決 gateway 在NAT的後面。<br/>
        data, GWaddr = self.sock_gw.recvfrom(4096)<br/>
     self.gateways.add(GWaddr)<br/>
 3. 將 gateway傳來的 --- PULL_DATA --- 封包，送到chirpstack <br/>
    if identifier == 0x02:<br/>
    	self.log(f"PULL_DATA from {GWaddr}, send to chirpstack", C_YELLOW) <br/>


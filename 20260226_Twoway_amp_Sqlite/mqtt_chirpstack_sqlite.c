#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mosquitto.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>

#define MQTT_HOST "localhost"
#define MQTT_PORT 1883
#define MQTT_TOPIC "application/+/device/+/event/up"

#define MAX_DATA 512

sqlite3 *db;

/* =========================
   Base64 Decode
========================= */

static const unsigned char b64_table[256] = {
    [0 ... 255] = 0x80,
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,
    ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
    ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
    ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
    ['y']=50,['z']=51,
    ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,
    ['7']=59,['8']=60,['9']=61,
    ['+']=62,['/']=63,['=']=0
};

int base64_decode(const char *in, uint8_t *out)
{
    int len = strlen(in);
    int i=0, j=0;

    while(i<len)
    {
        uint8_t a=b64_table[(uint8_t)in[i++]];
        uint8_t b=b64_table[(uint8_t)in[i++]];
        uint8_t c=b64_table[(uint8_t)in[i++]];
        uint8_t d=b64_table[(uint8_t)in[i++]];

        out[j++] = (a<<2)|(b>>4);
        if(in[i-2]!='=') out[j++] = (b<<4)|(c>>2);
        if(in[i-1]!='=') out[j++] = (c<<6)|d;
    }
    return j;
}

/* =========================
   HEX Convert
========================= */

void bytes_to_hex(uint8_t *in, int len, char *out)
{
    for(int i=0;i<len;i++)
        sprintf(out+i*2,"%02X",in[i]);
}

/* =========================
   LoRaWAN Parse
========================= */

typedef struct
{
    uint8_t mhdr;
    uint32_t devaddr;
    uint16_t fcnt;
    uint8_t fport;
    uint8_t mic[4];
    uint8_t payload[256];
    int payload_len;

} lorawan_frame_t;


int parse_lorawan(uint8_t *data, int len, lorawan_frame_t *frame)
{
    if(len < 12) return -1;

    int i=0;

    frame->mhdr = data[i++];

    frame->devaddr =
        data[i] |
        (data[i+1]<<8) |
        (data[i+2]<<16) |
        (data[i+3]<<24);

    i+=4;

    uint8_t fctrl = data[i++];

    frame->fcnt =
        data[i] |
        (data[i+1]<<8);

    i+=2;

    int fopts_len = fctrl & 0x0F;
    i+=fopts_len;

    frame->fport = data[i++];

    frame->payload_len = len - i - 4;

    memcpy(frame->payload,data+i,frame->payload_len);

    memcpy(frame->mic,data+len-4,4);

    return 0;
}

/* =========================
   SQLite
========================= */

void db_init()
{
    sqlite3_open("lorawan.db",&db);

    char *sql =
    "CREATE TABLE IF NOT EXISTS uplink("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "devEUI TEXT,"
    "devAddr TEXT,"
    "fcnt INTEGER,"
    "fport INTEGER,"
    "payload TEXT,"
    "mic TEXT"
    ");";

    sqlite3_exec(db,sql,0,0,0);
}

void db_insert(const char *devEUI,
               const char * devAddr,
               uint16_t fcnt,
               uint8_t fport,
               const char  *payload
               )
{
  
    char mic_hex[16]="11223344";		// 使用虛擬值
   
 //   bytes_to_hex(mic,4,mic_hex);


    char sql[1024];

    sprintf(sql,
    "INSERT INTO uplink(devEUI,devAddr,fcnt,fport,payload,mic)"
    " VALUES('%s','%s',%d,%d,'%s','%s');",
    devEUI,devAddr,fcnt,fport,payload,mic_hex);

    sqlite3_exec(db,sql,0,0,0);

    printf("Saved to SQLite\n");
}

/* =========================
   MQTT Callback
========================= */

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    mosquitto_subscribe(mosq,NULL,MQTT_TOPIC,0);
}

void on_message(struct mosquitto *mosq, void *obj,
                const struct mosquitto_message *msg)
{
    printf("\n--- New Uplink ---\n");
    printf("Topic: %s\n", msg->topic);
    printf("Payload: %s\n\n", (char *)msg->payload);

     // 解析 JSON
    cJSON *root = cJSON_Parse((char *)msg->payload);
    if (!root) {
        printf("JSON parse error\n");
        return;
    }

    // 取 deviceInfo.devEui
    cJSON *devEui = NULL;
    cJSON *deviceInfo = cJSON_GetObjectItem(root, "deviceInfo");
    if (deviceInfo) {
        devEui = cJSON_GetObjectItem(deviceInfo, "devEui");
        if (cJSON_IsString(devEui)) {
            printf("DevEUI: %s\n", devEui->valuestring);
        }
    }
    
    cJSON *devAddr = cJSON_GetObjectItem(root, "devAddr");
    if (cJSON_IsString(devAddr)) {
        printf("devAddr: %s\n", devAddr->valuestring);
    }

    // 取 fCnt
    cJSON *fCnt = cJSON_GetObjectItem(root, "fCnt");
    if (cJSON_IsNumber(fCnt)) {
        printf("fCnt: %d\n", fCnt->valueint);
    }


    // 取 fPort
    cJSON *fPort = cJSON_GetObjectItem(root, "fPort");
    if (cJSON_IsNumber(fPort)) {
        printf("FPort: %d\n", fPort->valueint);
    }

    // 取 base64 data
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (cJSON_IsString(data)) {
        printf("\nBase64 Data: %s\n", data->valuestring);
    }

    // 如果你在 ChirpStack 設定了 codec，會有 object 欄位
    cJSON *object = cJSON_GetObjectItem(root, "object");
    if (object) {
        char *object_str = cJSON_Print(object);
        printf("Decoded Object:\n%s\n", object_str);
        free(object_str);
    }   
    

    uint8_t decoded[MAX_DATA];

    int len = base64_decode(data->valuestring,decoded);
 

    char payload_hex[512];
    bytes_to_hex(decoded,len,payload_hex);

    printf("\nPayload HEX: %s\n",payload_hex);
    
    /*
    	CREATE TABLE uplink(id INTEGER PRIMARY KEY AUTOINCREMENT,
    			devEUI TEXT,
    			devAddr TEXT,
    			fcnt INTEGER,
    			fport INTEGER,
    			payload TEXT,
    			mic TEXT);
    */
    
     char *dev_Eui = NULL;
     char *dev_Addr = NULL;
     
     dev_Eui = strdup(devEui->valuestring);
     dev_Addr = strdup(devAddr->valuestring);


		db_insert(dev_Eui,
		          dev_Addr,
		          fCnt->valueint,
		          fPort->valueint,
		          payload_hex
		          );


    cJSON_Delete(root);
     // 3. 使用完畢後釋放記憶體
    if (dev_Eui != NULL) {
        free(dev_Eui);
        dev_Eui = NULL;
    }
    if (dev_Addr != NULL) {
        free(dev_Addr);
        dev_Addr = NULL;
    }
}

/* =========================
   MAIN
========================= */

int main()
{
    struct mosquitto *mosq;

    db_init();

    mosquitto_lib_init();

    mosq = mosquitto_new(NULL,true,NULL);

    mosquitto_connect_callback_set(mosq,on_connect);
    mosquitto_message_callback_set(mosq,on_message);

    mosquitto_connect(mosq,MQTT_HOST,MQTT_PORT,60);

    mosquitto_loop_forever(mosq,-1,1);

    return 0;
}

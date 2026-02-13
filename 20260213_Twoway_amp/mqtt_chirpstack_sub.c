
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <cjson/cJSON.h>

#define MQTT_HOST "localhost"
#define MQTT_PORT 1883
#define MQTT_TOPIC "application/+/device/+/event/up"

/* ---------------------------
   編譯: gcc mqtt_chirpstack_sub.c -o mqtt_sub -lmosquitto -lcjson
 執行： ./mqtt_sub
---------------------------- */

void on_connect(struct mosquitto *mosq, void *userdata, int rc)
{
    if (rc == 0) {
        printf("Connected to MQTT broker\n");
        mosquitto_subscribe(mosq, NULL, MQTT_TOPIC, 0);
    } else {
        printf("Connect failed: %d\n", rc);
    }
}

void on_message(struct mosquitto *mosq, void *userdata,
                const struct mosquitto_message *msg)
{
    printf("\n--- New Uplink ---\n");
    printf("Topic: %s\n", msg->topic);
    printf("Payload: %s\n", (char *)msg->payload);

    // 解析 JSON
    cJSON *root = cJSON_Parse((char *)msg->payload);
    if (!root) {
        printf("JSON parse error\n");
        return;
    }

    // 取 deviceInfo.devEui
    cJSON *deviceInfo = cJSON_GetObjectItem(root, "deviceInfo");
    if (deviceInfo) {
        cJSON *devEui = cJSON_GetObjectItem(deviceInfo, "devEui");
        if (cJSON_IsString(devEui)) {
            printf("DevEUI: %s\n", devEui->valuestring);
        }
    }

    // 取 fPort
    cJSON *fPort = cJSON_GetObjectItem(root, "fPort");
    if (cJSON_IsNumber(fPort)) {
        printf("FPort: %d\n", fPort->valueint);
    }

    // 取 base64 data
    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (cJSON_IsString(data)) {
        printf("Base64 Data: %s\n", data->valuestring);
    }

    // 如果你在 ChirpStack 設定了 codec，會有 object 欄位
    cJSON *object = cJSON_GetObjectItem(root, "object");
    if (object) {
        char *object_str = cJSON_Print(object);
        printf("Decoded Object:\n%s\n", object_str);
        free(object_str);
    }

    cJSON_Delete(root);
}

int main()
{
    struct mosquitto *mosq;

    mosquitto_lib_init();

    mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq) {
        printf("Error creating mosquitto client\n");
        return -1;
    }

    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_callback_set(mosq, on_message);

    if (mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60) != MOSQ_ERR_SUCCESS) {
        printf("Unable to connect to broker\n");
        return -1;
    }

    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return 0;
}

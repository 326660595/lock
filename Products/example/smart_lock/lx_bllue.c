#include "ble_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "aos/kernel.h"
#include <aos/yloop.h>
#include "cJSON.h"
#include "netmgr.h"
#include "iot_export.h"
#include "iot_import.h"
#include "breeze_export.h"
#include "combo_net.h"

#define COMBO_AWSS_NEED 1 // ap configuration is required
volatile bool lx_blue_open = false;
void blue_init(void)
{
#ifdef EN_COMBO_NET
    
    int ret = combo_net_deinit();
    printf("combo_net_deinit=%d.\n",ret);
    combo_net_init();
#else
    printf("lx_ble_init\n");
     lx_ble_init();
#endif
}

void blue_disconnect(void)
{
    printf("breeze_disconnect_ble\n");
    breeze_disconnect_ble(); //ble_disconnect
}
void blue_close(void)
{
    printf("blue_close=%d\n", breeze_end());
}
uint8_t lx_blue_state(void)
{
    return get_bule_state();
}

extern lx_cmd_in ble_cmd_in;
extern int cmd_data_in(void *cmd, uint32_t size);
void blue_open(void)
{
    printf("a-blue-open\n");


    netmgr_ap_config_t ap_config;
    memset(&ap_config, 0, sizeof(netmgr_ap_config_t));
    int wifi_info = netmgr_get_ap_config(&ap_config);
    if(wifi_info != 0)
    {
        printf("blue_open fail");
        return ;
    }

    ble_cmd_in = cmd_data_in;
    int err = breeze_start_advertising(1, COMBO_AWSS_NEED);//ble_advertising_start//ble_advertising_stop
    if(err == 0)
    {
        lx_blue_open = true;
    }
    printf("lx_blue_open ==%d",lx_blue_open);
}
void blue_stop(void)
{
    printf("blue_stop=%d\n", lx_ble_advertising_stop());
}
void blue_send(uint8_t value)
{
    printf("blue_send-\n");
    uint8_t lenth = value*10;

    uint8_t *test_buffer = (uint8_t *)malloc(sizeof(uint8_t)*lenth);
    //memset(test_buffer,1,lenth);
    for(int i= 0;i<lenth;i++)
    {
        test_buffer[i] = i;
    }

    int err = 0;
    printf("v1=%d;v2=%d",*test_buffer,*(test_buffer+1));

    err = ble_lx_send_notification(test_buffer, lenth);
    printf("ble_lx_send_notification =%d\n", err);
    free(test_buffer);
}
int lx_blue_send_cmd(uint8_t *data,uint8_t len)
{
    printf("lx_blue_send_cmd-\n");
    int err;
    err = ble_lx_send_notification(data, len);
    printf("ble_lx_send_notification =%d\n", err);
    return err;
}
void blue_send_1(void)
{
    // printf("blue_send-1\n");
    // uint8_t blue_buffer[3] = {0x09, 0x01, 0x02};
    // breeze_append_adv_data(blue_buffer, 3);
}
void blue_restart(void)
{
    printf("blue_restart-\n");
    breeze_restart_advertising();
}

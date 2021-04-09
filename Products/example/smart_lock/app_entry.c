/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <aos/aos.h>
#include <aos/yloop.h>
#include "netmgr.h"
#include "iot_export.h"
#include "iot_import.h"
#include "app_entry.h"
#include "aos/kv.h"
#include "vendor.h"
#include "device_state_manger.h"
#include "smart_lock.h"
#include "msg_process_center.h"
#include "property_report.h"
#include "hfilop/hfilop.h"
#include "hfat_cmd.h"
#include "ymodem.h"
#include "hal/wifi.h"
#include <hal/soc/flash.h>
#include <hal/soc/gpio.h>
#include "board.h"
#include "hfilop/hfilop.h"
#include "hfilop/hfilop_config.h"
#include "business.h"
#include "lx_bllue.h"
#include "lx_main.h"

#ifdef SUPPORT_MCU_OTA
#include "hfat_cmd.h"
#include "mcu_ota.h"
#else
extern bool mcu_ota_start_flag;

#endif

#ifdef AOS_TIMER_SERVICE
#include "iot_export_timer.h"
#endif
#ifdef CSP_LINUXHOST
#include <signal.h>
#endif

#include <k_api.h>

#if defined(OTA_ENABLED) && defined(BUILD_AOS)
#include "ota_service.h"
#endif

#ifdef EN_COMBO_NET
#include "breeze_export.h"
#include "combo_net.h"
#endif

#include <hfilop/hfilop_ble.h>


static aos_task_t task_key_detect;
static aos_task_t task_msg_process;
static aos_task_t task_property_report;
static aos_task_t task_linkkit_reset;
static aos_task_t task_reboot_device;
//static aos_task_t task_get_stat;//获取状态
//static aos_task_t task_printstate;//打印ota状态

char linkkit_started = 0;
aos_timer_t awss_config_timeout_timer;




extern int init_awss_flag(void);
extern int HAL_Awss_Get_Timeout_Interval_Ms(void);
extern int user_ble_serv_request_event_handler(const int devid, const char *serviceid, const int serviceid_len,
        const char *request, const int request_len);
extern int user_ble_property_set_event_handler(const int devid, const char *request, const int request_len);
extern int user_ble_property_get_event_handler(const int devid, const char *request, const int request_len,
        char **response, int *response_len);

extern const hfat_cmd_t user_define_at_cmds_table[];


void do_awss_ble_start(void);
void print_heap()
{
    extern k_mm_head *g_kmm_head;
    int               free = g_kmm_head->free_size;
    LOG("============free heap size =%d==========", free);
}

#ifdef CONFIG_PRINT_HEAP
void print_heap()
{
    extern k_mm_head *g_kmm_head;
    int               free = g_kmm_head->free_size;
    LOG("============free heap size =%d==========", free);
}
#endif

static void wifi_service_event(input_event_t *event, void *priv_data)
{
    if (event->type != EV_WIFI) {
        return;
    }

    LOG("wifi_service_event(), event->code=%d", event->code);
    if (event->code == CODE_WIFI_ON_CONNECTED) {
        LOG("CODE_WIFI_ON_CONNECTED");
    } else if (event->code == CODE_WIFI_ON_DISCONNECT) {
        LOG("CODE_WIFI_ON_DISCONNECT");
#ifdef EN_COMBO_NET
        combo_set_ap_state(COMBO_AP_DISCONNECTED);
#endif
    } else if (event->code == CODE_WIFI_ON_CONNECT_FAILED) {
        LOG("CODE_WIFI_ON_CONNECT_FAILED");
    } else if (event->code == CODE_WIFI_ON_GOT_IP) {
        LOG("CODE_WIFI_ON_GOT_IP");

#ifdef EN_COMBO_NET
        combo_set_ap_state(COMBO_AP_CONNECTED);
#endif
    }

    if (event->code != CODE_WIFI_ON_GOT_IP) {

        return;
    }

    netmgr_ap_config_t config;
    memset(&config, 0, sizeof(netmgr_ap_config_t));
    netmgr_get_ap_config(&config);
    LOG("wifi_service_event config.ssid %s", config.ssid);
    if (strcmp(config.ssid, "adha") == 0 || strcmp(config.ssid, "aha") == 0) {
        // clear_wifi_ssid();
        return;
    }
    //set_net_state(GOT_AP_SSID);
#ifdef EN_COMBO_NET
    combo_ap_conn_notify();
#endif

    if (!linkkit_started) {
#ifdef CONFIG_PRINT_HEAP
        print_heap();
#endif
#if (defined (TG7100CEVB))
        aos_task_new("linkkit", (void (*)(void *))linkkit_main, NULL, 1024 * 8);
#else
        aos_task_new("linkkit", (void (*)(void *))linkkit_main, NULL, 1024 * 6);
#endif
        linkkit_started = 1;
    }
}

static void cloud_service_event(input_event_t *event, void *priv_data)
{
    if (event->type != EV_YUNIO) {
        return;
    }

    LOG("cloud_service_event %d", event->code);

    if (event->code == CODE_YUNIO_ON_CONNECTED) {
        LOG("user sub and pub here");
		cloud_conn_status=true;//--20181029
        return;
    }

    if (event->code == CODE_YUNIO_ON_DISCONNECTED) {
        cloud_conn_status=false;//--20181029
    }
}

static void awss_config_net_timeout_event(void)
{
    static bool not_send_flag=true;
    if(not_send_flag)
    {
        not_send_flag=false;
        //unsigned char buf[100];
        //memset(buf,0,sizeof(buf));
        //strcpy(buf,"+ILOPCONNECT=AWSS_TIMEOUT\r\n\r\n");
        //if(!mcu_ota_start_flag && !g_hfilop_config.tmod)//--20190108
            //hfilop_uart_send_data(buf,strlen(buf));
    }
}

static void awss_config_timeout_check_function(void *timer,void *args)
{
    if(awss_config_press_start_flag)//awss config timeout
    {
        if(strlen(g_hfilop_config.last_connect_ssid)>0)//Has the SSID that connected the router successfully
        {
            netmgr_ap_config_t config;
            memset(config.ssid,0,sizeof(config.ssid));
            memset(config.pwd,0,sizeof(config.pwd));
            strcpy(config.ssid,g_hfilop_config.last_connect_ssid);
            strcpy(config.pwd,g_hfilop_config.last_connect_key);
            netmgr_set_ap_config(&config);
	        aos_kv_set(NETMGR_WIFI_KEY, (unsigned char *)&config, sizeof(netmgr_ap_config_t), 1);
            
            //unsigned char buf[100];
            //memset(buf,0,sizeof(buf));
            //strcpy(buf,"+ILOPCONNECT=AWSS_TIMEOUT\r\n\r\n");
            //if(!mcu_ota_start_flag && !g_hfilop_config.tmod)//--20190108
                //hfilop_uart_send_data(buf,strlen(buf));
            LOG("awss config timeout,connect last ssid(%s) key(%s).",g_hfilop_config.last_connect_ssid,g_hfilop_config.last_connect_key);
            aos_msleep(1000);
            aos_reboot();
        }
        else
        {
            //unsigned char buf[100];
            //memset(buf,0,sizeof(buf));
            //strcpy(buf,"+ILOPCONNECT=AWSS_TIMEOUT\r\n\r\n");
            //if(!mcu_ota_start_flag && !g_hfilop_config.tmod)//--20190108
                //hfilop_uart_send_data(buf,strlen(buf));
            LOG("awss config timeout,linkkit_reset.");
            aos_msleep(1000);
            linkkit_reset(NULL);
            
        }
    }
    else
    {
        aos_timer_stop(&awss_config_timeout_timer);
        aos_timer_free(&awss_config_timeout_timer);
    }
}


int awss_config_timeout_check(void)
{
    int outtime_time_ms=HAL_Awss_Get_Timeout_Interval_Ms()-(10*1000);
    return aos_timer_new(&awss_config_timeout_timer,awss_config_timeout_check_function,NULL,outtime_time_ms,1);
}


/*
 * Note:
 * the linkkit_event_monitor must not block and should run to complete fast
 * if user wants to do complex operation with much time,
 * user should post one task to do this, not implement complex operation in
 * linkkit_event_monitor
 */

static void linkkit_event_monitor(int event)
{
    switch (event) {
        case IOTX_AWSS_START: // AWSS start without enbale, just supports device discover
            // operate led to indicate user
			do_awss_active();
            set_net_state(UNCONFIGED);
            lx_wifi_state_reply();
            aos_msleep(200);
            uint8_t reply_msg[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(reply_msg)-3),DEVICE_PROV,0x04};
            //计算校验
            reply_msg[1] = check_sum(reply_msg,sizeof(reply_msg));
            lx_uart_send(reply_msg, sizeof(reply_msg) );

            LOG("IOTX_AWSS_START");
            break;
        case IOTX_AWSS_ENABLE: // AWSS enable, AWSS doesn't parse awss packet until AWSS is enabled.
            LOG("IOTX_AWSS_ENABLE");
            // operate led to indicate user
            break;
        case IOTX_AWSS_LOCK_CHAN: // AWSS lock channel(Got AWSS sync packet)
            LOG("IOTX_AWSS_LOCK_CHAN");
            // operate led to indicate user
            break;
        case IOTX_AWSS_PASSWD_ERR: // AWSS decrypt passwd error
            LOG("IOTX_AWSS_PASSWD_ERR");
            // operate led to indicate user
            break;
        case IOTX_AWSS_GOT_SSID_PASSWD:
            LOG("IOTX_AWSS_GOT_SSID_PASSWD");
        if(awss_config_press_start_flag)//awss config success check 
        {
            awss_config_sucess_event_down();
            awss_config_press_start_flag=false;
			#ifdef SUPPORT_MCU_OTA
            aos_post_delayed_action(2000, send_mcu_upgrade_file_ver, NULL);
			#endif
        }
            // operate led to indicate user
            //set_net_state(GOT_AP_SSID);
            break;
        case IOTX_AWSS_CONNECT_ADHA: // AWSS try to connnect adha (device
            // discover, router solution)
            LOG("IOTX_AWSS_CONNECT_ADHA");
            // operate led to indicate user
            break;
        case IOTX_AWSS_CONNECT_ADHA_FAIL: // AWSS fails to connect adha
            LOG("IOTX_AWSS_CONNECT_ADHA_FAIL");
            // operate led to indicate user
            break;
        case IOTX_AWSS_CONNECT_AHA: // AWSS try to connect aha (AP solution)
            LOG("IOTX_AWSS_CONNECT_AHA");
            // operate led to indicate user
            break;
        case IOTX_AWSS_CONNECT_AHA_FAIL: // AWSS fails to connect aha
            LOG("IOTX_AWSS_CONNECT_AHA_FAIL");
            // operate led to indicate user
            break;
        case IOTX_AWSS_SETUP_NOTIFY: // AWSS sends out device setup information
            // (AP and router solution)
            LOG("IOTX_AWSS_SETUP_NOTIFY");
            // operate led to indicate user
            break;
        case IOTX_AWSS_CONNECT_ROUTER: // AWSS try to connect destination router
            LOG("IOTX_AWSS_CONNECT_ROUTER");
            // operate led to indicate user
            break;
        case IOTX_AWSS_CONNECT_ROUTER_FAIL: // AWSS fails to connect destination
            // router.
            LOG("IOTX_AWSS_CONNECT_ROUTER_FAIL");
            //set_net_state(CONNECT_AP_FAILED);
            ilop_connect_status_down(WIFI_DISCONNECT);
            ilop_connect_status=WIFI_DISCONNECT;
            // operate led to indicate user
            break;
        case IOTX_AWSS_GOT_IP: // AWSS connects destination successfully and got
            // ip address
            LOG("IOTX_AWSS_GOT_IP");
		
            // operate led to indicate user
            break;
        case IOTX_AWSS_SUC_NOTIFY: // AWSS sends out success notify (AWSS
            // sucess)
            LOG("IOTX_AWSS_SUC_NOTIFY");
            // operate led to indicate user
            break;
        case IOTX_AWSS_BIND_NOTIFY: // AWSS sends out bind notify information to
            // support bind between user and device
            LOG("IOTX_AWSS_BIND_NOTIFY");
            // operate led to indicate user
            user_example_ctx_t *user_example_ctx = user_example_get_ctx();
            user_example_ctx->bind_notified = 1;
            break;
        case IOTX_AWSS_ENABLE_TIMEOUT: // AWSS enable timeout
            // user needs to enable awss again to support get ssid & passwd of router
            LOG("IOTX_AWSS_ENALBE_TIMEOUT");
            // operate led to indicate user
            break;
        case IOTX_CONN_CLOUD: // Device try to connect cloud
            LOG("IOTX_CONN_CLOUD");
            // operate led to indicate user
            break;
        case IOTX_CONN_CLOUD_FAIL: // Device fails to connect cloud, refer to
            // net_sockets.h for error code
            LOG("IOTX_CONN_CLOUD_FAIL");
#ifdef EN_COMBO_NET
            combo_set_cloud_state(0);
#endif
            set_net_state(CONNECT_CLOUD_FAILED);
            // lx_wifi_state_reply();
            // operate led to indicate user
            break;
        case IOTX_CONN_CLOUD_SUC: // Device connects cloud successfully
            LOG("IOTX_CONN_CLOUD_SUC");
#ifdef EN_COMBO_NET
            combo_set_cloud_state(1);
#endif
			hal_gpio_output_low(&GPIO_Link);
            set_net_state(CONNECT_CLOUD_SUCCESS);
            // lx_wifi_state_reply();
			//ilop_connect_status_down(SERVER_CONNECT);
            // operate led to indicate user
            break;
        case IOTX_RESET: // Linkkit reset success (just got reset response from
            // cloud without any other operation)
            LOG("IOTX_RESET");
            break;
        case IOTX_CONN_REPORT_TOKEN_SUC:
#ifdef EN_COMBO_NET
            combo_token_report_notify();
#endif
            LOG("---- report token success ----");
            break;
        default:
            break;
    }
}

#ifdef AWSS_BATCH_DEVAP_ENABLE


#define DEV_AP_ZCONFIG_TIMEOUT_MS  120000 // (ms)


void do_awss_dev_ap();

extern void awss_set_config_press(uint8_t press);
extern uint8_t awss_get_config_press(void);
extern void zconfig_80211_frame_filter_set(uint8_t filter, uint8_t fix_channel);



static aos_timer_t dev_ap_zconfig_timeout_timer;
static uint8_t g_dev_ap_zconfig_timer = 0; // this timer create once and can restart
static uint8_t g_dev_ap_zconfig_run = 0;

static void timer_func_devap_zconfig_timeout(void *arg1, void *arg2)
{
    LOG("%s run\n", __func__);

    if (awss_get_config_press()) {
        // still in zero wifi provision stage, should stop and switch to dev ap
        do_awss_dev_ap();
    } else {
        // zero wifi provision finished
    }

    awss_set_config_press(0);
    zconfig_80211_frame_filter_set(0xFF, 0xFF);
    g_dev_ap_zconfig_run = 0;
    aos_timer_stop(&dev_ap_zconfig_timeout_timer);
}

static void awss_dev_ap_switch_to_zeroconfig(void *p)
{
    LOG("%s run\n", __func__);
    // Stop dev ap wifi provision
    awss_dev_ap_stop();
    // Start and enable zero wifi provision
    awss_set_config_press(1);

    // Start timer to count duration time of zero provision timeout
    if (!g_dev_ap_zconfig_timer) {
        aos_timer_new(&dev_ap_zconfig_timeout_timer, timer_func_devap_zconfig_timeout, NULL, DEV_AP_ZCONFIG_TIMEOUT_MS, 0);
        g_dev_ap_zconfig_timer = 1;
    }
    aos_timer_start(&dev_ap_zconfig_timeout_timer);

    // This will hold thread, when awss is going
    netmgr_start(true);

    LOG("%s exit\n", __func__);
    aos_task_exit(0);
}

int awss_dev_ap_modeswitch_cb(uint8_t awss_new_mode, uint8_t new_mode_timeout, uint8_t fix_channel)
{
    if ((awss_new_mode == 0) && !g_dev_ap_zconfig_run) {
        g_dev_ap_zconfig_run = 1;
        // Only receive zero provision packets
        zconfig_80211_frame_filter_set(0x00, fix_channel);
        LOG("switch to awssmode %d, mode_timeout %d, chan %d\n", 0x00, new_mode_timeout, fix_channel);
        // switch to zero config
        aos_task_new("devap_to_zeroconfig", awss_dev_ap_switch_to_zeroconfig, NULL, 2048);
    }
}
#endif

static void awss_close_dev_ap(void *p)
{
    awss_dev_ap_stop();
    aos_task_exit(0);
}

extern int cmd_data_in(char *cmd, uint32_t size);
static int uart_recv_callback(void *data,int len)
{
    printf("uart_recv_callback\r\n");
    TRACE_BINARY(data,len);
    //LOG_TRACE("\r\nAPP: %s", aos_get_app_version());
	printf("uart_recv_callback uart buff len:%d,buffer:%s\n",len,data);
	if(hfilop_uart_in_cmd_mode()!=0)
        return len;

    if(len >= 3){
        cmd_data_in((char *)data, len);
    }else{
        //rouse_reply(NULL,0);
        uint8_t data_type = *(uint8_t *)data;
        switch (data_type)
        {
        case 0:
            blue_init();
            break;
        case 1:
            blue_open();
            break;
        case 2:
            blue_disconnect();
            break;
        case 3:
            blue_stop();
            break;
        case 4:
            blue_restart();
            break;
        case 5:
            blue_send(*((uint8_t *)data+1));
            break;
        case 6:
            blue_send_1();
            break;
        case 8:
        {
            
            printf("save a_test=%d\n",lx_blue_state());
            break;
            }
        case 9:
        {
            uint8_t a_test =9;
            user_data_read_lx_config(&a_test);
            printf("read a_test =%d\n",a_test);
            break;

        }
            
        default:
            break;
        }
    }

    // printf("data is a = %d",*((uint8_t*)data));
    // if(*((uint8_t*)data) == 8)
    //     lock_event_clean();
    // //aos_schedule_call(do_awss_ble_start, NULL);
    // if(*((uint8_t*)data) == 9)
    //   {
    //       printf("do_awss_ble_start---->>>>>\n");
    //       do_awss_ble_start();
    //   } 


      
	//to do post data to cloud
	/*if(post_uart_data_cloud(data,len))
		printf("post ali iot data success\n");
	else
		printf("post ali iot data fail !!!\n");*/
#ifdef  SUPPORT_MCU_OTA
		if(mcu_ota_start_flag)
		{
			Ymodem_Transmit_uart_data(data,len);
		}
#endif
	return 0;
}


void awss_open_dev_ap(void *p)
{
	aos_msleep(4000);
    /*if (netmgr_start(false) != 0) */{
        //aos_msleep(2000);
#ifdef AWSS_BATCH_DEVAP_ENABLE
        awss_dev_ap_reg_modeswit_cb(awss_dev_ap_modeswitch_cb);
#endif
        awss_dev_ap_start();
    }
    aos_task_exit(0);
}


void stop_netmgr(void *p)
{
	aos_msleep(3000);
    awss_stop();
    aos_task_exit(0);
}

void start_netmgr(void *p)
{
    netmgr_start(true);
    aos_task_exit(0);
}

void do_awss_active(void)
{
    LOG("do_awss_active");
#ifdef WIFI_PROVISION_ENABLED
    extern int awss_config_press();
    awss_config_press();
#endif
}


#ifdef EN_COMBO_NET
int user_ble_event_handler(uint16_t event_code) {
    if (event_code == COMBO_EVT_CODE_FULL_REPORT) {
        report_device_property(NULL, 0);
    }
}




void combo_open(void)
{
    combo_net_init();
    combo_reg_evt_cb(user_ble_event_handler);
    combo_reg_common_serv_cb(user_ble_serv_request_event_handler);
    combo_reg_property_set_cb(user_ble_property_set_event_handler);
    combo_reg_property_get_cb(user_ble_property_get_event_handler);
}

void ble_awss_open(void *p)
{
    combo_set_awss_state(1);
    aos_task_exit(0);
}

static void ble_awss_close(void *p)
{
    combo_set_awss_state(0);
    aos_task_exit(0);
}

void do_ble_awss()
{
    aos_task_new("ble_awss_open", ble_awss_open, NULL, 2048);
}
#endif

void do_awss_dev_ap()
{
    // Enter dev_ap awss mode
    aos_task_new("netmgr_stop", stop_netmgr, NULL, 4096);
    aos_task_new("dap_open", awss_open_dev_ap, NULL, 4096);
}

void do_awss()
{
    // Enter smart_config awss mode
    aos_task_new("dap_close", awss_close_dev_ap, NULL, 4096);
    aos_task_new("netmgr_start", start_netmgr, NULL, 5120);
}

void linkkit_reset(void *p)
{
    //aos_msleep(2000);
    aos_msleep(1000);
#ifdef AOS_TIMER_SERVICE
    timer_service_clear();
#endif
    aos_kv_del(KV_KEY_SWITCH_STATE);
    iotx_sdk_reset_local();
    netmgr_clear_ap_config();
#ifdef EN_COMBO_NET
    breeze_clear_bind_info();
#endif
    //HAL_Reboot();
    do_awss_ble_start();
    aos_task_exit(0);
}
void lx_unbundling(void *p)//解绑，不配网
{
    printf("lx_unbundling\n");
#ifdef AOS_TIMER_SERVICE
    timer_service_clear();
#endif
    aos_kv_del(KV_KEY_SWITCH_STATE);
    iotx_sdk_reset_local();
    netmgr_clear_ap_config();
#ifdef EN_COMBO_NET
    breeze_clear_bind_info();
#endif
    aos_task_exit(0);
}
extern int iotx_sdk_reset(iotx_vendor_dev_reset_type_t *reset_type);
iotx_vendor_dev_reset_type_t reset_type = IOTX_VENDOR_DEV_RESET_TYPE_UNBIND_ONLY;
void do_awss_reset(void)
{
#ifdef WIFI_PROVISION_ENABLED
    aos_task_new("reset", (void (*)(void *))iotx_sdk_reset, &reset_type, 6144);  // stack taken by iTLS is more than taken by TLS.
#endif
    // aos_task_new_ext(&task_linkkit_reset, "reset task", linkkit_reset, NULL, 1024, 0);
    aos_task_new_ext(&task_linkkit_reset, "reset task", linkkit_reset, NULL, 1024, 0);
}

void do_awss_ble_start(void)
{
	  g_hfilop_config.awss_mode=ILOP_AWSS_DEV_BLE_MODE;
 	  hfilop_config_save();
	  aos_msleep(200);
	  aos_reboot();
}

void smart_ble_config(void)
{
    int ret = 0;
    ret = aos_kv_del(NETMGR_WIFI_KEY); /* Remove unsecured config, if exists */
    ret = aos_kv_del(NETMGR_WIFI_SS_KEY); /* Remove secured config */
    do_awss_ble_start();
}

void reboot_device(void *p)
{
    // aos_msleep(500);
    // HAL_Reboot();
    aos_msleep(1000);
#ifdef AOS_TIMER_SERVICE
    timer_service_clear();
#endif
    aos_kv_del(KV_KEY_SWITCH_STATE);
    iotx_sdk_reset_local();
    netmgr_clear_ap_config();
    do_awss_ble_start();
    aos_task_exit(0);
}

void do_awss_reboot(void)
{
    int ret;
    unsigned char awss_flag = 1;
    int len = sizeof(awss_flag);

    ret = aos_kv_set("awss_flag", &awss_flag, len, 1);
    if (ret != 0)
        LOG("KV Setting failed");

    aos_task_new_ext(&task_reboot_device, "reboot task", reboot_device, NULL, 1024, 0);
}

void linkkit_key_process(input_event_t *eventinfo, void *priv_data)
{
    if (eventinfo->type != EV_KEY) {
        return;
    }
    LOG("awss config press %d\n", eventinfo->value);

    if (eventinfo->code == CODE_BOOT) {
        if (eventinfo->value == VALUE_KEY_CLICK) {
            do_awss_active();
        } else if (eventinfo->value == VALUE_KEY_LTCLICK) {
            do_awss_reset();
        }
    }
}

#ifdef MANUFACT_AP_FIND_ENABLE
void manufact_ap_find_process(int result)
{
    // Informed manufact ap found or not.
    // If manufact ap found, lower layer will auto connect the manufact ap
    // IF manufact ap not found, lower layer will enter normal awss state
    if (result == 0) {
        LOG("%s ap found.\n", __func__);
    } else {
        LOG("%s ap not found.\n", __func__);
    }
}
#endif

#ifdef CONFIG_AOS_CLI
static void handle_reset_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    aos_schedule_call((aos_call_t)do_awss_reset, NULL);
}

static void handle_active_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    aos_schedule_call((aos_call_t)do_awss_active, NULL);
}

static void handle_dev_ap_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    aos_schedule_call((aos_call_t)do_awss_dev_ap, NULL);
}

#ifdef EN_COMBO_NET
static void handle_ble_awss_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    aos_schedule_call((aos_call_t)do_ble_awss, NULL);
}
#endif

static void handle_linkkey_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    if (argc == 1) {
        int len = 0;
        char product_key[PRODUCT_KEY_LEN + 1] = { 0 };
        char product_secret[PRODUCT_SECRET_LEN + 1] = { 0 };
        char device_name[DEVICE_NAME_LEN + 1] = { 0 };
        char device_secret[DEVICE_SECRET_LEN + 1] = { 0 };
        char pidStr[9] = { 0 };

        len = PRODUCT_KEY_LEN + 1;
        aos_kv_get("linkkit_product_key", product_key, &len);

        len = PRODUCT_SECRET_LEN + 1;
        aos_kv_get("linkkit_product_secret", product_secret, &len);

        len = DEVICE_NAME_LEN + 1;
        aos_kv_get("linkkit_device_name", device_name, &len);

        len = DEVICE_SECRET_LEN + 1;
        aos_kv_get("linkkit_device_secret", device_secret, &len);

        aos_cli_printf("Product Key=%s.\r\n", product_key);
        aos_cli_printf("Device Name=%s.\r\n", device_name);
        aos_cli_printf("Device Secret=%s.\r\n", device_secret);
        aos_cli_printf("Product Secret=%s.\r\n", product_secret);
        len = sizeof(pidStr);
        if (aos_kv_get("linkkit_product_id", pidStr, &len) == 0) {
            aos_cli_printf("Product Id=%d.\r\n", atoi(pidStr));
        }
    } else if (argc == 5 || argc == 6) {
        aos_kv_set("linkkit_product_key", argv[1], strlen(argv[1]) + 1, 1);
        aos_kv_set("linkkit_device_name", argv[2], strlen(argv[2]) + 1, 1);
        aos_kv_set("linkkit_device_secret", argv[3], strlen(argv[3]) + 1, 1);
        aos_kv_set("linkkit_product_secret", argv[4], strlen(argv[4]) + 1, 1);
        if (argc == 6)
            aos_kv_set("linkkit_product_id", argv[5], strlen(argv[5]) + 1, 1);
        aos_cli_printf("Done");
    } else {
        aos_cli_printf("Error: %d\r\n", __LINE__);
        return;
    }
}

static void handle_awss_cmd(char *pwbuf, int blen, int argc, char **argv)
{
    aos_schedule_call((aos_call_t)do_awss, NULL);
}

static struct cli_command resetcmd = {
    .name = "reset",
    .help = "factory reset",
    .function = handle_reset_cmd
};

static struct cli_command awss_enable_cmd = {
    .name = "active_awss",
    .help = "active_awss [start]",
    .function = handle_active_cmd
};

static struct cli_command awss_dev_ap_cmd = {
    .name = "dev_ap",
    .help = "awss_dev_ap [start]",
    .function = handle_dev_ap_cmd
};

static struct cli_command awss_cmd = {
    .name = "awss",
    .help = "awss [start]",
    .function = handle_awss_cmd
};

#ifdef EN_COMBO_NET
static struct cli_command awss_ble_cmd = {
    .name = "ble_awss",
    .help = "ble_awss [start]",
    .function = handle_ble_awss_cmd
};
#endif

static struct cli_command linkkeycmd = {
    .name = "linkkey",
    .help = "set/get linkkit keys. linkkey [<Product Key> <Device Name> <Device Secret> <Product Secret>]",
    .function = handle_linkkey_cmd
};

#endif

#ifdef CONFIG_PRINT_HEAP
static void duration_work(void *p)
{
    print_heap();
    aos_post_delayed_action(5000, duration_work, NULL);
}
#endif

#if defined(OTA_ENABLED) && defined(BUILD_AOS)
static int ota_init(void);
static ota_service_t ctx = {0};
#endif
static int mqtt_connected_event_handler(void)
{
#if defined(OTA_ENABLED) && defined(BUILD_AOS)
    static bool ota_service_inited = false;

    if (ota_service_inited == true) {
        int ret = 0;

        LOG("MQTT reconnected, let's redo OTA upgrade");
        if ((ctx.h_tr) && (ctx.h_tr->upgrade)) {
            LOG("Redoing OTA upgrade");
            ret = ctx.h_tr->upgrade(&ctx);
            if (ret < 0) LOG("Failed to do OTA upgrade");
        }

        return ret;
    }

    LOG("MQTT Construct  OTA start to inform");
#ifdef DEV_OFFLINE_OTA_ENABLE
    ota_service_inform(&ctx);
    LOG_TRACE("ota_service_inform -->2 %s\n",ctx.sys_ver);//ctx.dev_type
#else
    ota_init();//检测上传ota版本号信息
#endif

#ifdef OTA_MULTI_MODULE_DEBUG
    extern ota_hal_module_t ota_hal_module1;
    extern ota_hal_module_t ota_hal_module2;
    iotx_ota_module_info_t module;
    char module_name_key[MODULE_NAME_LEN + 1] = {0};
    char module_version_key[MODULE_VERSION_LEN + 1] = {0};
    char module_name_value[MODULE_NAME_LEN + 1] = {0};
    char module_version_value[MODULE_VERSION_LEN + 1] = {0};
    char buffer_len = 0;
    int ret = 0;

    for(int i = 1; i <= 2; i++){
        memset(module_name_key, 0, MODULE_NAME_LEN);
        memset(module_version_key, 0, MODULE_VERSION_LEN);
        memset(module_name_value, 0, MODULE_NAME_LEN);
        memset(module_version_value, 0, MODULE_VERSION_LEN);
        HAL_Snprintf(module_name_key, MODULE_NAME_LEN, "ota_m_name_%d", i);
        HAL_Snprintf(module_version_key, MODULE_VERSION_LEN, "ota_m_version_%d", i);
        HAL_Printf("module_name_key is %s\n",module_name_key);
        HAL_Printf("module_version_key is %s\n",module_version_key);
        buffer_len = MODULE_NAME_LEN;
        ret = HAL_Kv_Get(module_name_key,module_name_value, &buffer_len);
        buffer_len = MODULE_VERSION_LEN;
        ret |= HAL_Kv_Get(module_version_key,module_version_value, &buffer_len);
        memcpy(module.module_name, module_name_value, MODULE_NAME_LEN);
        memcpy(module.module_version, module_version_value, MODULE_VERSION_LEN);
        memcpy(module.product_key, ctx.pk, sizeof(ctx.pk)-1);
        memcpy(module.device_name, ctx.dn, sizeof(ctx.dn)-1);
        if(!ret){
            if(i == 1){
                module.hal = &ota_hal_module1;
            }else{
                module.hal = &ota_hal_module2;
            }
            ota_service_set_module_info(&ctx, &module);
        }
        HAL_Printf("module_name_value is %s\n",module_name_value);
        HAL_Printf("module_version_value is %s\n",module_version_value);
    }

#endif
    ota_service_inited = true;
#endif
    return 0;
}
// void print_ota_state(void *argv)
// {
//     printf("------------printstate-------------\n");
//     while(1)
//     {
//         aos_msleep(200);
// #if defined(OTA_ENABLED) && defined(BUILD_AOS)
//         printf("ota state is->:%d\n",ctx.upg_status);
// #endif 

//     }
   
// }
static int ota_init(void)
{
#if defined(OTA_ENABLED) && defined(BUILD_AOS)
    char product_key[PRODUCT_KEY_LEN + 1] = {0};
    char device_name[DEVICE_NAME_LEN + 1] = {0};
    char device_secret[DEVICE_SECRET_LEN + 1] = {0};
    HAL_GetProductKey(product_key);
    HAL_GetDeviceName(device_name);
    HAL_GetDeviceSecret(device_secret);
    memset(&ctx, 0, sizeof(ota_service_t));
    strncpy(ctx.pk, product_key, sizeof(ctx.pk)-1);
    strncpy(ctx.dn, device_name, sizeof(ctx.dn)-1);
    strncpy(ctx.ds, device_secret, sizeof(ctx.ds)-1);
    ctx.trans_protcol = 0;
    ctx.dl_protcol = 3;
    LOG_TRACE("ota_init -->1 %s\n",ctx);
    ota_service_init(&ctx);
#endif
    return 0;
}

static void show_firmware_version(void)
{
    printf("\r\n--------Firmware info--------");
    printf("\r\nHost: %s", COMPILE_HOST);
    printf("\r\nBranch: %s", GIT_BRANCH);
    printf("\r\nHash: %s", GIT_HASH);
    printf("\r\nDate: %s %s", __DATE__, __TIME__);
    printf("\r\nKernel: %s", aos_get_kernel_version());
    printf("\r\nLinkKit: %s", LINKKIT_VERSION);
    printf("\r\nAPP: %s", aos_get_app_version());

    printf("\r\nRegion env: %s\r\n\r\n", REGION_ENV_STRING);
}
static int uart_data_process(char *data, uint32_t len)
{
    LOG("uart_data_process:(%d)[%s]\n", len,data);
    if(hfilop_uart_in_cmd_mode()!=0)
        return len;
//    hfilop_uart_send_data((unsigned char*)data,len);
#ifdef  SUPPORT_MCU_OTA
		if(mcu_ota_start_flag)
		{
			Ymodem_Transmit_uart_data(data,len);
		}
#endif

    return 0;
}



#if 0//(defined (TG7100CEVB))
void media_to_kv(void)
{
    char product_key[PRODUCT_KEY_LEN + 1] = { 0 };
    char *p_product_key = NULL;
    char product_secret[PRODUCT_SECRET_LEN + 1] = { 0 };
    char *p_product_secret = NULL;
    char device_name[DEVICE_NAME_LEN + 1] = { 0 };
    char *p_device_name = NULL;
    char device_secret[DEVICE_SECRET_LEN + 1] = { 0 };
    char *p_device_secret = NULL;
    char pidStr[9] = { 0 };
    char *p_pidStr = NULL;
    int len;

    int res;

    /* check media valid, and update p */
    res = ali_factory_media_get(
                &p_product_key,
                &p_product_secret,
                &p_device_name,
                &p_device_secret,
                &p_pidStr);
    if (0 != res) {
        printf("ali_factory_media_get res = %d\r\n", res);
        return;
    }

    /* compare kv media */
    len = sizeof(product_key);
    aos_kv_get("linkkit_product_key", product_key, &len);
    len = sizeof(product_secret);
    aos_kv_get("linkkit_product_secret", product_secret, &len);
    len = sizeof(device_name);
    aos_kv_get("linkkit_device_name", device_name, &len);
    len = sizeof(device_secret);
    aos_kv_get("linkkit_device_secret", device_secret, &len);
    len = sizeof(pidStr);
    aos_kv_get("linkkit_product_id", pidStr, &len);

    if (p_product_key) {
        if (0 != memcmp(product_key, p_product_key, strlen(p_product_key))) {
            printf("memcmp p_product_key different. set kv: %s\r\n", p_product_key);
            aos_kv_set("linkkit_product_key", p_product_key, strlen(p_product_key), 1);
        }
    }
    if (p_product_secret) {
        if (0 != memcmp(product_secret, p_product_secret, strlen(p_product_secret))) {
            printf("memcmp p_product_secret different. set kv: %s\r\n", p_product_secret);
            aos_kv_set("linkkit_product_secret", p_product_secret, strlen(p_product_secret), 1);
        }
    }
    if (p_device_name) {
        if (0 != memcmp(device_name, p_device_name, strlen(p_device_name))) {
            printf("memcmp p_device_name different. set kv: %s\r\n", p_device_name);
            aos_kv_set("linkkit_device_name", p_device_name, strlen(p_device_name), 1);
        }
    }
    if (p_device_secret) {
        if (0 != memcmp(device_secret, p_device_secret, strlen(p_device_secret))) {
            printf("memcmp p_device_secret different. set kv: %s\r\n", p_device_secret);
            aos_kv_set("linkkit_device_secret", p_device_secret, strlen(p_device_secret), 1);
        }
    }
    if (p_pidStr) {
        if (0 != memcmp(pidStr, p_pidStr, strlen(p_pidStr))) {
            printf("memcmp p_pidStr different. set kv: %s\r\n", p_pidStr);
            aos_kv_set("linkkit_product_id", p_pidStr, strlen(p_pidStr), 1);
        }
    }
}
#endif

void test_hf_at_cmd()
{
	char rsp[64] = {0};
	
	hfat_send_cmd("AT+UART\r\n",sizeof("AT+UART\r\n"),rsp,sizeof(rsp));

	LOG("-------------rsp = %s \r\n",rsp);
	if(0 != strcmp("+ok=9600,8,1,none,nfc",rsp))
	{
		hfat_send_cmd("AT+UART=9600,8,1,NONE,NFC\r\n",sizeof("AT+UART=9600,8,1,NONE,NFC\r\n"),rsp,sizeof(rsp));
	}
}

void set_general_firmware()
{
	extern char m2m_app_state;

	g_hfilop_config.tmod == CONFIG_EVENT_ON;
	m2m_app_state = M2M_STATE_RUN_CMD;
}

const hfproduct_cmd_t user_define_product_cmds_table[]=
{
	{NULL,			NULL} //the last item must be null
};

void hfble_scan_callback(BLE_SCAN_RESULT_ITEM *item)
{
	printf("---------------------\r\n");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\r\n",item->addr[0],item->addr[1],item->addr[2],item->addr[3],item->addr[4],item->addr[5]);
	printf("addr_type = %d,rssi = %d,evtype = %d,len = %d\r\n",item->addr_type,item->rssi,item->evtype,item->len);

	printf("\r\n");
	int i;
	for(i = 0; i < item->len; i++)
		printf("%02x ",item->data[i]);
	printf("\r\n");
	printf("---------------------\r\n");
}

void app_fill_ble_adv_data(void)
{
	// user fill self ble adv data to Advertisement_Data
	extern GAPP_DISC_DATA_T Advertisement_Data;
}

int application_start(int argc, char **argv)
{
	LOG("-----------HiFlying App Entry Start-------------\r\n");

#if (defined (TG7100CEVB))
    //media_to_kv();
#endif

#ifdef CONFIG_PRINT_HEAP
    print_heap();
    aos_post_delayed_action(5000, duration_work, NULL);
#endif

#ifdef CSP_LINUXHOST
    signal(SIGPIPE, SIG_IGN);
#endif

#ifdef WITH_SAL
    sal_init();
#endif

#ifdef MDAL_MAL_ICA_TEST
    HAL_MDAL_MAL_Init();
#endif

#ifdef DEFAULT_LOG_LEVEL_DEBUG
    IOT_SetLogLevel(IOT_LOG_DEBUG);
#else
    IOT_SetLogLevel(IOT_LOG_WARNING);
#endif

    	//����ͨ�õĹ̼�������ע��
	//set_general_firmware();
    g_hfilop_config.tmod = CONFIG_EVENT_OFF;
	
   	show_firmware_version();
    hf_uart_config(115200,0);
	hfilop_uart_task_start(uart_recv_callback, &user_define_at_cmds_table); 	   //?????¡ì2?¡ì?¡ì???
	
   if(strlen(hfilop_layer_get_product_key()) <=0 || strlen(hfilop_layer_get_device_name()) <=0)
   {
	   while(1)
		   aos_msleep(1000);
   }
   else
   {
	   char *name=hfilop_layer_get_device_name();
	   char *key=hfilop_layer_get_product_key();

	   printf("device_name:%s,product_key:%s\r\n", name,key);
   }
   
#ifdef HF_ID2
		gpio_dev_t GPIO4;
		GPIO24.port=4;
		GPIO24.config=OUTPUT_PUSH_PULL;
			
		hal_gpio_init(&GPIO4);
		hal_gpio_output_high(&GPIO4);
#endif

//    set_device_meta_info();
    netmgr_init();
    //lx_wifi_state_reply();
//    vendor_product_init();
    dev_diagnosis_module_init();

#ifdef DEV_OFFLINE_OTA_ENABLE
    ota_init();
#endif

    aos_register_event_filter(EV_KEY, linkkit_key_process, NULL);
    aos_register_event_filter(EV_WIFI, wifi_service_event, NULL);
    aos_register_event_filter(EV_YUNIO, cloud_service_event, NULL);
    IOT_RegisterCallback(ITE_MQTT_CONNECT_SUCC,mqtt_connected_event_handler);

    iotx_event_regist_cb(linkkit_event_monitor);
#ifdef CONFIG_AOS_CLI
    aos_cli_register_command(&resetcmd);
    aos_cli_register_command(&awss_enable_cmd);
    aos_cli_register_command(&awss_dev_ap_cmd);
    aos_cli_register_command(&awss_cmd);
#ifdef EN_COMBO_NET
    aos_cli_register_command(&awss_ble_cmd);
#endif
    aos_cli_register_command(&linkkeycmd);
#endif

	
	
	
    init_awss_flag();

	extern unsigned char hfsys_get_awss_state();
	if(hfsys_get_awss_state() == AWSS_STATE_OPEN)
	{
		hfsys_start_dms();	
	}

#ifdef EN_COMBO_NET
    combo_open();
#endif
	
    hfsys_start_network_status_process();
	
/*    
#if (defined (TG7100CEVB))
    aos_task_new_ext(&task_key_detect, "detect key pressed", key_detect_event_task, NULL, 1024 + 1024, AOS_DEFAULT_APP_PRI);
#else
    aos_task_new_ext(&task_key_detect, "detect key pressed", key_detect_event_task, NULL, 1024, AOS_DEFAULT_APP_PRI);
#endif

    init_msg_queue();
    aos_task_new_ext(&task_msg_process, "cmd msg process", msg_process_task, NULL, 2048, AOS_DEFAULT_APP_PRI - 1);
#ifdef REPORT_MULTHREAD
#if (defined (TG7100CEVB))
    aos_task_new_ext(&task_property_report, "property report", process_property_report_task, NULL, 2048 + 1024, AOS_DEFAULT_APP_PRI);
#else
    aos_task_new_ext(&task_property_report, "property report", process_property_report_task, NULL, 2048, AOS_DEFAULT_APP_PRI);
#endif
#endif
    */

//////////////lx
    init_msg_queue();
    printf("creat_task-msg_process_task\n");
    aos_task_new_ext(&task_msg_process, "cmd msg process", msg_process_task, NULL, 5120, AOS_DEFAULT_APP_PRI - 1);
    //aos_task_new_ext(&task_get_stat, "get state process", get_state_task, NULL, 1024, AOS_DEFAULT_APP_PRI);
    //aos_task_new_ext(&task_printstate, "get state process", print_ota_state, NULL, 1024, AOS_DEFAULT_APP_PRI-2);
///////////////////
    // business_init();

    check_factory_mode();
	
	hfsys_ready_link_gpio_init();//--20181212

	hfsys_device_status_light_timer_create();//--20181212

	hfilop_assis_task_start();
	
    hfilop_check_ota_state();

	
	LOG("-----------HiFlying App Entry End-------------\r\n");
	
    aos_loop_run();

    return 0;
}

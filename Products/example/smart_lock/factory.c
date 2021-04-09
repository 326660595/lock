/*
 *copyright (C) 2015-2018 Alibaba Group Holding Limited
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
#include "vendor.h"
#include "device_state_manger.h"
#include "hal/wifi.h"
#include "factory.h"

// #define FACTORY_TEST_AP_SSID "YOUR_SSID"
// #define FACTORY_TEST_AP_PSW  "YOUR_PASSWORD"
// #define FACTORY_TEST_AP_SSID "U-GEN-606-2.4G"
// #define FACTORY_TEST_AP_PSW  "macro_scope00"
#define FACTORY_TEST_AP_SSID "lx_factory"
#define FACTORY_TEST_AP_PSW  "88888888"


/////////////////产测，返回0成功
//int check_factory = 0;
int lx_factory_find_ap(uint8_t cmd)
{
    /* scan wifi */
    int ret = 0;
    ap_scan_info_t scan_result;
    int ap_scan_result = -1;
    // start ap scanning for default 3 seconds
    memset(&scan_result, 0, sizeof(ap_scan_info_t));
    ap_scan_result = awss_apscan_process(NULL, FACTORY_TEST_AP_SSID, &scan_result);
    switch (cmd)
    {
        case 1://扫描到wifi成功
        {
            if ( (ap_scan_result == 0) && (scan_result.found) ) 
            {
                LOG("[FACTORY]scan factory AP result = %d", scan_result.found);
                int rssi = (scan_result.rssi > 0)?scan_result.rssi : (0 - scan_result.rssi);
                printf("rssi = %d\n",rssi);
                return rssi;
            } 
            else {
                ret = -1;
            }
            break;
        }
        case 2://连接wifi，连接上会发送联网成功指令
        {
            LOG("[FACTORY]s connect wifi\n");
            if(scan_result.rssi < -60)
            {
                return -1;
            }
            netmgr_ap_config_t config;
            strncpy(config.ssid, FACTORY_TEST_AP_SSID, sizeof(config.ssid) - 1);
            strncpy(config.pwd, FACTORY_TEST_AP_PSW, sizeof(config.pwd) - 1);
            netmgr_set_ap_config(&config);
            
            //netmgr_start(true);
            //set_net_state(UNCONFIGED);
            extern int awss_stop(void);
            awss_stop();

            extern void check_factory_mode(void);
            check_factory_mode();
            // netmgr_init();
            // extern int awss_start(void);
            // awss_start();
            //check_factory = 1;
            break;
        }
        /*
        case 3://蓝牙产测
        {
            测wifi就等于硬件RF测试了，没有必要再测蓝牙，如果一定要测蓝牙，可以开发手机的APP，不停的去连接蓝牙（sdk暂时没有该功能）。
        }
        */
        default:
        ret = -1;
    }   
	
    return ret;
}

int scan_factory_ap(void)
{
    /* scan wifi */
    int ret = 0;
    ap_scan_info_t scan_result;
    int ap_scan_result = -1;
    // start ap scanning for default 3 seconds
    memset(&scan_result, 0, sizeof(ap_scan_info_t));
    ap_scan_result = awss_apscan_process(NULL, FACTORY_TEST_AP_SSID, &scan_result);
    LOG("[FACTORY]scan factory AP result = %d", scan_result.found);
	if ( (ap_scan_result == 0) && (scan_result.found) ) {
        enter_factory_mode(scan_result.rssi);
    } else {
        ret = -1;
    }
    return ret;
}

int enter_factory_mode(int8_t rssi)
{
    #ifdef WIFI_PROVISION_ENABLED
    extern int awss_stop(void);
    awss_stop();
    #endif

    /* factory: Don't connect AP */

    /* RSSI > -60dBm */
    if (rssi < -60) {
        LOG("[FACTORY]factory AP power < -60dbm");
        //set_net_state(FACTORY_FAILED_1);
    } else {
        LOG("[FACTORY]meter calibrate begin");
        //set_net_state(FACTORY_BEGIN);
    }

    return 0;
}

int exit_factory_mode()
{
    //need to reboot
}


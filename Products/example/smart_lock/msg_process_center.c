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
#include "smart_lock.h"
#include "vendor.h"
#include "msg_process_center.h"
#include "property_report.h"

#include "business.h"

#define MB_RGBSTATUS_COUNT 10

static aos_queue_t *g_cmd_msg_queue_id = NULL;
static char *g_cmd_msg_queue_buff = NULL;

aos_queue_t *g_property_report_queue_id = NULL;
char *g_property_report_queue_buff = NULL;

// void init_msg_queue(void)
// {
//     if (g_cmd_msg_queue_buff == NULL) {
//         g_cmd_msg_queue_id = (aos_queue_t *) aos_malloc(sizeof(aos_queue_t));
//         g_cmd_msg_queue_buff = aos_malloc(MB_RGBSTATUS_COUNT * sizeof(recv_msg_t));

//         aos_queue_new(g_cmd_msg_queue_id, g_cmd_msg_queue_buff, MB_RGBSTATUS_COUNT * sizeof(recv_msg_t),
//                 sizeof(recv_msg_t));
//     }

//     if (g_property_report_queue_buff == NULL) {
//         g_property_report_queue_id = (aos_queue_t *) aos_malloc(sizeof(aos_queue_t));
//         g_property_report_queue_buff = aos_malloc(MB_RGBSTATUS_COUNT * sizeof(property_report_msg_t));

//         aos_queue_new(g_property_report_queue_id, g_property_report_queue_buff,
//                 MB_RGBSTATUS_COUNT * sizeof(property_report_msg_t), sizeof(property_report_msg_t));
//     }
// }

// void send_msg_to_queue(recv_msg_t * cmd_msg)
// {
//     int ret = aos_queue_send(g_cmd_msg_queue_id, cmd_msg, sizeof(recv_msg_t));
//     if (0 != ret)
//         LOG_TRACE("###############ERROR: CMD MSG: aos_queue_send failed! #################\r\n");
// }

// void msg_process_task(void *argv)
// {
//     uint32_t h, s, v;
//     unsigned int rcvLen;
//     recv_msg_t msg;
//     user_example_ctx_t *user_example_ctx = user_example_get_ctx();
//     device_status_t *device_status = &user_example_ctx->status;

//     while (true) {
//         if (aos_queue_recv(g_cmd_msg_queue_id, AOS_WAIT_FOREVER, &msg, &rcvLen) == 0) {
//             device_status->powerswitch = msg.powerswitch;
//             device_status->all_powerstate = msg.all_powerstate;
//             if (msg.powerswitch == 1) {
//                 product_set_switch(ON);
//             } else {
//                 product_set_switch(OFF);
//             }
//             report_device_property(msg.seq, msg.flag);
//         }
//     }
// }



//////////////////////////////////////////////lx
aos_queue_t cmd_queue;

#define QUEUE_MAX_MSG_SIZE (sizeof(uint8_t) * RECV_UART_DATA_MAXLENGTH)
#define QUEUE_MAX_MSG_COUNT (8)
#define QUEUE_SIZE (QUEUE_MAX_MSG_SIZE * QUEUE_MAX_MSG_COUNT)
char queue_buf[QUEUE_SIZE] = {0};

int cmd_init()
{
    printf("\ncmd_init\n");
    int ret = aos_queue_new(&cmd_queue, queue_buf, QUEUE_SIZE, QUEUE_MAX_MSG_SIZE);
    printf("cmd_init ret = %d \n", ret);
    return ret;
}

int cmd_data_in(void *cmd, uint32_t size)
{
    printf("good");
    int ret = aos_queue_send(&cmd_queue, cmd, size);
    return ret;
}

int cmd_recv(char *recv, uint32_t *recv_size)
{
    return aos_queue_recv(&cmd_queue, 0, recv, recv_size);
}

void cmd_deinit(void)
{
    return aos_queue_free(&cmd_queue);
}

void init_msg_queue(void)
{
    cmd_init();
}

void send_msg_to_queue(recv_msg_t * cmd_msg)
{
    int ret = aos_queue_send(g_cmd_msg_queue_id, cmd_msg, sizeof(recv_msg_t));
    if (0 != ret)
        LOG_TRACE("###############ERROR: CMD MSG: aos_queue_send failed! #################\r\n");
}
extern bool lx_blue_open;
void msg_process_task(void *argv)
{
    aos_msleep(50);
    business_init();
    uint8_t serial_recv_data[RECV_UART_DATA_MAXLENGTH];
    uint32_t serial_recv_len;
    printf("--------------msg_process_task--------aab---------");
    while (1)
    {
        cmd_recv(serial_recv_data, &serial_recv_len);
        if (serial_recv_len != 0)
        {
            lx_uart_recv_handle(serial_recv_data, serial_recv_len);
        }
        aos_msleep(200);
        if(lx_blue_open&&(!lx_blue_state()))
        {
            blue_open();
        }
    }
    aos_task_exit(0);
}
/*
extern void print_time(void);
void get_state_task(void *argv)
{
    printf("\n--------------get_state_task-----------------\n");
    while (1)
    {
        aos_msleep(BATH_UNCONFIGED_GET_STATE_TIME);
        print_time();
        // if(bath_get_wifi_state() == 3)//在配网状态5s下发一次查询指令，其它30s；
        // {
        //     aos_msleep(BATH_UNCONFIGED_GET_STATE_TIME);
        // }
        // else
        // {
        //     aos_msleep(BATH_GET_STATE_TIME);
        // }
        // start_get_state();
        //print_heap();
    }
    aos_task_exit(0);
}
*/
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <aos/aos.h>
#include <aos/yloop.h>
#include <hal/soc/flash.h>
#include "netmgr.h"
#include "iot_export.h"
#include "iot_import.h"

#include "iot_export_linkkit.h"
#include "linkkit_export.h"
#include "cJSON.h"
#include "aos/kv.h"
#include "iot_export.h"
#include "smart_lock.h"
#include "vendor.h"
#include "device_state_manger.h"
#include "msg_process_center.h"
#include "property_report.h"
//
#include "business.h"
#include "factory.h"
#include "lx_main.h"

#define EXAMPLE_MASTER_DEVID (0)

uint64_t nowtime =0x00;

// #ifdef crc
/*LRC校验*/
uint16_t check_sum(uint8_t *data, uint8_t len)
{
    if( (data == NULL) || (len == 0)) 
        return NULL;
    uint8_t sum = 0x00;
    for(uint8_t i=3;i<len;i++)
    {
        sum += data[i];
    }
    sum = 0x100 - (sum % 0x100);
	LOG_TRACE("check_sum: sum = 0x%x",sum);
    return sum;
}
/*
uint16_t check_sum(uint8_t *data, uint8_t len)
{
    int i=0;
    uint8_t sum_byte = 0x00;
    uint8_t uart_send[50] = {'\0'};
    memcpy(uart_send, data, len);
    for (i=3;i<len;i++)
    {
        sum_byte += uart_send[i];
    }
    sum_byte = 0x100 - sum_byte;
    //sum_byte += 0x01;
	LOG_TRACE("check_sum: sum = 0x%x",sum_byte);
    return sum_byte;
}
*/


/*
//累加和
uint8_t check_sum(void *data, uint8_t len)
{
    int i=0;
    uint8_t sum_byte = 0x00;
    uint8_t uart_send[50] = {'\0'};
    memcpy(uart_send, data, len);
    for (i=3;i<14;i++)
    {
        sum_byte += uart_send[i];
    }
    sum_byte = ~sum_byte;
    // sum_byte = sum_byte;
	printf("check_sum: sum = 0x%x",sum_byte);
    return sum_byte;
}

//CRC_16 校验函数
// uint16_t check_sum(uint8_t *data,uint8_t len)
// {
//   unsigned int tmp_crc_calc=0x0000;
//   unsigned char i,j;
//   for(i=0;i<len;i++)
//   {
//     tmp_crc_calc^=(unsigned int)(a[i]);
//     for(j=0;j<8;j++){
//       if(tmp_crc_calc&0x0001)
//       {
//         tmp_crc_calc>>=1;
//         tmp_crc_calc^=0xA001;
//       }
//       else
//       {
//         tmp_crc_calc>>=1;
//       }
//     }
//   }
//   LOG_TRACE("check_sum is: %x",tmp_crc_calc);
//   return tmp_crc_calc;
// }
*/
extern void lx_unbundling(void);
//初始化
int lock_event_clean(){
    LOG_TRACE("do_awss_reset\n");
    do_awss_reset();//初始化并重启配网
    //lx_unbundling();//只解绑
    return 0;
}

//进入配网
void HAL_lx_start_ap_config(){
    LOG_TRACE("HAL_lx_start_ap_config\n");

    //lock_event_clean();//解除app界面设备
    do_awss_reboot();//不解除app界面设备
}

//打印uart串口数据
int TRACE_BINARY(uint8_t *data, uint32_t len){
	for(int i = 0;i<len;i++){
		printf(" %02x",*(data+i));
	}
    printf("  <end> \n");
    return 0;
}

//4字节大小端转换
uint32_t lx_Conversion_32(uint8_t *data)
{
    if(data == NULL)
    {
        return 0;
    }
	uint32_t ret_32 = 0;

	ret_32 = data[3];
	ret_32 = (ret_32 << 8) + data[2];
	ret_32 = (ret_32 << 8) + data[1];
	ret_32 = (ret_32 << 8) + data[0];
	return ret_32;
}
//HEX 转 ASCII
uint8_t lx_HexToAscii(uint8_t *hex,uint32_t hex_len,uint8_t *ascii )
{
    if( (ascii == NULL) || (hex == NULL) )return 0;
    uint32_t i=0;
    uint8_t hex_temp = 0;
    uint32_t ascii_len = hex_len * 2;
    while(i < ascii_len)
    {
        //每两字节ASCII，取一字节HEX
        if( (i % 2) == 0x00 )
        {
            hex_temp = hex[i/2];
        }
        //判断高4位
        if(hex_temp <= 0x9F)
        {
            ascii[i] = ((hex_temp >> 4) & 0x0F) + '0';

        }else if( (hex_temp >= 0xA0) && (hex_temp <= 0xFF) )
        {
            ascii[i] = ((hex_temp >> 4) & 0x0F) - 0x0A + 'A';
        }
        hex_temp <<= 4; //取高四位
        i++;
    }
    return i;
}
//
//ASCII 转 HEX
uint8_t lx_AsciiToHex(uint8_t *ascii,uint32_t ascii_len,uint8_t *hex )
{
    if( (ascii == NULL) || (hex == NULL) )return 0;
    
    uint32_t i=0;
    while(i < ascii_len)
    {
        //比较ACSII
        if( (ascii[i] >= '0') && (ascii[i] <= '9') )
        {
            hex[i/2] = (hex[i/2] << 4) | (ascii[i] - '0');
        }else if( (ascii[i] >= 'a') && (ascii[i] <= 'f')  )
        {
            hex[i/2] = (hex[i/2] << 4) | ( (ascii[i] - 'a') + 0x0A );
        }else if( (ascii[i] >= 'A') && (ascii[i] <= 'F')  )
        {
            hex[i/2] = (hex[i/2] << 4) | ( (ascii[i] - 'A') + 0x0A );
        }
        else
        {
            return 0;//错误
        }
        i++;   
    }
    printf("lx_AsciiToHex %d\n",TRACE_BINARY(hex,sizeof(hex)));
    return i;
}

void bcd2hex(uint8_t *bcd, uint8_t *hex)
{
	int i;
	for(i = 0; i < 6; i++)
	{
		hex[2 * i] = bcd[i] >> 4;
		if(hex[2 * i] == 0x0F)
			hex[2 * i] = 0xFF;
		hex[(2 * i) + 1] = bcd[i] & 0x0F;
		if(hex[(2 * i) + 1] == 0x0F)
			hex[(2 * i) + 1] = 0xFF;
	}
}
void hex2bcd(uint8_t *hex, uint8_t len)
{
	int i;
	uint8_t temp[6] = {0};
	int odd = len % 2;
	int count = odd ? ((len - 1) / 2) : (len / 2);
	for(i = 0; i < count; i++)
	{
		temp[i] = (hex[2 * i] << 4) | (hex[2 * i + 1]);
	}
	if(odd)
	{
		temp[count] = (hex[len - 1] << 4) | 0x0F;
		for(i = 0; i < (6 - (count + 1)); i++)
		{
			temp[5 - i] = 0xFF;
		}
	}
	else {
		for(i = 0; i < (6 - (count)); i++)
		{
			temp[5 - i] = 0xFF;
		}
	}
	
	memcpy(hex, temp, 6);
}

// char * get_property_name(char *p)//读取属性名返回字符串
// {	
//     char * property_type = NULL;
//     static char buf[80];
//     uint8_t count = 0;
//     int i = 0;
//     while (*p != '\0')	
//     {	
//         if(*p == '"'){
//             count++;
//         }
//         if (count == 2)		
//         {
//             break;
//         }		
//         p++;i++; 	
//     }
//     snprintf(buf,i-1,"%s",p-i+2);
//     property_type = (char *)buf;	
//     printf("the cmd is a:  %s\n",property_type);
//     return property_type;
// }
void lx_check_ota(void)
{
    hfilop_check_ota_state();
}

uint32_t StringToInteger(char *p)//读取属性字符串返回int
{	
    uint32_t value = 0;	
    while (*p != '\0')	
    {	
        if ((*p >= '0') && (*p <= '9'))		
        {			value = value * 10 + *p - '0';		}		
        p++; 	
    }	
    printf("the cmd is a +++++++++++ %d:\n",value);
    return value;
}
//获取属性值
uint32_t get_value(const char *data,const char *property)
{
    if(!strstr(data,property)){
        return 0;
    }
    uint32_t value = 0;
	char * p = strstr(data,property)+strlen(property)+2;
    while ((*p != ',') && (*p != '}'))	
    {	
        if ((*p >= '0') && (*p <= '9'))		
        {			value = value * 10 + *p - '0';		}		
        p++; 	
    }	
    //printf("the cmd is a +++++++++++ %d:\n",value);
    return value;

}
///////////////////////////l获取属性值字符串
char * get_str_value(const char *data,const char *property)
{
	char *password = (char *)aos_malloc(sizeof(char) * 50);
	int count = 0;
	char * p = strstr(data,property)+strlen(property)+4;
    while ((*p != ',') && (*p != '"'))	
    {	
        if (((*p >= '0') && (*p <= '9'))||((*p >= 'A')&&(*p <= 'Z')))		
        {			count++;	}		
        p++; 	
    }	
	snprintf(password,count+2,"%s",p-1-count);
	LOG_TRACE("get_str_value len %d : %s\n",count,password);
    //printf("the cmd is a +++++++++++ %d:\n",value);
    return password;

}
//lrc校验
uint8_t lx_check_cmd(void * uart_recv,uint8_t recv_size){
    uint8_t bath_up_check;
    for (uint8_t i = 3; i < recv_size; i++)
    {
        bath_up_check += *((uint8_t*)uart_recv+i);
        printf("check_value1 is:%x\n",bath_up_check); 

    }
    bath_up_check = 0x100-(bath_up_check%0x100);
    printf("check_value is a:%x\n",bath_up_check); 
    if (bath_up_check!=*((uint8_t*)uart_recv+1))//校验位不对返回0
          return 0;
    return 1;
}

// void ntp_time_reply_l(const char *offset_time) /////云端发送时间戳的提取，通过函数：linkkit_ntp_time_request(ntp_time_reply);
// {
//     char *ntime0 = malloc(sizeof(char) * 11);
//     char *ntime = malloc(sizeof(char) * 11);
//     strncpy(ntime0, offset_time, 10);
//     strncpy(ntime, ntime0, 10);
//     nowtime = atol(ntime);
//     LOG_TRACE("nowtime is = %d",nowtime);
//     free(ntime0);free(ntime);
// }
//请求更新时间戳，会自动和云端同步时间
extern void ntp_timer_update(const char *str);
extern uint64_t local_update_timestamp(void);
uint64_t  sync_timeStamp_tiemr_cb(void)
{
    uint64_t timeStamps = 0;
    uint64_t time = 0;
    if(get_net_state() == CONNECT_CLOUD_SUCCESS)//如果联网，通过网络更新时间
    {
        linkkit_ntp_time_request(ntp_timer_update);
    }
    time = local_update_timestamp();//本地获取时间
    timeStamps = nowtime + time;
    printf("sync_timeStamp_tiemr_cb = %d",(uint32_t)timeStamps);
    return timeStamps;
}
//获取保存的时间
uint64_t * get_timeStamp_tiemr_cb(void){
    return &nowtime;
}
/////////////////////////
//bool LOCK_CHANCHE = false;
//产测,ret等于0产测成功
int lx_pt_start(uint8_t cmd){
    //int ret = scan_factory_ap();
    int ret = lx_factory_find_ap(cmd);
    //printf("\nfactory_test start %d\n",ret);
    return ret;
}	

//获取mac地址
uint8_t * get_mac(void)
{
    printf("get_mac start \n");
    // char mac1[HAL_MAC_LEN];
    // HAL_Wifi_Get_Mac(mac1);//获取wifi mac地址
    // printf("mac1 is a :%s",mac1);
    // TRACE_BINARY(mac1,HAL_MAC_LEN);

    uint8_t info[6];
	char *mac = hfilop_layer_get_mac();   //获取设备mac地址

    TRACE_BINARY(mac,strlen(mac));
    // lx_AsciiToHex(mac,6,mac_buff);
    memcpy(&info,mac,6);
    TRACE_BINARY(info,6);
	// 
    return info;
}
//获取rssi信号强度db
extern int wifi_mgmr_rssi_get(int *rssi);
int lx_get_rssi(void)
{
    printf("lx_get_rssi\n");
    uint8_t wifi_state = get_net_state();
    if(wifi_state == CONNECT_CLOUD_FAILED || wifi_state == CONNECT_CLOUD_SUCCESS || wifi_state == CONNECT_CLOUD_SUCCESSED){
        int ret = 0;
        wifi_mgmr_rssi_get(&ret);
        LOG_TRACE("[FACTORY]scan factory AP result = %d", ret);
        return -ret;
    }else{
        return 120;
    }

}
//写flash
bool user_data_write_lx_config(const uint8_t *config)
{
    LOG_TRACE("user_data_write_lx_config");
    write_lx_config(config);
    return true;
}
//读flash,接收指针，将数据赋值到指针指向的数据
bool user_data_read_lx_config(uint8_t *config)
{
    LOG_TRACE("user_data_read_lx_config");
    read_lx_config(config);
    return true;
}
/*
/////////////////////////////////////////////////////////上报
void lx_send_property(void){//l

    user_example_ctx_t *user_example_ctx = user_example_get_ctx();
    printf("lx_send_property------->>>>\n");
    char *property_payload = NULL;
    cJSON *root = NULL,*item_csr = NULL;
    uint32_t lock_power =80;

    root = cJSON_CreateObject();//a,b,1 {"a":}
    item_csr = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "power",lock_power);
    cJSON_AddNumberToObject(root, "volume",lock_power);
    //cJSON_AddNumberToObject(root, "doorOpenNotification",0);
    //cJSON_AddStringToObject(root, "unlockedEvent","unlockedEvent");
    // cJSON_AddItemToObject(root, "CommonServiceResponse", item_csr);

    property_payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    cJSON_Delete(item_csr);
    uint8_t res = IOT_Linkkit_Report(user_example_ctx->master_devid, ITM_MSG_POST_PROPERTY,
                    (unsigned char *)property_payload, strlen(property_payload));
    // va_list v1;
    // char *event_id = va_arg(v1, char *);
    // uint8_t res = IOT_Linkkit_TriggerEvent(user_example_ctx->master_devid, event_id, strlen(event_id), (unsigned char *)property_payload, strlen(property_payload));

    example_free(property_payload);
    //printf("good\n");

}
*/
//发送uart指令
int lx_uart_send(unsigned char *data, int len){
    LOG_TRACE("lx_uart_send : \n");
    TRACE_BINARY(data,len);
    lx_blue_send_cmd(data,len);
    return hfilop_uart_send_data(data,len);
}

/////////////////接收属性名和值，上报
uint8_t set_property(char * name,uint32_t value)// //
{
    LOG_TRACE("++++++========= set_property  ====%d =======+++++++++++++++",value);
    char *Value = (char *)aos_malloc(sizeof(char) * 20);
    memset(Value, 0, 20);
    snprintf(Value, 20, "#%d", value); 
    uint8_t ret = ali_cloud_send(lx_PROPERTY_UP, 2,name,Value); 
    aos_free(Value);
    return ret;
}
//将数字转化为ali_cloud_send接收的字符串
char * change_value(uint32_t value)
{
    char *Value = (char *)aos_malloc(sizeof(char) * 20);//使用结束需free指针
    memset(Value, 0, 20);
    snprintf(Value, 20, "#%d", value);
    return Value;
}
// char * change_value(uint32_t value){
//     char * res = NULL;
//     static char buf[80];
//     snprintf(buf,79,"%s%d","#",value);
//     buf[79]=0;
//     res = (char *)buf;
//     printf(" value is : %s\n",res);
//     return res;
// }

//上报属性和事件
int ali_cloud_send(int function_type, int arg_num, ...)//第一个参数是上报数据类型，第二个是函数会入参的个数，后面填入上报的参数
{
    LOG_TRACE("ali_cloud_send start ----------->\n");
    if(&function_type == NULL || function_type < lx_MIN || function_type > lx_MAX || arg_num < 1)
    {
        LOG_TRACE("Invalid Prameters!");
        return -1;
    }
    
    cJSON *root, *sub;
    root = cJSON_CreateObject();
    sub = cJSON_CreateObject();
    int res = 0;
    int count = 0;
    int complex_flag = 0;

    user_example_ctx_t *user_example_ctx = user_example_get_ctx();

    char *property_payload = "NULL";
    char *event_id = "0";
    char *event_payload = "NULL";

    va_list vl;
    va_start(vl, arg_num);

    char *str1 = "NULL";
    char *str2 = "NULL";
    count = 0;
    complex_flag = 0;

    switch (function_type) {
        case lx_PROPERTY_UP:
            if(arg_num % 2 == 1)
            {
                complex_flag = 1;
                arg_num--;
                cJSON_AddItemToObject(root, va_arg(vl, char *), sub);
            }
            while(count < arg_num / 2)
            {
                str1 = va_arg(vl, char *);
                str2 = va_arg(vl, char *);
                if(strstr(str2, "#"))
                {
                    if(complex_flag == 1)
                    {
                        cJSON_AddNumberToObject(sub, str1, atoi(str2 + 1));
                    } else {
                        cJSON_AddNumberToObject(root, str1, atoi(str2 + 1));
                    }
                } else {
                    if(complex_flag == 1)
                    {
                        cJSON_AddStringToObject(sub, str1, str2);
                    } else {
                        cJSON_AddStringToObject(root, str1, str2);
                    }
                }
                count++;
            }
            property_payload = cJSON_Print(root);
            printf("property_payload is :%s",property_payload);
            break;

        case lx_EVENT_UP:
            event_id = va_arg(vl, char *);
            arg_num--;
            while(count < arg_num / 2)
            {
                str1 = va_arg(vl, char *);
                str2 = va_arg(vl, char *);
                if(strstr(str2, "#"))
                {
                    cJSON_AddNumberToObject(root, str1, atoi(str2 + 1));
                } else {
                    cJSON_AddStringToObject(root, str1, str2);
                }
                count++;
            }
            event_payload = cJSON_PrintUnformatted(root);
            printf("event_payload is :%s",event_payload);
            break;
    }  
    va_end(vl);
    if(complex_flag == 0)
    {
        cJSON_Delete(sub);
    }
    cJSON_Delete(root);
///////////////////////////
    switch (function_type) {
        case lx_PROPERTY_UP:
            res = IOT_Linkkit_Report(user_example_ctx->master_devid, ITM_MSG_POST_PROPERTY, (unsigned char *)property_payload, strlen(property_payload));
            LOG_TRACE("Post Property Message ID: %d\n", res);
            aos_free(property_payload);
            return res;

        case lx_EVENT_UP:
            res = IOT_Linkkit_TriggerEvent(user_example_ctx->master_devid, event_id, strlen(event_id), (unsigned char *)event_payload, strlen(event_payload));
            LOG_TRACE("Post Event Message ID: %d\n", res);
            aos_free(event_payload);
            return res;

        default: 
            return -1;
    }
}
int32_t app_post_event_Error_l(void)
{
	LOG_TRACE("app_post_event_Error_l---------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    int32_t res_l = -0x100;
    char *event_id = "doorOpenNotification";
    char event_payload[64] = {0};

    res_l = HAL_Snprintf(event_payload, sizeof(event_payload), "{\"userId\":1,\"lockType\":1,\"userLimit\":1}");
    if (res_l < 0)
    {
        return -0x10E;
    }

    res_l = IOT_Linkkit_TriggerEvent(EXAMPLE_MASTER_DEVID, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    return res_l;
}

/****************************** include **********************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <aos/aos.h>
#include <aos/yloop.h>
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

//#include "business.h"

#include "lx_main.h"
#include "lx_crypt.h"
#include "lock.h"
// #include "rec_define.h"

#include "device_state_manger.h"

//static uint8_t rouse_reply(uint8_t *data, uint32_t len);		/* 唤醒应答 */
static uint8_t start_prov(uint8_t *data, uint32_t len);			/* 配网  */
static uint8_t model_reset(uint8_t *data, uint32_t len);		/* 初始化 */
static uint8_t time_calibration(uint8_t *data, uint32_t len);	/* 时间校准 */
static uint8_t start_pt(uint8_t *data, uint32_t len);	/* 产测 */
static uint8_t system_cfg(uint8_t *data, uint32_t len);	/* 系统配置 */
static uint8_t get_device_info(uint8_t *data, uint32_t len);	/* 获取设备信息 */

static uint8_t openDoor_report(uint8_t *data, uint32_t len);	//开门通知
static uint8_t event_report(uint8_t *data, uint32_t len);		//事件上报
static uint8_t state_report(uint8_t *data, uint32_t len);		//状态信息通知
static uint8_t keys_report(uint8_t *data, uint32_t len);		//钥匙信息通知
static uint8_t scode_report(uint8_t *data, uint32_t len);		//安全码上报
static uint8_t del_key_report(uint8_t *data, uint32_t len);	//删除钥匙


static uint8_t modeSet_reply(uint8_t *data, uint32_t len);		//模式设置回复
static uint8_t keysManage_reply(uint8_t *data, uint32_t len);	//钥匙管理回复
static uint8_t ciphertext_reply(uint8_t *data, uint32_t len);	//密文上报
static uint8_t get_admin_reply(uint8_t *data, uint32_t len);	//获取管理员密码
static void report_error_event(uint8_t error_code);						//错误事件上报



/****************************** global variable **********************************/

//临时密码暂存
static uint8_t *temp_attr_type = NULL;
static uint8_t *temp_password = NULL;
static uint8_t temp_password_len = 0;

static uint8_t post_tid = NULL;//去重

volatile uint8_t g_cipher_type = 1;

void business_init(void){
	// user_data_write_lx_config(&g_cipher_type);
	user_data_read_lx_config(&g_cipher_type);
	LOG_TRACE("business_init read g_cipher_type is:%d\n",g_cipher_type);
	g_cipher_type = (g_cipher_type)? 1:0;
	
	uint8_t reply_msg[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(reply_msg)-3),DEVICE_PROV,0x01};//模块启动完成
	//reply_msg[4] = 0x05;
	//计算校验
	reply_msg[1] = check_sum(reply_msg,sizeof(reply_msg));
	lx_uart_send(reply_msg,sizeof(reply_msg) );
	//rouse_reply(NULL, 0); //唤醒回应（预留）
}


//钥匙参数
typedef struct lock_key_parameter
{
	uint8_t key_id;		//ID
	uint8_t key_limit;		//权限
	uint8_t key_type;		//类型
	uint8_t key_period;	//周期
	uint32_t key_start_time;	//生效时间
	uint32_t key_expired_time;	//失效时间
	uint16_t key_active_time;	//每日生效时间
	uint16_t key_inactive_time;	//每日失效时间

	uint8_t temp_pw[8];			//临时密码
	uint8_t temp_len : 0x08;	//临时密码长度
	uint8_t temp_time : 0x05;	//临时密码时效 unit：minute
	uint8_t admin_pw[8];		//管理密码
	uint8_t admin_len : 0x08;	//管理密码长度
}lock_key_t;

//钥匙操作指令
typedef struct lock_cmd_key
{
	uint16_t attr_flag;	//用户操作标识:添加钥匙、删除钥匙、配置时效、临时密码
	union 
	{
		uint8_t key_manage[21];		//钥匙设置
		uint8_t key_temp[20];		//临时密码添加
		uint8_t validate_admin[20];	//安全验证
	}key_cmd_u;

}lock_cmd_key_t;

//钥匙指令初始化
static lock_cmd_key_t key_cmd = {
	.attr_flag = 0xFFFF,	//用户操作标识:添加钥匙、删除钥匙、配置时效、临时密码
	.key_cmd_u = {MODEL_CMD_HEAD,0xFF},
};

DLPS_ctrl_flag_t dlps_ctrl_flag = {
	.rouse_msg_flag = true,
	.rouse_pin_flag = true,
	.cloud_msg_flag = true,
	.start_prov_flag = true
};

static lock_key_t key_para = {0};	//钥匙参数

//uart回调函数
static lx_cmd_device_table_t cmd_device_table[] = {
	{DEVICE_ROUSE_REPLY,rouse_reply},		/* 唤醒应答 */
	{DEVICE_PROV,start_prov},				/* 配网  */
	{DEVICE_RESET,model_reset},				/* 初始化 */
	{DEVICE_TIME_CHECK,time_calibration},	/* 时间校准 */
	{DEVICE_PT,start_pt},				//产测//l
	{DEVICE_CFG,system_cfg},								/* 系统配置 */
	{DEVICE_INFO,get_device_info},								/* 设备信息 */

	{DEVICE_OPEN_DOOR,openDoor_report},		//开门通知
	{DEVICE_EVENT_REPORT,event_report},		//事件上报
	{DEVICE_STATE_REPORT, state_report},	//状态信息通知
	{DEVICE_KEYS_REPORT, keys_report},		//钥匙信息通知
	{DEVICE_SCODE_REPORT,scode_report},	// 安全码上报
	{DEVICE_DEL_KEY_REPORT, del_key_report},//删除钥匙
	
	// {DEVICE_KEY_CHECK,keyCheck_reply},	//密码验证回复
	{DEVICE_STATE_SET,state_report},	//模式设置回复(与状态上报参数相同)
	{DEVICE_KEYS_MANAGE,keys_report},	//钥匙管理回复
	{DEVICE_TEMP_KEY,ciphertext_reply},	//设置临时密码回复
	{DEVICE_AUTH_PW,ciphertext_reply},	//安全认证回复
	{DEVICE_GET_ADMIN,			get_admin_reply},	// 获取管理员密码
	{DEVICE_AUTH_CODE,			ciphertext_reply},	// 安全验证码
	{DEVICE_TEMP_CODE,			NULL},	// 下发临时密码
	
	/** must be at the end */
    {0xFF,NULL}
};

//云端指令回调函数


uint8_t ACK[5] = {MODEL_CMD_HEAD,0x00,0x02,0xFF,0x01};
uint8_t ack_true[5] = {MODEL_CMD_HEAD,0x00,0x02,0xFF,0x01};
uint8_t ack_false[5] = {MODEL_CMD_HEAD,0x00,0x02,0xFF,0x02};
//static bool reset_flag = false;//mesh_node_reset 会触发prov_cb 这个时候不应该返回设备绑定状态
#define ACK_TRUE	lx_uart_send(ack_true, sizeof(ack_true) )
#define ACK_FALSE	lx_uart_send(ack_false, sizeof(ack_false) )
void lx_uart_reply(int res)
{
    printf("res---%d---",res);
    if(res)
    {
		ACK_TRUE;
    }
    else
    {
       ACK_FALSE;
    }
}	



/****************************** function body **********************************/
/*
//唤醒引脚拉低，至少延时20ms
void rouse_control_entry(void)
{	
	//LOG_TRACE("OUT_LOW %u",plt_time_read_ms() );
	// lock_io_rouse_pin_out(PAD_OUT_LOW);
	// plt_delay_ms(20);
	// lock_io_rouse_pin_out(PAD_OUT_HIGH);
	//LOG_TRACE("OUT_HIGH %u",plt_time_read_ms() );
}

//唤醒引脚拉高
void rouse_control_exit(void)
{
	// plt_delay_ms(20);
	// lock_io_rouse_pin_out(PAD_OUT_HIGH);
}
*/
/*********************** uart handle ************************/



//唤醒应答
uint8_t rouse_reply(uint8_t *data, uint32_t len)
{
	LOG_TRACE("rouse_reply");
	uint8_t reply_msg[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(reply_msg)-3),DEVICE_ROUSE_REPLY,0x01};
	//reply_msg[4] = 0x05;
	//计算校验
	reply_msg[1] = check_sum(reply_msg,sizeof(reply_msg));
	lx_uart_send(reply_msg,sizeof(reply_msg) );
	return 0;
}

//配网状态回复
void lx_wifi_state_reply(void)
{
    LOG_TRACE("lx_wifi_state_reply\n");
	uint8_t reply_msg[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(reply_msg)-3),DEVICE_PROV,0x03};
	switch (get_net_state())
	{
	case CONNECT_CLOUD_FAILED:
		blue_open();
		reply_msg[4] = 0x06;
		break;

	case CONNECT_CLOUD_SUCCESSED:
		reply_msg[4] = 0x03;
		break;

	case CONNECT_CLOUD_SUCCESS:
		blue_open();
		reply_msg[4] = 0x05;
		break;

	case UNCONFIGED:
		reply_msg[4] = 0x02;
		break;

	default:
		//未知状态
		return 0;
	}
	//计算校验
	reply_msg[1] = check_sum(reply_msg,sizeof(reply_msg));
	lx_uart_send(reply_msg,sizeof(reply_msg) );
	return 0;
}


//配网
extern int awss_clear_reset(void);
uint8_t start_prov(uint8_t *data, uint32_t len)
{
	LOG_TRACE("start_prov");

	HAL_lx_start_ap_config();//重新配网
	
	return 0;
}

//初始化
uint8_t model_reset(uint8_t *data, uint32_t len)
{
	LOG_TRACE("model_reset\n");
	uint8_t reply_msg[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(reply_msg)-3),DEVICE_RESET,0x01};
	//reset_flag = true;
	reply_msg[1] = check_sum(reply_msg,sizeof(reply_msg));
	lx_uart_send(reply_msg,sizeof(reply_msg) );
	lock_event_clean();//清除配网信息并重启模组
	return 0;
}

//时间校准
static time_t time_calibration_do_time = 0;
static int time_calibration_time_out = 5*1000;
uint8_t time_calibration(uint8_t *data, uint32_t len)
{
	LOG_TRACE("time_calibration: data");
	TRACE_BINARY(data,len);
	uint8_t cmd_msg[10] = { MODEL_CMD_HEAD,0xFF,(sizeof(cmd_msg)-3),DEVICE_TIME_CHECK};
	uint64_t timeStamp = sync_timeStamp_tiemr_cb();
	cmd_msg[4]=(timeStamp&0xFF000000)>>24;
    cmd_msg[5]=(timeStamp&0x00FF0000)>>16;
    cmd_msg[6]=(timeStamp&0x0000FF00)>>8;
    cmd_msg[7]=(timeStamp&0x000000FF);
	cmd_msg[8] = 0x08;
    cmd_msg[1]= check_sum(cmd_msg,sizeof(cmd_msg));
	lx_uart_send( cmd_msg, sizeof(cmd_msg) );

	return 0;
}



//产测
uint8_t start_pt(uint8_t *data, uint32_t len){
	LOG_TRACE("start_pt:\n");
	
	uint8_t rouse_msg[5] = {MODEL_CMD_HEAD, 0xFF, sizeof(rouse_msg)-3, DEVICE_PT, 0x00};
    int ret = lx_pt_start(1);
    if(ret == 0){
        rouse_msg[4] = 0x01;
    }
	rouse_msg[1] = check_sum(rouse_msg, sizeof(rouse_msg) );
    lx_uart_send(rouse_msg,sizeof(rouse_msg));
	return 0;
}

/////////////////////接收保存配置信息
uint8_t system_cfg(uint8_t *data, uint32_t len){
		LOG_TRACE("get_device_info: %d\n",data[5]);
		uint8_t rouse_msg[5] = {MODEL_CMD_HEAD, 0xFF, sizeof(rouse_msg)-3, DEVICE_CFG, 0x01};
		g_cipher_type = data[5];
		// uint8_t config[4] = {0}; 
		// memcpy(config,&data[5],1);
		user_data_write_lx_config(&g_cipher_type);//将g_cipher_type写入flash每次开机读取；
		rouse_msg[1] = check_sum(rouse_msg, sizeof(rouse_msg) );
		lx_uart_send(rouse_msg,sizeof(rouse_msg));
}
void gap_get_param(uint8_t *version)//获取版本号
{
	printf("gap_get_param \n");
    version[0] = LOCK_VERSION_UART;
    lx_AsciiToHex(LOCK_VERSION,strlen(LOCK_VERSION),version + 1);   
}
uint8_t get_device_info(uint8_t *data, uint32_t len){
	uint8_t info[11] = {MODEL_CMD_HEAD, 0xFF, sizeof(info)-3, DEVICE_INFO, 0x01};
	LOG_TRACE("get_device_info: \n");
	uint8_t * mac = (uint8_t *)hfilop_layer_get_mac();   //获取设备mac地址
	memcpy(&info[5],mac,6);
	TRACE_BINARY(info,11);
	info[1] = check_sum(info, sizeof(info) );
	lx_uart_send(info,sizeof(info));
}
uint8_t aes_key[16];
//获取管理员密码
uint8_t get_admin_reply(uint8_t *data, uint32_t len)
{
	LOG_TRACE("get_admin_reply:");
	TRACE_BINARY(data,len);
	if(temp_password == NULL || temp_password_len == NULL || temp_attr_type == NULL){
		printf(" temp_attr_type =%s;;temp_password_len =%d",temp_attr_type,temp_password_len);
		return 0;

	}
	
	uint8_t cmd_temp_code[11] = {MODEL_CMD_HEAD, 0x00, (sizeof(cmd_temp_code) - 3) };
	uint8_t admin[12] = {0};
	bcd2hex(data + 4, admin);
	LOG_TRACE("get_admin_reply admin: %d", TRACE_BINARY(admin,12) );
	generate_aes_key(admin);//设置aes key
	cmd_temp_code[3] = DEVICE_TEMP_CODE;
	LOG_TRACE("lx_aes_decrypt type: %x, action:%x", temp_attr_type, cmd_temp_code[3]);
	uint8_t hex_arr[16] = {0};
	uint8_t text_len = data[0] - 2;

	//char *password = get_str_value(temp_password,ALI_LOCK_TEMP_PW);
	// char *password =malloc(sizeof(char) * 50);
	char *password = (char *)temp_password;

	lx_AsciiToHex( (password+2), temp_password_len-2 ,hex_arr);
	LOG_TRACE("lx_aes_decrypt before hex_arr: %d", TRACE_BINARY(hex_arr,16) );
	lx_aes_decrypt(hex_arr);
	LOG_TRACE("lx_aes_decrypt after hex_arr: %d", TRACE_BINARY(hex_arr,16) );

	
	//返回给云设置成功标识位
	uint8_t report_code = 1;
	uint8_t yh = 0;
	uint8_t yh_len = hex_arr[0];
	if(yh_len < 13){
		uint8_t need_yh = hex_arr[yh_len+1];
		for(int i = 1;i<=yh_len;i++){
				yh = yh ^ hex_arr[i];
		}
		LOG_TRACE("lx_aes_decrypt check yh: %d, need:%d", yh, need_yh);
		if(yh != need_yh){
			report_code = ERROR_DECODE_FAIL;
		}
	}else{
		report_code = ERROR_DECODE_FAIL;
	}
	if(report_code == 1){
		if(strstr(temp_attr_type,ALI_LOCK_TEMP_PW)){
			cmd_temp_code[4] = hex_arr[1];
			hex2bcd(hex_arr + 2, hex_arr[0] - 1);
			LOG_TRACE("hex2bcd hex_arr: %d", TRACE_BINARY(hex_arr,16) );
			memcpy((cmd_temp_code + 5), hex_arr + 2, 6);
			cmd_temp_code[1] = check_sum(cmd_temp_code, sizeof(cmd_temp_code) );
			lx_uart_send(cmd_temp_code, sizeof(cmd_temp_code));	//发送临时密码指令
		}else{
			LOG_TRACE("send_secure_cmd\n");
			uint8_t cmd_scode[8] = {MODEL_CMD_HEAD, 0x00, (sizeof(cmd_scode) - 3) };
			cmd_scode[3] = DEVICE_AUTH_CODE;
			memcpy((cmd_scode+4), hex_arr + 1, 4);
			cmd_scode[1] = check_sum(cmd_scode, sizeof(cmd_scode) );
			lx_uart_send(cmd_scode, sizeof(cmd_scode));	//发送安全码指令
		}
	}

	LOG_TRACE("lx_aes_decrypt before td %s", temp_password);
	char trans[60];
	snprintf(trans,"%s",temp_password,34);
	trans[1] = '1';
	printf("report_code  >. %d\n",report_code);
	snprintf(password,"%s",trans,34);
	LOG_TRACE("lx_aes_decrypt after td %s", password);

	if(strstr(temp_attr_type,ALI_LOCK_TEMP_PW) || report_code != 1){
		printf("ALI_LOCK_TEMP_PW\n");
		ali_cloud_send(lx_PROPERTY_UP,2,ALI_LOCK_TEMP_PW,password);
	}else if(strstr(temp_attr_type,ALI_LOCK_VALIDATE_PW) || report_code != 1){
		//ali_cloud_send(lx_PROPERTY_UP,2,ALI_LOCK_TEMP_PW,password);
		printf("ALI_LOCK_VALIDATE_PW\n");	
		ali_cloud_send(lx_PROPERTY_UP,2,ALI_LOCK_VALIDATE_PW,password);
	}
	if(temp_password!=NULL){
		aos_free(temp_password);
		temp_attr_type = NULL;
		temp_password_len = 0;
		LOG_TRACE("aos_free temp_password\n");
	}
	return 0;
}

void scode_uart_reply(uint8_t result)
{
	uint8_t temp_pw[5] = {MODEL_CMD_HEAD, 0x00, 0x02, 0xFF, result};
	temp_pw[1] = check_sum(temp_pw, sizeof(temp_pw));
	lx_uart_send(temp_pw, sizeof(temp_pw));
}
/////////////////////
//开门通知
uint8_t openDoor_report(uint8_t *data, uint32_t len)
{
	LOG_TRACE("openDoor_report-->>%d\n",get_net_state());
	// g_cipher_type = 0;
	// user_data_write_lx_config(&g_cipher_type);
	//开门事件
	if(*(data+7) > 3 || *(data+6) > 9)
	{
		ACK_FALSE;
		return 1;
	}

	//钥匙ID
	char * key_id = change_value(*(data+5));
	//钥匙类型
	char * key_type = change_value(*(data+6));
	//钥匙权限
	char * key_limit = change_value(*(data+7));

	int res = ali_cloud_send(lx_EVENT_UP,7,
							EVENT_OPEN_DOOR,
							ALI_LOCK_USER_LIMIT,key_limit,
							ALI_LOCK_TYPE,key_type,
							ALI_LOCK_USER_ID,key_id);
	aos_free(key_id);aos_free(key_type);aos_free(key_limit);
	lx_uart_reply(res);//回复上报结果
	LOG_TRACE("openDoor_report is :%d",res);
	return 0;
}

//事件上报
uint8_t event_report(uint8_t *data, uint32_t len)
{
	LOG_TRACE("event_report: \n" );
	char * report_msg = NULL;
	// uint8_t report_msg[3] = {0};
	printf("g_cipher_type is %d",g_cipher_type);
	// report_msg[0] = ALI_LOCK_EVENT_TRIGGER >> 8;
	// report_msg[1] = ALI_LOCK_EVENT_TRIGGER & 0x00FF;
	switch (*(data+4))
	{
	case DEV_EVENT_DOORBELL/* 门铃 */:
		report_msg = EVENT_DOORBELL;
		break;
	
	case DEV_EVENT_PRYLOCK/* 防撬报警 */:
		report_msg = EVENT_PRYLOCK;
		break;
	
	case DEV_EVENT_UNLOCKED/* 门未锁报警 */:
		report_msg = EVENT_UNLOCKED;
		break;
	
	case DEV_EVENT_NOTRY/* 禁试报警 */:
		report_msg = EVENT_NOTRY;
		break;
	
	case DEV_EVENT_HIJACK/* 劫持报警 */:
		report_msg = EVENT_HIJACK;
		break;
	
	case DEV_EVENT_LOW_BATTERY/* 低电量报警 */:
		report_msg = EVENT_LOW_BATTERY;
		break;
	case DEV_EVENT_EVENT_DEFENCE/* 布防开门报警 */:
		report_msg = EVENT_DEFENCE;
		break;

	default:
		ACK_FALSE;
		return 1;
	}

	//ali_cloud_send(report_msg, sizeof(report_msg), ACK, sizeof(ACK) );
	int res = ali_cloud_send(lx_EVENT_UP,1,report_msg);
	lx_uart_reply(res);//回复上报结果
	LOG_TRACE("event_report is %s --> %d",report_msg,res);
	return 0;
}


//状态信息上报
uint8_t state_report(uint8_t *data, uint32_t len)
{
	LOG_TRACE("state_report is start --> %x",*(data+5));
	uint8_t cmd_type = *(data+3);
	uint8_t state_type = *(data+4);

	// uint8_t report_msg[3];
	char * report_msg;
	uint32_t value;

	switch (state_type)
	{
	case DEV_STATE_VOLUME/* 音量 */:
		report_msg = ALI_LOCK_VOLUME;
		value = *(data+5);
		break;
	case DEV_STATE_POWER/* 电量 */:
		report_msg = ALI_LOCK_POWER;
		value = *(data+5);
		break;

	case DEV_STATE_LANGUAGE/* 语言  */:
		report_msg = ALI_LOCK_LANGUAGE;
		value = *(data+5);
		break;

	case DEV_STATE_KEYBOARD/* 锁面板开关  */:
		report_msg = ALI_LOCK_KEYBOARD;
		value = *(data+5);
		break;

	case DEV_STATE_AUTO_LOCKED/* 自动上锁  */:
		report_msg = ALI_LOCK_AUTO_LOCKED;
		value = *(data+5);
		break;

	case DEV_STATE_OUT_LOCKED/* 门外上锁  */:
		report_msg = ALI_LOCK_OUT_LOCKED;
		value = *(data+5);
		break;

	case DEV_STATE_INNER/* 反锁状态  */:
		report_msg = ALI_LOCK_INNER_STATE;
		value = *(data+5);
		break;

	case DEV_STATE_DOUBLE_CHECK/* 双重验证  */:
		report_msg = ALI_LOCK_DOUBLE_CHECK;
		value = *(data+5);
		break;

	case DEV_STATE_ARM_MODE/* 门锁布防  */:
		report_msg = ALI_LOCK_ARM_MODE;
		value = *(data+5);
		break;
	case DEV_STATE_OFTEN_OPEN_STATE/* 常开状态  */:
		report_msg = ALI_LOCK_ALWAYS_OPEN;
		value = *(data+5);
		break;
	case DEV_STATE_FORCE_MODE/* 强制模式  */:
		report_msg = ALI_LOCK_FORCE_MODE;
		value = *(data+5);
		break;
	case DEV_STATE_DOORSTATUS/* 门状态  */:
		report_msg = ALI_LOCK_DOORSTATUS;
		value = *(data+5);
		break;

	case DEV_STATE_UNLOCKED_STATUS/* 未锁报警状态  */:
		report_msg = ALI_LOCK_UNLOCKED_STATUS;
		value = *(data+5);
		break;

	case DEV_STATE_UNLOCKED_DT/* 未锁报警延迟时间  */:
		report_msg = ALI_LOCK_UNLOCKED_DT;
		value = *(data+5);
		break;

	case DEV_STATE_NOTRY_STATUS/*禁试报警状态  */:
		report_msg = ALI_LOCK_NOTRY_STATUS;
		value = *(data+5);
		break;

	case DEV_STATE_NOTRY_TC/* 禁试报警触发次数  */:
		report_msg = ALI_LOCK_NOTRY_TC;
		value = *(data+5);
		break;

	case DEV_STATE_NOTRY_RT/* 禁试报警恢复时间  */:
		report_msg = ALI_LOCK_NOTRY_RT;
		value = *(data+5);
		break;

	default:
		ACK_FALSE;
		return 0;
	}

	char * state_value = change_value(value);
	int res = ali_cloud_send(lx_PROPERTY_UP,2,report_msg,state_value);
	aos_free(state_value);
	lx_uart_reply(res);//回复上报结果
	LOG_TRACE("event_report is %s --> %d",report_msg,res);

	// ali_cloud_send(lx_EVENT_UP,7,
	// 						EVENT_OPEN_DOOR,
	// 						ALI_LOCK_USER_LIMIT,"#1",
	// 						ALI_LOCK_TYPE,"#1",
	// 						ALI_LOCK_USER_ID,"#1");

	return 0;
}


//延时上报
#define DELAY_REPORT_TIME	8*1000	//8s
// static plt_timer_t delayReport_Timer = NULL;

static uint8_t delayReport_buf[28] = {0};
static uint32_t delayReport_len = 0;

void delayReport_cb(void * agrv)
{
	LOG_TRACE("delayReport_cb: ciphertext_buf %s",(char *)agrv);
	// if(delayReport_len == 0)
	// {
	// 	LOG_TRACE("delayReport_cb: delayReport_len=%d",delayReport_len);
	// 	memset(delayReport_buf , 0x00, sizeof(delayReport_buf) );
	// 	plt_timer_delete(delayReport_Timer, 0); 
	// 	delayReport_Timer = NULL;
	// 	return ;
	// }

	// ali_cloud_send(delayReport_buf,delayReport_len,NULL,0);
	// memset(delayReport_buf , 0x00, sizeof(delayReport_buf) );
	// delayReport_len = 0;
	// plt_timer_delete(delayReport_Timer, 0); 
	// delayReport_Timer = NULL;
	return ;
}

//钥匙信息通知
uint8_t keys_report(uint8_t *data, uint32_t len)
{
	LOG_TRACE("keys_report:_start\n");
	uint8_t operation = *(data+4);
	uint8_t key_id = *(data+5);
	uint8_t key_type = *(data+6);
	uint8_t key_limit = *(data+7);
	uint8_t key_period = *(data+8);
	uint32_t start_timestamp = lx_Conversion_32(data+9);
	uint32_t stop_timestamp = lx_Conversion_32(data+13);
	uint8_t start_min = 0;
	uint16_t stop_min = 0;

	start_min =*(data+17);

	memcpy( &stop_min, (data+19), sizeof(stop_min) );
	LITTLE_BIG_16(stop_min);

	LOG_TRACE("start_timestamp1");
	LOG_TRACE("start_timestamp2");
	//钥匙ID
	char * user_id = change_value(key_id);
	LOG_TRACE("ALI_LOCK_USER_ID %s",user_id);
	//钥匙权限
	char * user_limit = NULL;
	user_limit =change_value(key_limit);
	LOG_TRACE("ALI_LOCK_USER_LIMIT %s",user_limit);
	//钥匙类型
	char * lock_type = change_value(key_type);
	LOG_TRACE("ALI_LOCK_TYPE %s",lock_type);
	//钥匙周期
	char * lock_cycle = change_value(key_period);
	LOG_TRACE("ALI_LOCK_CYCLE %s",lock_cycle);

	//生效时间
	char * start_time = change_value(start_timestamp);
	LOG_TRACE("ALI_LOCK_START_TIME %s",start_time);
	//失效时间
	char * expired_time = change_value(stop_timestamp);
	LOG_TRACE("ALI_LOCK_EXPIRED_TIME %s",expired_time);
	//开始分钟
	char * active_preday = change_value(start_min);
	LOG_TRACE("ALI_LOCK_ACTIVE_PREDAY %s",active_preday);
	//结束分钟
	char * inactive_preday = change_value(stop_min);
	LOG_TRACE("ALI_LOCK_INACTIVE_PREDAY");

	char * operation_type;
	int res;
	//判断执行操作
	switch (operation)
	{
	case 0x01/* constant-expression */:
		//添加钥匙
		operation_type = EVENT_ADD_KEY;
		break;

	case 0x02/* constant-expression */:
		//更新钥匙
		operation_type = EVENT_KEY_UPDATE;
		break;

	case 0x03/* constant-expression */:
		//删除钥匙
		operation_type = EVENT_DEL_KEY;
		res = ali_cloud_send(lx_EVENT_UP,5,
					operation_type,
					ALI_LOCK_USER_ID,user_id,
					ALI_LOCK_TYPE,lock_type);
		lx_uart_reply(res);//回复上报结果
		return 0;
	default:
		//指令错误
		ACK_FALSE;
		LOG_TRACE("keys_report: operation type ERROR! 0x%x",operation);
		return 1;
	}
		
	LOG_TRACE("start_timestamp8");
	res = ali_cloud_send(lx_EVENT_UP,17,
				operation_type,
				ALI_LOCK_USER_ID,user_id,
				ALI_LOCK_USER_LIMIT,user_limit,
				ALI_LOCK_TYPE,lock_type,
				ALI_LOCK_CYCLE,lock_cycle,
				ALI_LOCK_START_TIME,start_time,
				ALI_LOCK_EXPIRED_TIME,expired_time,
				ALI_LOCK_ACTIVE_PREDAY,active_preday,
				ALI_LOCK_INACTIVE_PREDAY,inactive_preday);

	lx_uart_reply(res);//回复上报结果			
	aos_free(user_id);aos_free(user_limit);aos_free(lock_type);aos_free(inactive_preday);
	aos_free(start_time);aos_free(expired_time);aos_free(active_preday);
	return 0;
}
//安全码上报
uint8_t scode_report(uint8_t *data, uint32_t len){
	LOG_TRACE("scode_report_g_cipher_type %d", g_cipher_type);
	uint8_t temp_buf[17] = {0};
	uint8_t temp_arr[22] = {0};
	uint8_t scode[16] = {0};
	uint8_t checksum;
	char * report_property = ALI_LOCK_VALIDATE_PW;
	
	memset(temp_buf, 0x00, sizeof(temp_buf));
	if(g_cipher_type == 0x01)
	{
		memcpy((temp_arr + 1), &data[4], 4);
		checksum = aes_check_sum(temp_arr + 1, 4);
		for(int i = 0; i < 12; i++)
		{
			temp_arr[i + 5] = checksum;
		}
		memcpy(scode + 1, temp_arr + 1, 15);
		scode[0] = 4;
		LOG_TRACE("scode: %d", TRACE_BINARY(scode, 16) );
		lx_aes_encrypt(scode);
		memcpy(temp_arr + 1, scode, 16);
		memcpy(temp_buf, temp_arr, 17);

	} else if(g_cipher_type == 0x00)
	{
		memcpy(temp_buf, &data[4], 17);
	}
	char *password = (char *)aos_malloc(sizeof(char)*20);
	sprintf(password,"%d",temp_buf);
	LOG_TRACE("scode_report: report_msg ");
	int res = ali_cloud_send(lx_PROPERTY_UP,2,report_property,password);
	lx_uart_reply(res);
	aos_free(password);
}
//删除钥匙
uint8_t del_key_report(uint8_t *data, uint32_t len){
	LOG_TRACE("del_key_report ->\n");
	ACK_TRUE;
}

static uint8_t Ciphertext_buf[48];
static uint8_t Ciphertext_len = 0;

//密文验证回复
uint8_t ciphertext_reply(uint8_t *data, uint32_t len)
{
	LOG_TRACE("ciphertext_reply\n");
	char *report_msg = NULL;	
	uint8_t checksum;
	uint8_t scode[16] = {0};
	uint8_t cmd_type = *(data+3);
	uint8_t cmd_ret = *(data+4);
	uint8_t temp_arr[22] = {0};
	temp_arr[0] = cmd_ret;

	switch (cmd_type)
	{
	case DEVICE_TEMP_KEY /* 一次性密码 */:
		LOG_TRACE("ciphertext_reply DEVICE_TEMP_KEY\n");
		report_msg = ALI_LOCK_TEMP_PW;
		memcpy( (temp_arr+1), (data+5), 16 );
		break;
	
	case DEVICE_AUTH_PW /* 管理认证码 */:
		report_msg = ALI_LOCK_VALIDATE_PW;
		memcpy( (temp_arr+1), (data+5), 16 );
		break;
	
	case DEVICE_AUTH_CODE /* 安全码 */:
		report_msg = ALI_LOCK_VALIDATE_PW;
		memcpy( (temp_arr+1), (data+5), 4 );
		checksum = aes_check_sum(temp_arr+1, 4);
		for(int i = 0; i < 12; i++)
		{
			temp_arr[i + 5] = checksum;
		}
		memcpy(scode + 1, temp_arr + 1, 15);
		scode[0] = 4;
		//LOG_TRACE("scode: %s", TRACE_BINARY(16, scode) );
		lx_aes_encrypt(scode);
		memcpy(temp_arr + 1, scode, 16);
		break;
	
	default:
		//错误类型
		LOG_TRACE("ciphertext_reply: ciphertext cmd type error! 0x%x",cmd_type);
		return 0;
	}

	uint8_t report_temp_arr[37] = {0};
	lx_HexToAscii(temp_arr, 17, report_temp_arr);
	char * report_temp_arr1 = (char *)report_temp_arr;
	char * password = (char *)aos_malloc(sizeof(char)*38);
	sprintf(password,"%s",(char*)report_temp_arr1);

	LOG_TRACE("ciphertext_reply: report_msg %s,value %s",report_msg,report_temp_arr);
	ali_cloud_send(lx_PROPERTY_UP,2,report_msg, password);
	aos_free(password);
	return 0;
}

void report_error_event(uint8_t error_code){
	// uint8_t report_msg[6] = {0};
	//事件触发
	// char * report_msg1 = EVENT_FAILT;	
	// char * report_msg2 = ALI_ERROR_CODE;
	//report_msg[5] = error_code;
	char* error_code_str = change_value(error_code);
	//APP_PRINT_TRACE1("error_report handler send:%s", TRACE_BINARY(sizeof(report_msg), report_msg));
	ali_cloud_send(lx_EVENT_UP,3,EVENT_FAILT,ALI_ERROR_CODE,error_code_str);
	aos_free(error_code_str);
}

static uint8_t uart_check_error_list[3] = {DEVICE_KEY_CHECK,DEVICE_KEYS_MANAGE,DEVICE_TEMP_CODE};
bool error_report(uint8_t *data,uint32_t len){
	LOG_TRACE("error_report handler:");
	TRACE_BINARY(data,len); 
	uint8_t action = data[3];
	bool need_check = false;
	for(int i = 0;i<sizeof(uart_check_error_list);i++){
		if(uart_check_error_list[i] == action){
			need_check = true;
		}
	}
	if(!need_check)
		return true;
	uint8_t value = data[4];
	
	LOG_TRACE("error_report handler vaue:%d,action:%d,data:%d", value,action,data[5]);
	if(value == 1){
		return true;
	}
	uint8_t error_code = 0;

	switch(action){
		case DEVICE_KEY_CHECK:
			error_code = ERROR_PW_INCALID;//无效密码
			break;
		case DEVICE_KEYS_MANAGE:
			switch(value){
				case 0x10:
					error_code = ERROR_ID_INEXISTENCE;// 编号不存在
					break;
				case 0x11:
					error_code = ERROR_KEYS_FULL;// 钥匙满
					break;
				case 0x12:
					error_code = ERROR_ID_EXIST;// 编号已存在
					break;
				case 0x13:
					error_code = ERROR_ID_OUT_RANGE;// 编号超出范围
					break;
				default:
					error_code = ERROR_KEYS_CTL_UNKNOW_FAIL;// 未知错误，操作失败
			}
			break;
		case DEVICE_TEMP_KEY:
		case DEVICE_AUTH_PW:
			switch(value){
				case 0x20:
					error_code = ERROR_DECODE_FAIL;// 解码失败
					break;
				case 0x21:
					error_code = ERROR_CUMUlATIVE;// 累加值异常
				break;default:
					error_code = ERROR_KEYS_CTL_UNKNOW_FAIL;// 未知错误，操作失败
			}
			break;
		case DEVICE_TEMP_CODE:
			error_code = ERROR_TEMP_KEYS_SET_FAIL;//临时密码设置失败
			break;
		default:
			error_code = ERROR_KEYS_CTL_UNKNOW_FAIL;// 未知错误，操作失败
	}
	report_error_event(error_code);
	return false;
}
//uart recv cmd handle
void lx_uart_recv_handle(uint8_t *data, uint32_t len )
{
	LOG_TRACE("lx_uart_recv_handle start len->%d\n",len);
	//TRACE_BINARY(data,len);
	// if(post_tid == NULL){
	// 	post_tid = data[3];
	// }else if(post_tid == data[3]){
	// 	LOG_TRACE("lx_cloud_recv_handle tid repeat");
	// 	return;
	// }else{
	// 	post_tid = data[3];
	// }

	uint8_t data1 = *(data+1);		
	int i = 0;
	uint8_t uart_cmd[32] = {0};
	uint32_t uart_cmd_len = len>32?32:len;

	DeviceCMD_t cmd_data ;
	cmd_data.head = *(data);	//指令头
	cmd_data.check_code = *(data+1);	//校验和
	cmd_data.msg_len = *(data+2);		//指令长度
	cmd_data.type = *(data+3);		//CMD type
	//check head
	if(cmd_data.head != DEVICE_CMD_HEAD )
	{
		ACK_FALSE;
		LOG_TRACE("CMD head error!");
		return ;
	}
	// //check len
	if(cmd_data.msg_len != len-3)
	{
		ACK_FALSE;
		LOG_TRACE("CMD msg len error!");
		return ;
	}
    //check check_code lrc校验判断
	if(cmd_data.check_code != check_sum(data,len) )
	{
		ACK_FALSE;
		LOG_TRACE("CMD check_code error!");
		return ;
	}	
	memcpy(uart_cmd, data, uart_cmd_len);
	if(!error_report(uart_cmd,uart_cmd_len)){
		return;
	}
	//search cmd type
	while(cmd_device_table[i].command != 0xff)
	{
		if(cmd_data.type == cmd_device_table[i].command )
		{
			dlps_ctrl_flag.rouse_msg_flag = false;
			LOG_TRACE("CMD check_code %d",cmd_device_table[i].command);
			if(cmd_device_table[i].lx_cmd_cb != NULL){
				cmd_device_table[i].lx_cmd_cb(uart_cmd, uart_cmd_len);
				dlps_ctrl_flag.rouse_msg_flag = true;
			}
			break;
		}
		i++;
	}
	if(cmd_device_table[i].command == 0xff)
	{
		ACK_FALSE;//未知命令
		LOG_TRACE("CMD check_code not find");
	}
	/**/
    return ;
}



/****************************************** cloud handle ************************************/
typedef enum{
	CMD_ATTR_ADD = 0,	//添加钥匙
	CMD_ATTR_SET = 1,	//修改钥匙
}CMD_Attr_flag_e;

//钥匙管理
uint8_t lock_keys_manage(uint8_t *data, uint32_t len)
{
	LOG_TRACE("lock_keys_manage :\n" );

	int type = 0;
	if(strstr(data,ALI_LOCK_USER_LIMIT))//添加钥匙
	{
		type = 1; 
		key_para.key_id = get_value(data,ALI_LOCK_USER_ID);//用户 id
		key_para.key_type = get_value(data,ALI_LOCK_TYPE);//钥匙类型
		key_para.key_limit = get_value(data,ALI_LOCK_USER_LIMIT);//用户权限
		LOG_TRACE("lock_keys_manage :1\n" );
		key_para.key_period = get_value(data,ALI_LOCK_CYCLE);//生效周期
		key_para.key_active_time = get_value(data,ALI_LOCK_ACTIVE_PREDAY);//每日生效时间
		key_para.key_inactive_time = get_value(data,ALI_LOCK_INACTIVE_PREDAY);//每日失效时间
		key_para.key_start_time = get_value(data,ALI_LOCK_START_TIME);//钥匙生效时间
		key_para.key_expired_time = get_value(data,ALI_LOCK_EXPIRED_TIME);//钥匙失效时间	
		LOG_TRACE("lock_keys_manage :2\n" );
		//判断添加、修改钥匙
		//周期值：0000 0000 第7位为1，修改钥匙；第7位为0，添加钥匙
		if(key_para.key_period >= 0x80)
		{
			//修改钥匙
			key_cmd.key_cmd_u.key_manage[4] = 0x02;	//修改
			key_para.key_period = key_para.key_period & 0x7F;
		}
		else
		{
			//添加钥匙
			key_cmd.key_cmd_u.key_manage[4] = 0x01;	//添加
		}

		key_cmd.key_cmd_u.key_manage[5] = key_para.key_id;
		key_cmd.key_cmd_u.key_manage[6] = key_para.key_type;
		key_cmd.key_cmd_u.key_manage[7] = key_para.key_limit;
		key_cmd.key_cmd_u.key_manage[8] = key_para.key_period;
		//生效时间
		memcpy( (key_cmd.key_cmd_u.key_manage + 9), &key_para.key_start_time, sizeof(key_para.key_start_time) );
		//失效时间
		memcpy( (key_cmd.key_cmd_u.key_manage + 13), &key_para.key_expired_time, sizeof(key_para.key_expired_time) );
		//开始时间
		key_cmd.key_cmd_u.key_manage[17] = key_para.key_active_time >> 8;
		key_cmd.key_cmd_u.key_manage[18] = key_para.key_active_time & 0x00FF;
		//结束时间
		key_cmd.key_cmd_u.key_manage[19] = key_para.key_inactive_time >> 8;
		key_cmd.key_cmd_u.key_manage[20] = key_para.key_inactive_time & 0xFF;
		//组合串口指令
		key_cmd.key_cmd_u.key_manage[2] = sizeof(key_cmd.key_cmd_u.key_manage) - 3;
		key_cmd.key_cmd_u.key_manage[3] = DEVICE_KEYS_MANAGE;
		//计算校验
		key_cmd.key_cmd_u.key_manage[1] = check_sum(key_cmd.key_cmd_u.key_manage, sizeof(key_cmd.key_cmd_u.key_manage) );
		LOG_TRACE("lock_keys_manage :3\n" );
		lx_uart_send(key_cmd.key_cmd_u.key_manage, sizeof(key_cmd.key_cmd_u.key_manage) );	
	}
	else//删除钥匙
	{
		type = 2;
		key_para.key_id = get_value(data,ALI_LOCK_USER_ID);//用户 id
		key_para.key_type = get_value(data,ALI_LOCK_TYPE);//钥匙类型
		LOG_TRACE("lock_keys_delet-->key_id %d ; key_type %d;\n",key_para.key_id ,key_para.key_type );
		key_cmd.key_cmd_u.key_manage[4] = 0x03;
		key_cmd.key_cmd_u.key_manage[5] = key_para.key_id;
		key_cmd.key_cmd_u.key_manage[6] = key_para.key_type;

		memset(key_cmd.key_cmd_u.key_manage + 7, 0xFF, 14);
		//组合串口指令
		key_cmd.key_cmd_u.key_manage[2] = sizeof(key_cmd.key_cmd_u.key_manage) - 3;
		key_cmd.key_cmd_u.key_manage[3] = DEVICE_KEYS_MANAGE;
		key_cmd.key_cmd_u.key_manage[1] = check_sum(key_cmd.key_cmd_u.key_manage, sizeof(key_cmd.key_cmd_u.key_manage) );
		lx_uart_send(key_cmd.key_cmd_u.key_manage, sizeof(key_cmd.key_cmd_u.key_manage) );
	}
	LOG_TRACE("lock_keys_manage :4\n" );
	return 0;
}


////////////////////模式设置///////////////////////////////////
uint8_t cmd_mode_set[6] = {MODEL_CMD_HEAD,0xFF,(sizeof(cmd_mode_set)-3),
								DEVICE_STATE_SET,0x00,0x00};
/////////////////////音量设置
void lock_set_volume(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_OUT_LOCKED\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_VOLUME;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_VOLUME);// 音量
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////语言设置
void lock_set_language(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_LANGUAGE\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_LANGUAGE;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_LANGUAGE);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////反锁状态
void lock_set_inner_state(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_INNER_STATE\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_INNER;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_INNER_STATE);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////门锁布防
void lock_set_arm_mode(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_ARM_MODE\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_ARM_MODE;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_ARM_MODE);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////锁面板开关
void lock_set_keyboard(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_KEYBOARD\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_KEYBOARD;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_KEYBOARD);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////自动上锁
void lock_set_aoto_locked(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_AUTO_LOCKED\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_AUTO_LOCKED;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_AUTO_LOCKED);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////门锁双重验证
void lock_set_double_check(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_DOUBLE_CHECK\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_DOUBLE_CHECK;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_DOUBLE_CHECK);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////门外上锁
void lock_set_out_locked(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_OUT_LOCKED\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_OUT_LOCKED;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_OUT_LOCKED);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}

/////////////////////强制模式
void lock_set_force_mode(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_FORCE_MODE\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_FORCE_MODE;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_FORCE_MODE);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}
/////////////////////常开状态
void lock_set_often_open_state(uint8_t *data,uint8_t len)
{
	LOG_TRACE("ALI_LOCK_OFTEN_OPEN_STATE\n");
	dlps_ctrl_flag.cloud_msg_flag = false;
	cmd_mode_set[4] = DEV_STATE_OFTEN_OPEN_STATE;
	cmd_mode_set[5] = get_value(data,ALI_LOCK_ALWAYS_OPEN);// 
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) );
}


//设置临时密码
uint8_t set_temp_password(char *data,uint8_t len){
	LOG_TRACE("set_temp_password :\n");
	uint8_t hex_arr[16] = {0};
	char *password = get_str_value(data,ALI_LOCK_TEMP_PW);
	if(g_cipher_type == 0){////mcu解密，直接下发密文
		uint8_t cmd_ciphertext[20] = {MODEL_CMD_HEAD, 0x00, (sizeof(cmd_ciphertext) - 3) };
		cmd_ciphertext[3] = DEVICE_TEMP_KEY;
		int count = 0;
		LOG_TRACE("validate_password leen %d : %s\n",count,password);
		lx_AsciiToHex(password+2, strlen(password)-2 ,hex_arr);
		TRACE_BINARY(hex_arr,16);
		memcpy( (cmd_ciphertext+4), hex_arr, sizeof(hex_arr) );
		cmd_ciphertext[1] = check_sum(cmd_ciphertext, sizeof(cmd_ciphertext) );
		lx_uart_send( cmd_ciphertext, sizeof(cmd_ciphertext) );//发送临时密码指令
	} else if(g_cipher_type == 1){//设备解密，请求mcu获取密码
		get_admin_cmd();
		temp_password = (char *)malloc(sizeof(char)*50);//暂存数据等待mcu回应
		temp_attr_type = ALI_LOCK_TEMP_PW;
		snprintf(temp_password,"%s",password);
		temp_password_len = strlen(temp_password);
		printf("temp -- :%s,,%s,,len:%d\n",temp_password,temp_attr_type,temp_password_len);
	}
	aos_free(password);
}
//验证管理员密码
uint8_t validate_password(char *data,uint8_t len){
	LOG_TRACE("validate_password :ALI_LOCK_VALIDATE_PW:%d\n",g_cipher_type);
	//temp_attr_type = ALI_LOCK_VALIDATE_PW;
//{"confirmPassword":"0055DF94BFAA16502F0424924D97952E0F"} --->len 56
	uint8_t hex_arr[16] = {0};
	char *validate_password = get_str_value(data,ALI_LOCK_VALIDATE_PW);
	LOG_TRACE("validate_password : g_cipher_type=%d\n",g_cipher_type);
	if(g_cipher_type == 0){////mcu解密，直接下发密文
		uint8_t cmd_ciphertext[20] = {MODEL_CMD_HEAD, 0x00, (sizeof(cmd_ciphertext) - 3) };
		cmd_ciphertext[3] = DEVICE_TEMP_KEY;
		int count = 0;
		LOG_TRACE("validate_password leen %d : %s\n",count,validate_password);
		lx_AsciiToHex(validate_password+2, strlen(validate_password)-2 ,hex_arr);
		LOG_TRACE("validate_password :2\n");
		memcpy( (cmd_ciphertext+4), hex_arr, sizeof(hex_arr) );
		cmd_ciphertext[1] = check_sum(cmd_ciphertext, sizeof(cmd_ciphertext) );
		lx_uart_send( cmd_ciphertext, sizeof(cmd_ciphertext) );//发送临时密码指令
	} else if(g_cipher_type == 1){//设备解密，请求mcu获取密码
		get_admin_cmd();
		temp_password = (char *)aos_malloc(sizeof(char)*50);
		temp_attr_type = ALI_LOCK_VALIDATE_PW;
		snprintf(temp_password,"%s",validate_password);
		temp_password_len = strlen(temp_password);
		printf("temp -- :%s,,%s,,len:%d\n",temp_password,temp_attr_type,temp_password_len);
	}
	aos_free(validate_password);
	return 0;
}

uint16_t timer_attr_type;
uint8_t *timer_temp;
uint32_t timer_temp_len;

void get_admin_cmd(void)
{
	uint8_t temp_pw[4] = {MODEL_CMD_HEAD, 0x00, 0x01, DEVICE_GET_ADMIN};
	temp_pw[1] = check_sum(temp_pw, sizeof(temp_pw) );
	lx_uart_send(temp_pw, sizeof(temp_pw));
}

//ota
void ota_ack(uint8_t state){
	uint8_t cmd_mode_set[5] = {MODEL_CMD_HEAD,0xFF,(sizeof(cmd_mode_set)-3),
								DEVICE_OTA,0x00};
	cmd_mode_set[4] = state;
	cmd_mode_set[1] = check_sum(cmd_mode_set, sizeof(cmd_mode_set) );
	lx_uart_send(cmd_mode_set,sizeof(cmd_mode_set) ); 
}

static lx_cloud_device_table_t cloud_device_table[] = {
	{ALI_LOCK_OUT_LOCKED,lock_set_out_locked},	/* 门外上锁 */
	{ALI_LOCK_DEL,lock_keys_manage},			/* 删除钥匙 删除锁用户*/
	{ALI_LOCK_TEMP_PW,set_temp_password},				/* 设置临时密码 */
	{ALI_LOCK_VALIDATE_PW,validate_password},/* 验证操作密码  */
	// {ALI_LOCK_USER_LIMIT,lock_keys_manage},	/*  用户权限(钥匙权限)*/
	{ALI_LOCK_TYPE,lock_keys_manage},			/* 开锁方式(钥匙类型)*/
	{ALI_TIME_TYPE_TIME,time_calibration},		/* 时间校准 */

	{ALI_LOCK_VOLUME,lock_set_volume},			/* 音量设置 */
	{ALI_LOCK_LANGUAGE,lock_set_language},		/* 语言设置 */
	{ALI_LOCK_INNER_STATE,lock_set_inner_state},	/* 反锁状态 */
	{ALI_LOCK_ARM_MODE,lock_set_arm_mode},		/* 门锁布防 */
	{ALI_LOCK_KEYBOARD,lock_set_keyboard},		/* 锁面板开关 */
	{ALI_LOCK_AUTO_LOCKED,lock_set_aoto_locked},	/* 自动上锁 */
	{ALI_LOCK_DOUBLE_CHECK,lock_set_double_check},	/* 门锁双重验证 */
	{ALI_LOCK_ADD,lock_keys_manage},			/* 添加钥匙 */
	{ALI_LOCK_ALWAYS_OPEN,lock_set_often_open_state},	/* 常开状态 */
	{ALI_LOCK_FORCE_MODE,lock_set_force_mode},	/* 强制模式 */

	/** must be at the end */
    {ALI_ERROR_CODE,NULL}
};

//cloud recv msg handle
void lx_cloud_recv_handle(uint8_t *data , uint32_t len)
{
	LOG_TRACE("lx_cloud_recv_handle %s --->len %d\n",data,len);

	int i = 0;
	while(!strstr(cloud_device_table[i].command,ALI_ERROR_CODE))
	{

		if(strstr(data,cloud_device_table[i].command) )
		{
			LOG_TRACE("property_good\n");
			if(cloud_device_table[i].lx_cmd_cb == NULL){
				LOG_TRACE("factory is NULL ;property:%s\n",cloud_device_table[i].command);
				return;
			}
			dlps_ctrl_flag.cloud_msg_flag = false;
			cloud_device_table[i].lx_cmd_cb(data,len);
			break;
		}
		i++;
	}
	if(strstr(cloud_device_table[i].command,ALI_ERROR_CODE))
	{
		LOG_TRACE("lx_cloud_recv_handle Not find attr type.\n");
	}
    return ;



}///////////////////

#ifndef _LOCK_BUSINESS_H_
#define _LOCK_BUSINESS_H_

//#include "lock.h"

#define DEVICE_CMD_HEAD     0xD0
#define MODEL_CMD_HEAD      0xD1
#define RECV_UART_DATA_LENGTH 50

#define RECV_UART_DATA_MAXLENGTH 30 //mcu上报下发指令最大长度

#define BATH_GET_STATE_TIME 30000   //下发查询指令时间，配网中为5s，其它为30s
#define BATH_UNCONFIGED_GET_STATE_TIME 5000

typedef struct 
{
    uint8_t head;
    uint8_t check_code;
    uint8_t msg_len;
    uint8_t type;
    uint8_t *cmd_msg;
}DeviceCMD_t;

typedef enum 
{
	CIPHER_TYPE_NONE = 0,
	CIPHER_TYPE_SELF = 1
}Cipher_Type_e;

typedef enum
{
    DEVICE_ROUSE_REPLY = 0x00,  //唤醒回应
    DEVICE_PROV = 0x01,         //配网
    DEVICE_RESET = 0x03,        //初始化
    DEVICE_TIME_CHECK = 0x04,   //时间校准
    DEVICE_PT = 0x05,   				//产测
    DEVICE_OTA = 0x06,   				//OTA
    DEVICE_CFG = 0x07,  				//配置
    DEVICE_INFO = 0x08,  				//获取设备信息

    DEVICE_OPEN_DOOR = 0x81,    //开门通知
    DEVICE_EVENT_REPORT = 0x82, //事件上报
    DEVICE_STATE_REPORT = 0x83, //状态信息通知
    DEVICE_KEYS_REPORT = 0x84,  //钥匙信息上报
    DEVICE_SCODE_REPORT = 0x85,	//安全码上报
    DEVICE_DEL_KEY_REPORT = 0x86,	//删除钥匙
	
	

    DEVICE_KEY_CHECK = 0xA0,    //密码验证
    DEVICE_STATE_SET = 0xA1,    //模式设置
    DEVICE_KEYS_MANAGE = 0xA2,  //钥匙管理
    DEVICE_TEMP_KEY = 0xA3,     //设置临时密码
    DEVICE_AUTH_PW = 0xA4,      //安全认证
    DEVICE_GET_ADMIN = 0xA6,		//获取管理员密码
    DEVICE_AUTH_CODE = 0xA7,		//安全码验证
    DEVICE_TEMP_CODE = 0xA8			//下发临时密码

}Device_Cmd_Type_e;
/**/
typedef enum{
    DEV_EVENT_DOORBELL = 0x01,  //门铃
    DEV_EVENT_PRYLOCK = 0x02,   //防撬报警
    DEV_EVENT_UNLOCKED = 0x03,    //门未锁报警
    DEV_EVENT_NOTRY = 0x04,     //禁试报警
    DEV_EVENT_HIJACK = 0x05,    //劫持报警
    DEV_EVENT_LOW_BATTERY = 0x06,   //低电量报警
    DEV_EVENT_DOWNTIME = 0x07,      //设备宕机
    DEV_EVENT_POWER_ON = 0x08,      //设备上电
    DEV_EVENT_EVENT_DEFENCE = 0x0a,

    DEV_EVENT_MAX
}Device_Event_Type_e;

typedef enum{

    DEV_STATE_VOLUME = 0x01,        // 音量
    DEV_STATE_POWER,                // 电量
    DEV_STATE_LANGUAGE,             // 语言
    DEV_STATE_KEYBOARD,             // 锁面板开关
    DEV_STATE_AUTO_LOCKED,          // 自动上锁
    DEV_STATE_OUT_LOCKED = 0x06,    // 门外上锁
    DEV_STATE_INNER,                // 反锁状态
    DEV_STATE_DOUBLE_CHECK,         // 双重验证
    DEV_STATE_ARM_MODE,             // 门锁布防
    DEV_STATE_OFTEN_OPEN_STATE,     // 常开状态
    DEV_STATE_FORCE_MODE,           // 强制模式

    DEV_STATE_DOORSTATUS = 0xA0,       // 门状态

    DEV_STATE_UNLOCKED_STATUS = 0xA2,  // 未锁报警状态
    DEV_STATE_UNLOCKED_DT,    // 未锁报警延迟时间
    DEV_STATE_NOTRY_STATUS,     // 禁试报警状态
    DEV_STATE_NOTRY_TC,    // 禁试报警触发次数
    DEV_STATE_NOTRY_RT,   // 禁试报警恢复时间

    DEV_STATE_MAXLOCK
}Device_State_Type_e;


void lx_uart_recv_handle(uint8_t *data, uint32_t len );

void lx_cloud_recv_handle(uint8_t *data , uint32_t len);

void rouse_control_entry(void);

void rouse_control_exit(void);

uint8_t rouse_reply(uint8_t *data, uint32_t len);

uint8_t start_prov_reply(uint8_t state);    //发送配网状态

void gap_get_param(uint8_t *version);

//void lx_pt_cb(bool success);		//产测回应

void business_init();

void ota_ack(uint8_t);   //ota回应

void get_admin_cmd(void);					//获取管理员密码

#endif //#ifndef _LOCK_BUSINESS_H_




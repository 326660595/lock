#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define LOCK_VERSION    "0920191201" //固件版本号
#define LOCK_VERSION_HF    0x01     //固件版本号
#define LOCK_VERSION_POWER    0x01 //Power on and off . 0x01:通用锁-通断电0x02:通用锁-串口唤醒
#define LOCK_VERSION_UART    0x02


#define LOCK_NETWORK 0x01           //配网
#define LOCK_RESET 0x03             //复位
#define LOCK_SET_TIME 0x04          //时间
#define LOCK_TEST 0x05              //产测
#define LOCK_ATTRIBUTE 0x12         //属性上报


///////////////////事件列表
// #define ALI_TIME_TYPE_TIME  "unixTime" //UNIX时间
#define ALI_TIME_TYPE_ZONE  0x1EF0, //时区
#define ALI_LOCK_EVENT_TRIGGER  0x09F0,    // 事件触发
#define ALI_LOCK_EVENT_CLEAN  0x19F0,      // 事件清除
#define ALI_ERROR_CODE  "errorCode"        //错误码

//事件 lx_EVENT_UP,
#define EVENT_DOORBELL  "keyClickEvent"  //门铃,按键单击事件
#define EVENT_PRYLOCK "prylockEvent"   //防撬报警
#define EVENT_UNLOCKED "unlockedEvent"    //门未锁报警
#define EVENT_NOTRY "notryEvent"     //禁试报警
#define EVENT_HIJACK "hijackAlarmEvent"    //劫持报警事件
#define EVENT_LOW_BATTERY "lowBatteryEvent"   //低电量报警
#define EVENT_KEY_UPDATE "keyUpdateNotification"   //更新钥匙信息
#define EVENT_ADD_KEY  "keyAddedNotification"     //添加钥匙通知
#define EVENT_FAILT "faultReportEvent"   //故障上报
#define EVENT_DEL_KEY  "keyDelNotification"       //删除钥匙通知
#define EVENT_OPEN_DOOR  "doorOpenNotification"       //开门通知
#define EVENT_DEFENCE  "defenceEvent"       //布防开门报警

#define EVENT_LOCKING  "lockingEvent"       //锁定报警


//属性 lx_PROPERTY_UP
#define ALI_TIME_TYPE_TIME  "unixTime" //UNIX时间

#define ALI_LOCK_AUTO_LOCKED "autoLock"      // 自动上锁
#define ALI_LOCK_DOUBLE_CHECK "lockDoubleCheck"    // 双重验证
#define ALI_LOCK_OUT_LOCKED "outsideLock"      // 门外上锁 outsideLock
#define ALI_LOCK_KEYBOARD "lockPanelOP"         // 锁面板开关
#define ALI_LOCK_ARM_MODE "armMode"        // 门锁布防
#define ALI_LOCK_ALWAYS_OPEN "oftenOpenstate"   // 常开状态
#define ALI_LOCK_FORCE_MODE "forceMode"   // 强制模式
#define ALI_LOCK_INNER_STATE "innerLockState"      // 反锁状态
#define ALI_LOCK_LANGUAGE "language"         // 语言
#define ALI_LOCK_DOORSTATUS "doorStatus"       // 门状态
#define ALI_LOCK_POWER "power"          // 电量
#define ALI_LOCK_VOLUME "volume"        // 音量

#define ALI_LOCK_UNLOCKED_STATUS "unlockAlarm"// 未锁报警状态
#define ALI_LOCK_UNLOCKED_DT "unlockAlarmDT"   // 未锁报警延迟时间
#define ALI_LOCK_NOTRY_STATUS "noTryAlarm"    // 禁试报警状态
#define ALI_LOCK_NOTRY_TC "noTryAlarmTC"   // 禁试报警触发次数
#define ALI_LOCK_NOTRY_RT "noTryAlarmResumeTime"  // 禁试报警恢复时间
#define ALI_LOCK_SLEEP_ONOFF  "sleepOnOff"  // 睡眠功能开关
#define ALI_LOCK_SLEEP_START "sleepStartTime"      //门锁睡眠开始时间
#define ALI_LOCK_SLEEP_END "sleepEndTime"       //门锁睡眠结束时间	

#define ALI_LOCK_TYPE "lockType"   // 开锁方式(钥匙类型)
#define ALI_LOCK_USER_LIMIT "userLimit"   // 用户权限(钥匙权限)
#define ALI_LOCK_USER_ID  "userId"  // 用户账号(钥匙ID)
#define ALI_LOCK_CYCLE  "entryIntoForceTime"    // 生效时间(钥匙周期)
#define ALI_LOCK_ACTIVE_PREDAY "activeTimePerDay"    //每日生效时间
#define ALI_LOCK_INACTIVE_PREDAY "inactiveTimePerDay"  //每日失效时间
#define ALI_LOCK_START_TIME "keyStartTime"   // 钥匙生效时间
#define ALI_LOCK_EXPIRED_TIME "keyExpiredTime" // 钥匙失效时间
#define ALI_LOCK_VALIDATE_PW "confirmPassword"      // 验证操作密码 confirmPassword
#define ALI_LOCK_TEMP_PW "addOTP"          // 添加一次性密码

//服务
#define ALI_LOCK_ADD "addLockUser"      // 添加锁用户(添加钥匙)
#define ALI_LOCK_DEL "deleteKeyType"      // 删除锁用户(删除钥匙) deleteLockUser
#define ALI_LOCK_SET_LIMIT "setUserLimit"    // 配置用户权限(钥匙权限)

//错误码表
typedef enum
{
    ERROR_KEYS_FULL = 190,  // 钥匙满 0xBE
    ERROR_ID_EXIST = 191,   // 编号已存在 0xBF
    ERROR_ID_INEXISTENCE = 192,     // 编号不存在 0xC0
    ERROR_ID_OUT_RANGE = 193,   // 编号超出范围 0xC1
    ERROR_ADD_SET_KEY_FAIL = 194,   //添加钥匙失败 0xC2
    ERROR_DEL_FAIL_SAFE = 195,       //删除失败，为安全模式 0xC3
		ERROR_KEYS_CTL_UNKNOW_FAIL = 196,	//未知错误，操作失败 0xC4
		ERROR_TEMP_KEYS_SET_FAIL = 197,	//临时密码设置失败 0xC5

    ERROR_DECODE_FAIL = 0x20,    // 解码失败 0xC9
    ERROR_CUMUlATIVE = 202, // 累加值异常 0xCA
    ERROR_PW_EASY = 203,    // 简单密码(弱密码) 0xCB
    ERROR_PW_INCALID = 0x20, // 无效密码 0xCC

    ERROR_SAME_TYPE = 210,  // 未添加两种密钥类型(开启安全模式)

}ALI_Lock_Error_e;

typedef struct
{
	bool rouse_msg_flag : true;
	bool rouse_pin_flag : true;
	bool cloud_msg_flag : true;
	bool start_prov_flag;
}DLPS_ctrl_flag_t;

uint32_t Unix_Timestamp;		//校准时间戳
uint32_t Recv_Timestamp_Clock;	//时间戳更新是的系统时钟
uint16_t DeepSleep_Start;		//睡眠开始时间
uint16_t DeepSleep_Stop;		//睡眠结束时间


#ifdef TOUC
/**/
//事件列表
typedef enum
{
    EVENT_FAILT = 0x00,     //故障上报
    EVENT_LOW_BATTERY = 0x01,   //低电量事件
    EVENT_NOTRY = 0x19,     //禁试报警
    EVENT_PRYLOCK = 0x18,   //防撬报警
    EVENT_UNLOCKED = 0x16,  //门未锁好
    EVENT_DOOEBELL = 0x05,  //按键单击事件
    EVENT_ADD_KEY = 0x1E,   //添加钥匙通知
    EVENT_DEL_KEY = 0x1F,   //删除钥匙通知
    EVENT_OPEN_DOOR = 0x20, //开门通知
    EVENT_DEFENCE = 0x21,   //布防开门报警
    EVENT_KEY_UPDATE = 0x22,    //更新钥匙信息
    EVENT_HIJACK = 0x17,    //劫持报警事件

}ALI_Lock_Event_e;



/* mesh lock Attr Code Type*/
typedef enum{
    ALI_TIME_TYPE_TIME = 0x1FF0,    //UNIX时间
    ALI_TIME_TYPE_ZONE = 0x1EF0,    //时区

    ALI_LOCK_EVENT_TRIGGER = 0x09F0,    // 事件触发
    ALI_LOCK_EVENT_CLEAN = 0x19F0,      // 事件清除
    ALI_ERROR_CODE = 0x0000,        //错误码

    //属性
    ALI_LOCK_AUTO_LOCKED = 0x9005,      // 自动上锁
    ALI_LOCK_DOUBLE_CHECK = 0x9105,     // 双重验证
    ALI_LOCK_OUT_LOCKED = 0x9205,       // 门外上锁
    ALI_LOCK_KEYBOARD = 0x8F05,         // 锁面板开关
    ALI_LOCK_ARM_MODE = 0x8705,         // 门锁布防
    ALI_LOCK_ALWAYS_OPEN = 0x0204,      // 常开状态
    ALI_LOCK_INNER_STATE = 0x0304,      // 反锁状态
    ALI_LOCK_LANGUAGE = 0x3601,         // 语言
    ALI_LOCK_DOORSTATUS = 0x0804,       // 门状态
    ALI_LOCK_POWER = 0x0401,            // 电量
    ALI_LOCK_VOLUME = 0x0901,           // 音量

    ALI_LOCK_UNLOCKED_STATUS = 0x9505,  // 未锁报警状态
    ALI_LOCK_UNLOCKED_DT = 0x9605,    // 未锁报警延迟时间
    ALI_LOCK_NOTRY_STATUS = 0x9705,     // 禁试报警状态
    ALI_LOCK_NOTRY_TC = 0x9805,    // 禁试报警触发次数
    ALI_LOCK_NOTRY_RT = 0x9905,   // 禁试报警恢复时间

    ALI_LOCK_SLEEP_ONOFF = 0x0705,  // 睡眠功能开关
    ALI_LOCK_SLEEP_START = 0x9305,      //门锁睡眠开始时间
    ALI_LOCK_SLEEP_END = 0x9405,        //门锁睡眠结束时间

    ALI_LOCK_USER_LIMIT = 0x8905,   // 用户权限(钥匙权限)
    ALI_LOCK_USER_ID = 0x02F0,  // 用户账号(钥匙ID)
    ALI_LOCK_TYPE = 0x8805,     // 开锁方式(钥匙类型)
    ALI_LOCK_CYCLE = 0xA005,    // 生效时间(钥匙周期)
    ALI_LOCK_ACTIVE_PREDAY = 0x9C05,    //每日生效时间
    ALI_LOCK_INACTIVE_PREDAY = 0x9D05,  //每日失效时间
    ALI_LOCK_START_TIME = 0x9E05,   // 钥匙生效时间
    ALI_LOCK_EXPIRED_TIME = 0x9F05, // 钥匙失效时间

    ALI_LOCK_VALIDATE_PW = 0x9A05,      // 验证操作密码
    ALI_LOCK_TEMP_PW = 0x8D05,          // 添加一次性密码

    //服务
    ALI_LOCK_ADD = 0x8A05,      // 添加锁用户(添加钥匙)
    ALI_LOCK_DEL = 0x8B05,      // 删除锁用户(删除钥匙)
    ALI_LOCK_SET_LIMIT = 0x8C05,    // 配置用户权限(钥匙权限)

}ALI_Lock_Attr_e;
#endif



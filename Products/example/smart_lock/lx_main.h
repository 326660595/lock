#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define LITTLE_BIG_16(value)     (((value >> 8) & 0x00FF) | (value & 0xFF00))

#define CUSTOM_LOCK_FIND_SSID       "U-GEN-606-2.4G"     //产测寻找的ssid


//
typedef enum{
    lx_MIN = 1,
    lx_PROPERTY_UP = lx_MIN,
    lx_EVENT_UP,
    lx_MAX
}lx_UPSTREAM_TYPE;

typedef struct 
{
  char * property;
  uint32_t value;
  char * value1;
}property_data;

typedef uint8_t (*lx_cmd_cb_p)(uint16_t *data ,uint8_t len );

typedef struct 
{
    uint8_t command;	//cmd type code
    lx_cmd_cb_p lx_cmd_cb;	//callback function
}lx_cmd_device_table_t;

//typedef uint8_t (*lx_cmd_cb_p)(uint8_t *data ,uint32_t len );
typedef struct 
{
    char * command;	//cmd type code
    lx_cmd_cb_p lx_cmd_cb;	//callback function
}lx_cloud_device_table_t;

uint16_t check_sum(uint8_t *data, uint8_t len);
void HAL_lx_start_ap_config();
int lock_event_clean();
//4字节大小端转换
int TRACE_BINARY(uint8_t *data, uint32_t len);
uint32_t lx_Conversion_32(uint8_t *data);
uint8_t lx_HexToAscii(uint8_t *hex,uint32_t hex_len,uint8_t *ascii );
uint8_t lx_AsciiToHex(uint8_t *ascii,uint32_t ascii_len,uint8_t *hex );
void bcd2hex(uint8_t *bcd, uint8_t *hex);
void hex2bcd(uint8_t *hex, uint8_t len);
uint32_t StringToInteger(char *p);
uint32_t get_value(const char *data,const char *property);
//char * get_property_name(char *p);
//void lx_uart_reply(int res);
char * get_str_value(const char *data,const char *property);

//获取mac地址
uint8_t * get_mac(void);
bool user_data_write_lx_config(const uint8_t *config);
bool user_data_read_lx_config(uint8_t *config);

//获取时间
uint64_t * get_timeStamp_tiemr_cb(void);
// void lx_send_property(void);
int lx_uart_send(unsigned char *data, int len);

//void ntp_time_reply(const char *offset_time);
int lx_pt_start(uint8_t cmd);

uint8_t set_property(char * name,uint32_t value);
char * change_value(uint32_t value);//将数字转化为ali_cloud_send接收的字符串
int ali_cloud_send(int function_type, int arg_num, ...);

int lx_get_rssi(void);
//int32_t app_post_event_Error_l(void);
//void ali_cloud_send(char *type,lx_UPSTREAM_TYPE upstream_type,uint32_t value);
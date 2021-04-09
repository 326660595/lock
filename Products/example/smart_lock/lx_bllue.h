#include <stdint.h>
void blue_init(void);
void blue_disconnect(void);
void blue_open(void);
void blue_close(void);

void blue_send(uint8_t value);
int lx_blue_send_cmd(uint8_t *data,uint8_t len);
void blue_send_1(void);
void blue_restart(void);
uint8_t lx_blue_state(void);
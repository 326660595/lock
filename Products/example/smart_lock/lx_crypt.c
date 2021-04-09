#include "lx_crypt.h"

static uint8_t aes_key[16] = {0x06, 0x01, 0x04, 0x07, 0x01, 0x04, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static int plen = 16;

uint8_t aes_check_sum(void *data, uint32_t len)
{
    int i=0;
    uint8_t sum_byte = 0x00;
    uint8_t uart_send[50] = {'\0'};
    memcpy(uart_send, data, len);
    for (i=0;i<len;i++)
    {
        sum_byte ^= uart_send[i];
    }
    return sum_byte;
}

void generate_aes_key(uint8_t *admin)
{
	memcpy(aes_key + 1, admin, 12);
	
	int i;
	int admin_size = 0;
	for(i = 0; i < 12; i++)
	{
		if(admin[i] == 0xFF)
		{
			break;
		}
		admin_size++;
	}
	aes_key[0] = admin_size;
	uint8_t checksum = aes_check_sum(aes_key + 1, admin_size);
	for(i = 15; i > (admin_size); i--)
	{
		aes_key[i] = checksum;
	}
	printf("generate_aes_key:");
}

void lx_aes_encrypt(_IO_ uint8_t *plain)
{
	aes(plain, plen, aes_key);
}

void lx_aes_decrypt(_IO_ uint8_t *cipher)
{
	deAes(cipher, plen, aes_key);
}
#ifndef BOARD_FBXGW1R_H_
#define BOARD_FBXGW1R_H_

/*
 * board gpios
 */
#define GPIO_OLED_DATA_SELECT	7
#define GPIO_SR_CLK		10
#define GPIO_BCM_DOWN		11
#define GPIO_SR_DIN		12
#define GPIO_TEST_MODE		13
#define GPIO_SFP_TXDIS		14
#define GPIO_SR_LOAD		17
#define GPIO_SW_RESET		28
#define GPIO_SW_INT		29
#define GPIO_SFP_PWRGOOD	34
#define GPIO_SFP_TXFAULT	35
#define GPIO_SPI_CS_BCM		36
#define GPIO_SFP_PRESENCE	37
#define GPIO_SFP_RXLOSS		38
#define GPIO_BOARD_ID_0		43
#define GPIO_EXP_RST		44
#define GPIO_POS_SENSE		45
#define GPIO_EXP_PWRGOOD	46
#define GPIO_EXP_PRESENCE	47
#define GPIO_KP_INT		48
#define GPIO_BOARD_ID_1		49

/*
 * shift register outputs
 */
#define SROUT_SFP_PWREN		0
#define SROUT_USB_RST		1
#define SROUT_AUDIO_RST		2
#define SROUT_EXP_PWREN		3
#define SROUT_BCM_RST		4
#define SROUT_PCIE_RST		5
#define SROUT_KEYPAD_OLED_RST	6
#define SROUT_OLED_PWREN	7

#endif /* !BOARD_FBXGW1R_H_ */

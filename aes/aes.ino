#include "test.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef msp432p401r
#define UART
#include "msp432.h"
#include "rom_map.h"
#include "rom.h"
#include "systick.h"
#ifdef UART
#include "driverlib.h"
#endif
#endif

#ifdef msp430f5529
#define UART
#include "msp430.h"
#ifdef UART
#include "driverlib.h"
#endif
#endif

#ifdef msp430g2553
#include "msp430.h"
#endif

#ifdef msp430fr5994
#define UART
#include "msp430.h"
#ifdef UART
#include "driverlib.h"
#endif
#endif

#ifdef apollo3
#define UART
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\am_mcu_apollo.h"
#include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\bsp\am_bsp.h"
#include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\bsp\am_bsp_pins.h"
#include "D:\AmbiqSuiteSDK-master\utils\am_util.h"
#include "D:\AmbiqSuiteSDK-master\utils\am_util_stdio.h"
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\hal\am_hal_uart.h"
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\hal\am_hal_pin.h"
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\hal\am_hal_stimer.h"
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\hal\am_hal_status.h"
#include "D:\AmbiqSuiteSDK-master\mcu\apollo3\hal\am_hal_sysctrl.h"
#endif

#ifdef saml11
#include <saml11e16a.h>
#include "atmel_start.h"
#include <hal_gpio.h>
#include <hal_delay.h>
/* For measurement method; if TIMER is used then just set uncomment this line*/
#define TIMER
//115200 Baud rate
static const uint8_t welcoming_str[] = "Time: \r\n";
#endif

#ifdef riscv
#include <metal/cpu.h>
#include <metal/interrupt.h>
#include <metal/timer.h>
#endif

#if defined riscv || defined saml11 || defined msp432p401r || defined msp430fr5994 || defined msp430f5529
#include "experiment_time.h"
#endif

#ifdef apollo3
#include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo_aes\keil\experiment_time.h"
#endif

#ifdef gladman_aes
#include "gladman\aes.h"
#include "gladman\brg_endian.h"
#include "gladman\aesopt.h"
#include "gladman\aestst.h"
#if defined adafruitm0express || defined riscv
#if !defined riscv
#include "gladman\aescpp.h"
#endif
#include "gladman\aestab.c"
#include "gladman\aestst.c"
#include "gladman\aescrypt.c"
#include "gladman\aeskey.c"
#endif
#endif

#ifdef tiny_aes
#include "tiny_aes\aes.h"
#if defined adafruitm0express || defined riscv
#include "tiny_aes\aes.c"
#endif
#endif

#ifdef mbedtls_aes
#include "mbedtls\aes.h"
#if defined adafruitm0express || defined riscv
#include "mbedtls\aes.c"
#endif
#endif

#ifdef riscv
double cycles_to_ms(unsigned long long cycles) {
    double frequency = 32000000.0; // HiFive1 Rev B board has a 32MHz clock
    return (cycles / frequency) * 1000.0;
}
#endif

#ifdef saml11
void start_timer_0_16_bit(void)
{
    GCLK->PCHCTRL[14].reg = (GCLK_PCHCTRL_CHEN|GCLK_PCHCTRL_GEN_GCLK0);
    TC0->COUNT16.CTRLA.bit.ENABLE = 0; // CNTLA is write protected to so we have to disable it before writing.
    while(TC0->COUNT16.SYNCBUSY.reg & TC_SYNCBUSY_ENABLE);
    TC0->COUNT16.CTRLA.bit.MODE = 0x1; // set the counter to be in 32 bit mode.
    TC0->COUNT16.DBGCTRL.bit.DBGRUN = 0x1; // keep timer running even when the device is halted.
    TC0->COUNT16.CTRLA.bit.ENABLE = 0x1; // start the counter
    while(TC0->COUNT16.SYNCBUSY.bit.ENABLE);

}


uint16_t read_time_0_16_bit(void)
{
    TC0->COUNT16.CTRLBSET.bit.CMD = 0X4;// READSYNC
    while(TC0->COUNT16.SYNCBUSY.reg & TC_SYNCBUSY_CTRLB);
    return TC0->COUNT16.COUNT.reg;

}



void start_timer_0_32_bit(void)
{
    /************************************************************************/
    /* 16 bit is not enough for most cases
    So this function makes it a 32 bit time.
    TC0 and TC1; TC1 is just a slave device.                                     */
    /************************************************************************/
    GCLK->PCHCTRL[14].reg = (GCLK_PCHCTRL_CHEN|GCLK_PCHCTRL_GEN_GCLK0);
    TC0->COUNT32.CTRLA.bit.ENABLE = 0; // CNTLA is write protected to so we have to disable it before writing.
    while(TC0->COUNT32.SYNCBUSY.reg & TC_SYNCBUSY_ENABLE);

    TC0->COUNT32.CTRLA.bit.MODE = 0x2; // set the counter to be in 32 bit mode.
    TC0->COUNT32.DBGCTRL.bit.DBGRUN = 0x1; // keep timer running even when the device is halted.
    TC0->COUNT32.CTRLA.bit.ENABLE = 0x1; // start the counter
    while(TC0->COUNT32.SYNCBUSY.bit.ENABLE);// wait for it to be activated
}

volatile uint32_t read_time_0_32_bit(void)
{ /**Dumps the timer cycles to a variable*/
    TC0->COUNT32.CTRLBSET.bit.CMD = 0X4;// READSYNC
    while(TC0->COUNT32.SYNCBUSY.reg & TC_SYNCBUSY_CTRLB);
    return TC0->COUNT32.COUNT.reg; // return count register.
}
#endif

#ifdef apollo3

#ifdef UART
// -- UART Stuff --
void *phUART;

#define CHECK_ERRORS(x)                                                       \
    if ((x) != AM_HAL_STATUS_SUCCESS)                                         \
    {                                                                         \
        error_handler(x);                                                     \
    }

volatile uint32_t ui32LastError;

// Catch HAL errors
void error_handler(uint32_t ui32ErrorStatus)
{
    ui32LastError = ui32ErrorStatus;
    while (1);
}

// UART buffers
uint8_t g_pui8TxBuffer[256];
uint8_t g_pui8RxBuffer[2];

// UART configuration
const am_hal_uart_config_t g_sUartConfig =
{
    // Standard UART settings: 115200-8-N-1
    .ui32BaudRate = 115200,
    .ui32DataBits = AM_HAL_UART_DATA_BITS_8,
    .ui32Parity = AM_HAL_UART_PARITY_NONE,
    .ui32StopBits = AM_HAL_UART_ONE_STOP_BIT,
    .ui32FlowControl = AM_HAL_UART_FLOW_CTRL_NONE,

    // Set TX and RX FIFOs to interrupt at half-full.
    .ui32FifoLevels = (AM_HAL_UART_TX_FIFO_1_2 |
                       AM_HAL_UART_RX_FIFO_1_2),

    // Buffers
    .pui8TxBuffer = g_pui8TxBuffer,
    .ui32TxBufferSize = sizeof(g_pui8TxBuffer),
    .pui8RxBuffer = g_pui8RxBuffer,
    .ui32RxBufferSize = sizeof(g_pui8RxBuffer),
};

// UART0 interrupt handler
void am_uart_isr(void)
{
    // Service the FIFOs as necessary, and clear the interrupts
    uint32_t ui32Status, ui32Idle;
    am_hal_uart_interrupt_status_get(phUART, &ui32Status, true);
    am_hal_uart_interrupt_clear(phUART, ui32Status);
    am_hal_uart_interrupt_service(phUART, ui32Status, &ui32Idle);
}

// UART print string
void uart_print(char *pcStr)
{
    uint32_t ui32StrLen = 0;
    uint32_t ui32BytesWritten = 0;

    // Measure the length of the string
    while (pcStr[ui32StrLen] != 0){
        ui32StrLen++;
    }

    // Print the string via the UART
    const am_hal_uart_transfer_t sUartWrite =
    {
        .ui32Direction = AM_HAL_UART_WRITE,
        .pui8Data = (uint8_t *) pcStr,
        .ui32NumBytes = ui32StrLen,
        .ui32TimeoutMs = 0,
        .pui32BytesTransferred = &ui32BytesWritten,
    };

    CHECK_ERRORS(am_hal_uart_transfer(phUART, &sUartWrite));

    if (ui32BytesWritten != ui32StrLen)
    {
        // Couldn't send the whole string!!
        while(1);
    }
}

 // -- End UART Stuff --

void init(void){
//    am_util_id_t sIdDevice;
//    uint32_t ui32StrBuf;

    // Set the clock frequency.
    am_hal_clkgen_control(AM_HAL_CLKGEN_CONTROL_SYSCLK_MAX, 0);

    // Set the default cache configuration
    am_hal_cachectrl_config(&am_hal_cachectrl_defaults);
    am_hal_cachectrl_enable();

    // Configure the board for low power operation.
    // am_bsp_low_power_init();

    // Initialize the printf interface for UART output
    CHECK_ERRORS(am_hal_uart_initialize(0, &phUART));
    CHECK_ERRORS(am_hal_uart_power_control(phUART, AM_HAL_SYSCTRL_WAKE, false));
    CHECK_ERRORS(am_hal_uart_configure(phUART, &g_sUartConfig));

    // Enable the UART pins
    am_hal_gpio_pinconfig(AM_BSP_GPIO_COM_UART_TX, g_AM_BSP_GPIO_COM_UART_TX);
    am_hal_gpio_pinconfig(AM_BSP_GPIO_COM_UART_RX, g_AM_BSP_GPIO_COM_UART_RX);

    // Enable interrupts
    NVIC_EnableIRQ((IRQn_Type)(UART0_IRQn + AM_BSP_UART_PRINT_INST));
    am_hal_interrupt_master_enable();

    // Set the main print interface to use the UART print function we defined
    am_util_stdio_printf_init(uart_print);

    //// Configure GPIO for measurement
    //am_hal_gpio_pinconfig(1, g_AM_HAL_GPIO_OUTPUT);
    //am_hal_gpio_state_write(1, AM_HAL_GPIO_OUTPUT_CLEAR);

    // Configure the system timer
    am_hal_stimer_config(AM_HAL_STIMER_CFG_THAW | AM_HAL_STIMER_HFRC_3MHZ);

}
#endif
#endif

#ifdef msp430f5529


#ifdef UART
    /*  Function to send a character through UART*/
    void UART1_putchar(char c) {

        //Load data onto buffer
        USCI_A_UART_transmitData(USCI_A1_BASE, c);
        //Wait for transmit buffer to be empty
        while(USCI_A_UART_queryStatusFlags(USCI_A1_BASE, USCI_A_UART_BUSY)){};

    }

    /*  Function to send a string through UART by sending each character in the string. */
    void UART1_puts(char* s) {
        while (*s != 0)             /* if not end of string */
        UART1_putchar(*s++);        /* send the character through UART0 */
    }

    void uart_init(void)
    {
         //P4.4,5 = USCI_A1 TXD/RXD for MSP430F5529
        GPIO_setAsPeripheralModuleFunctionInputPin(
            GPIO_PORT_P4,
            GPIO_PIN4 + GPIO_PIN5
            );

        //Baudrate = 9600, clock freq = 1.048MHz
        //UCBRx = 109, UCBRFx = 0, UCBRSx = 2, UCOS16 = 0
        // N = clock freq/Baudrate
        USCI_A_UART_initParam param = {0};
        param.selectClockSource = USCI_A_UART_CLOCKSOURCE_SMCLK;
        param.clockPrescalar = 109;
        param.firstModReg = 0;
        param.secondModReg = 2;
        param.parity = USCI_A_UART_NO_PARITY;
        param.msborLsbFirst = USCI_A_UART_LSB_FIRST;
        param.numberofStopBits = USCI_A_UART_ONE_STOP_BIT;
        param.uartMode = USCI_A_UART_MODE;
        param.overSampling = USCI_A_UART_LOW_FREQUENCY_BAUDRATE_GENERATION;

        //Check UART initialization
        if (STATUS_FAIL == USCI_A_UART_init(USCI_A1_BASE, &param)){
                return;
            }

        //Enable UART module for operation
        USCI_A_UART_enable(USCI_A1_BASE);

    }
    #endif
#endif

#ifdef msp430fr5994

#ifdef UART
/*  Function to send a character through UART*/
void UART0_putchar(char c) {

    //Load data onto buffer
    EUSCI_A_UART_transmitData(EUSCI_A0_BASE, c);
    //Wait for transmit buffer to be empty
    while(EUSCI_A_UART_queryStatusFlags(EUSCI_A0_BASE, EUSCI_A_UART_BUSY)){};
}

/*  Function to send a string through UART by sending each character in the string. */
void UART0_puts(char* s) {
    while (*s != 0)             /* if not end of string */
    UART0_putchar(*s++);        /* send the character through UART0 */
}

void uart_init(void)
{
    // LFXT Setup - LFXT oscillator supports ultra-low-current consumption using a 32768-Hz watch crystal.
    //Set PJ.4 and PJ.5 as Primary Module Function Input.
    /*

    * Select Port J
    * Set Pin 4, 5 to input Primary Module Function, LFXT. A watch crystal connects to LFXIN & LFXOUT pins when enabled for LFXT configuration.
    */
    GPIO_setAsPeripheralModuleFunctionInputPin(
        GPIO_PORT_PJ,
        GPIO_PIN4 + GPIO_PIN5,
        GPIO_PRIMARY_MODULE_FUNCTION
    );

    //ACLK = BRCLK = 32.768kHz, MCLK = SMCLK = DCO = ~1MHz
    //Code works by configuring just the ACLK and LFXT as well.
    //Set DCO frequency to 1 MHz
    CS_setDCOFreq(CS_DCORSEL_0,CS_DCOFSEL_0);
    //Set external clock frequency to 32.768 KHz
    CS_setExternalClockSource(32768,0);
    //Set ACLK=LFXT
    CS_initClockSignal(CS_ACLK,CS_LFXTCLK_SELECT,CS_CLOCK_DIVIDER_1);
    //Set SMCLK = DCO with frequency divider of 1
    CS_initClockSignal(CS_SMCLK,CS_DCOCLK_SELECT,CS_CLOCK_DIVIDER_1);
    //Set MCLK = DCO with frequency divider of 1
    CS_initClockSignal(CS_MCLK,CS_DCOCLK_SELECT,CS_CLOCK_DIVIDER_1);
    //Start XT1 with no time out
    CS_turnOnLFXT(CS_LFXT_DRIVE_0);

    //Configure UART pins
    //Set P2.0 and P2.1 as Secondary Module Function Input for MSP430FR5994.
    /*

    * Select Port 2d
    * Set Pin 0, 1 to input Secondary Module Function, (UCA0TXD/UCA0SIMO, UCA0RXD/UCA0SOMI).
    */
    GPIO_setAsPeripheralModuleFunctionInputPin(
    GPIO_PORT_P2,
    GPIO_PIN0 + GPIO_PIN1,
    GPIO_SECONDARY_MODULE_FUNCTION
    );

    // Configure UART 9600 baud rate with ACLK = LFXT = 32.768kHz
    EUSCI_A_UART_initParam param = {0};
    param.selectClockSource = EUSCI_A_UART_CLOCKSOURCE_ACLK;
    param.clockPrescalar = 3;
    param.firstModReg = 0;
    param.secondModReg = 92;
    param.parity = EUSCI_A_UART_NO_PARITY;
    param.msborLsbFirst = EUSCI_A_UART_LSB_FIRST;
    param.numberofStopBits = EUSCI_A_UART_ONE_STOP_BIT;
    param.uartMode = EUSCI_A_UART_MODE;
    param.overSampling = EUSCI_A_UART_LOW_FREQUENCY_BAUDRATE_GENERATION;

    if (STATUS_FAIL == EUSCI_A_UART_init(EUSCI_A0_BASE, &param)) {
        return;
    }

    EUSCI_A_UART_enable(EUSCI_A0_BASE);

}
#endif
#endif

#ifdef msp432p401r
#ifdef UART
void uart_init(void)
{
    const eUSCI_UART_Config uartConfig =
    {
            EUSCI_A_UART_CLOCKSOURCE_SMCLK,          // SMCLK Clock Source
            78,                                     // BRDIV = 78
            2,                                       // UCxBRF = 2
            0,                                       // UCxBRS = 0
            EUSCI_A_UART_NO_PARITY,                  // No Parity
            EUSCI_A_UART_LSB_FIRST,                  // LSB First
            EUSCI_A_UART_ONE_STOP_BIT,               // One stop bit
            EUSCI_A_UART_MODE,                       // UART mode
            EUSCI_A_UART_OVERSAMPLING_BAUDRATE_GENERATION  // Oversampling
    };

    /* Selecting P1.2 and P1.3 in UART mode */
    MAP_GPIO_setAsPeripheralModuleFunctionInputPin(GPIO_PORT_P1,
            GPIO_PIN1 | GPIO_PIN2 | GPIO_PIN3, GPIO_PRIMARY_MODULE_FUNCTION);

    /* Setting DCO to 12MHz */
    CS_setDCOCenteredFrequency(CS_DCO_FREQUENCY_12);

    /* Configuring UART Module */
    MAP_UART_initModule(EUSCI_A0_BASE, &uartConfig);

    /* Enable UART module */
    MAP_UART_enableModule(EUSCI_A0_BASE);

}

/*  Function to send a character through UART*/
void UART0_putchar(char c) {
    MAP_UART_transmitData(EUSCI_A0_BASE, c);              /* send a char */

    while(UART_queryStatusFlags(EUSCI_A0_BASE, EUSCI_A_UART_BUSY));  /* wait for transmit buffer empty */
}

/*  Function to send a string through UART by sending each character in the string. */
void UART0_puts(char* s) {
    while (*s != 0)             /* if not end of string */
    UART0_putchar(*s++);        /* send the character through UART0 */
}
#endif
#endif


/** Globals (test inputs) **/
uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73,
                  0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
                  0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
                  0xdf, 0xf4
                };
uint8_t expected_pt[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
                        };
uint8_t expected_ct[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                          0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
                        };

//For comparison with chacha20
// uint8_t expected_pt[] = {0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
//                         0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
//                         0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
//                         0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
//                         0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
//                         0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
//                         0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69};
// uint8_t expected_ct[] = {0x15, 0x5c, 0xfd, 0xbe, 0x7c, 0x06, 0x3a, 0x60, 0x50, 0x6f, 0x5d, 0x79, 0x55, 0x08, 0x61, 0x1d,
//                         0xb0, 0x52, 0xcb, 0x76, 0x22, 0xf8, 0xe0, 0x3c, 0xf2, 0x64, 0x3a, 0xd9, 0x68, 0x3a, 0x2c, 0x0f,
//                         0xc9, 0x84, 0x9b, 0xdc, 0x4e, 0x5e, 0xcb, 0xcc, 0x0b, 0x8e, 0x28, 0x9e, 0x75, 0xa0, 0x0f, 0x9b,
//                         0xda, 0x93, 0x0c, 0x17, 0xda, 0x95, 0x68, 0x1d, 0xbf, 0x20, 0x2f, 0x77, 0xfb, 0x0b, 0x68, 0x63,
//                         0x51, 0x2b, 0x0e, 0x9e, 0x7b, 0xd1, 0xb7, 0x05, 0x47, 0x33, 0x8a, 0xf1, 0x91, 0x1c, 0x41, 0x66,
//                         0xe0, 0x8b, 0x48, 0xb9, 0x91, 0x92, 0xeb, 0xf6, 0x58, 0xcb, 0x2b, 0x9c, 0xff, 0x56, 0xc9, 0x0f,
//                         0xc6, 0x37, 0x0c, 0x0c, 0xd1, 0x04, 0x5a, 0xff, 0x2c, 0x80, 0x28, 0x8d, 0x36, 0x00, 0xbf, 0x10};

#ifdef AES_CBC
uint8_t pt[MSG_LNGTH];
uint8_t ct[MSG_LNGTH];
// initialization vector for CBC mode
unsigned char iv[AES_BLOCK_SIZE_BYTES] = { 0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e,
                                           0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75
                                         };
#else
uint8_t pt[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
               };
uint8_t ct[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b,
                 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
               };
//For comparison with chacha20
// uint8_t pt[] = {0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
//                0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
//                0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
//                0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
//                0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
//                0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
//                0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69};
// uint8_t ct[] = {0x15, 0x5c, 0xfd, 0xbe, 0x7c, 0x06, 0x3a, 0x60, 0x50, 0x6f, 0x5d, 0x79, 0x55, 0x08, 0x61, 0x1d,
              //  0xb0, 0x52, 0xcb, 0x76, 0x22, 0xf8, 0xe0, 0x3c, 0xf2, 0x64, 0x3a, 0xd9, 0x68, 0x3a, 0x2c, 0x0f,
              //  0xc9, 0x84, 0x9b, 0xdc, 0x4e, 0x5e, 0xcb, 0xcc, 0x0b, 0x8e, 0x28, 0x9e, 0x75, 0xa0, 0x0f, 0x9b,
              //  0xda, 0x93, 0x0c, 0x17, 0xda, 0x95, 0x68, 0x1d, 0xbf, 0x20, 0x2f, 0x77, 0xfb, 0x0b, 0x68, 0x63,
              //  0x51, 0x2b, 0x0e, 0x9e, 0x7b, 0xd1, 0xb7, 0x05, 0x47, 0x33, 0x8a, 0xf1, 0x91, 0x1c, 0x41, 0x66,
              //  0xe0, 0x8b, 0x48, 0xb9, 0x91, 0x92, 0xeb, 0xf6, 0x58, 0xcb, 0x2b, 0x9c, 0xff, 0x56, 0xc9, 0x0f,
              //  0xc6, 0x37, 0x0c, 0x0c, 0xd1, 0x04, 0x5a, 0xff, 0x2c, 0x80, 0x28, 0x8d, 0x36, 0x00, 0xbf, 0x10};
#endif

/** contexts **/
#ifdef tiny_aes
struct AES_ctx ctx;
#endif
#ifdef mbedtls_aes
struct mbedtls_aes_context ctx;
#endif

/** define keysizes **/
#if defined AES_128
long keysize = 128;
#elif defined AES_192
long keysize = 192;
#else
long keysize = 256;
#endif

/** Call initialization functions for different AES implementations **/
void init_aes()
{
#ifdef gladman_aes
  gladman_init(key, pt, ct, keysize);
#endif
#ifdef tiny_aes
  AES_init_ctx(&ctx, key);
#endif
#ifdef mbedtls_aes
  mbedtls_aes_init(&ctx);
#endif
}

void test_encrypt()
{
  /** Gladman AES **/
#ifdef gladman_aes
#ifdef AES_128
  aes_gladman_128_encrypt(key, pt, ct);
#elif AES_192
  aes_gladman_192_encrypt(key, pt, ct);
#else // AES_256
  aes_gladman_256_encrypt(key, pt, ct);
#endif
#endif

  /** tiny AES **/
#ifdef tiny_aes
  AES_encrypt(&ctx, pt);
#endif

  /** MbedTLS AES **/
#ifdef mbedtls_aes
  mbedtls_aes_setkey_enc(&ctx, key, keysize);
  mbedtls_internal_aes_encrypt(&ctx, pt, ct);
#endif
}

void test_decrypt()
{
  /** Gladman AES **/
#ifdef gladman_aes
#ifdef AES_128
  aes_gladman_128_decrypt(key, ct, pt);
#elif AES_192
  aes_gladman_192_decrypt(key, ct, pt);
#else // AES_256
  aes_gladman_256_decrypt(key, ct, pt);
#endif
#endif

  /** tiny AES **/
#ifdef tiny_aes
  AES_decrypt(&ctx, ct);
#endif

  /** MbedTLS AES **/
#ifdef mbedtls_aes
  mbedtls_aes_setkey_dec(&ctx, key, keysize);
  mbedtls_internal_aes_decrypt(&ctx, ct, pt);
#endif
}

/******************************

  Function to verify encryption

******************************/
int check_encrypt() {

 return memcmp((char*) expected_ct, (char*) ct, sizeof(expected_ct));
}

/******************************

  Function to verify decryption

******************************/
int check_decrypt() {
 return memcmp((char*) expected_pt, (char*) pt, sizeof(expected_pt));
}

#ifdef AES_CBC
void aes_encrypt_cbc(size_t length) {
  uint8_t * p = pt;
  uint8_t * c = ct;

  while (length > 0) {
    // Perform IV xor PT for 128 bits
    int i = 0;
    for (i = 0; i < AES_BLOCK_SIZE_BYTES; i++)
      p[i] = p[i] ^ iv[i];

    // Perform 1 encrypt
    test_encrypt();

    // IV is now CT
    memcpy(iv, c, AES_BLOCK_SIZE_BYTES);

    // Go to next block of PT
    p += AES_BLOCK_SIZE_BYTES;
    c += AES_BLOCK_SIZE_BYTES;
    length -= AES_BLOCK_SIZE_BYTES;
  }
}

void aes_decrypt_cbc(size_t length) {
  uint8_t * p = pt;
  uint8_t * c = ct;

  while (length > 0) {
    // Perform 1 encrypt
    test_decrypt();

    // Perform IV xor PT for 128 bits
    int i = 0;
    for (i = 0; i < AES_BLOCK_SIZE_BYTES; i++)
      p[i] = p[i] ^ iv[i];

    // IV is now CT
    memcpy(iv, c, AES_BLOCK_SIZE_BYTES);

    // Go to next block of PT
    p += AES_BLOCK_SIZE_BYTES;
    c += AES_BLOCK_SIZE_BYTES;
    length -= AES_BLOCK_SIZE_BYTES;
  }
}
#endif


#ifdef adafruitm0express
void setup()
{
    Serial.begin(9600);
}
#endif

//  int main(void)
void loop(void)
{
  
#ifdef adafruitm0express
  /** Measure the starting time **/
  setup();
  unsigned long long int start, finished, elapsed;
  start = micros();
#endif

#ifdef riscv
    int hartid = metal_cpu_get_current_hartid();
    unsigned long long start_cycle_count, end_cycle_count;

    // Get the start cycle count
    if (metal_timer_get_cyclecount(hartid, &start_cycle_count) != 0) {
        printf("Failed to get the start cycle count.\n");
        return 1;
    }
#endif

#ifdef saml11
  atmel_start_init();
  #ifdef TIMER
    volatile uint32_t a = 0;
    start_timer_0_32_bit();
  #endif
#endif

#ifdef apollo3
  #ifdef UART
    init();
  #endif
  //  am_hal_gpio_state_write(1, AM_HAL_GPIO_OUTPUT_CLEAR);
  //  am_util_delay_us(20);

  uint32_t startClock, stopClock, aesTime;
  startClock = am_hal_stimer_counter_get();
  //  am_hal_gpio_state_write(1, AM_HAL_GPIO_OUTPUT_SET);
#endif

#if defined msp432p401r || defined msp430fr5994 || defined msp430f5529
    board_init();
  #ifdef UART
      uart_init();
  #endif
    startTimer();
#endif

  /** initialize AES **/
  init_aes();
  /** Choose the function to be called **/
  /** Encrypt or decrypt possibly many times **/
  /** test aes **/
 test_encrypt();
  // test_decrypt();
  //aes_encrypt_cbc(sizeof(pt));
  //aes_decrypt_cbc(sizeof(ct));

  /** Check the result to see whether RSA algorithm is correctly working or not **/
    // volatile unsigned int verify = check_encrypt(); // Check the validity of an encryption method
//   volatile unsigned int verify = check_decrypt(); // Check the validity of a decryption method

#if defined msp430fr5994
volatile unsigned int elapsed = getElapsedTime();
#endif

#if defined msp432p401r || defined msp430f5529
volatile unsigned long long int elapsed = getElapsedTime();
#endif

#ifdef msp432p401r
  #ifdef UART
    char buffer[20];
    sprintf(buffer, "Value: %llu\n", elapsed);  //Divide by 10 to get value in milliseconds
    UART0_puts(buffer);
  #endif
#endif

#ifdef msp430fr5994
  #ifdef UART
    char buffer[20];
    sprintf(buffer, "Value: %d\n", elapsed);
    UART0_puts(buffer);
  #endif
#endif

#if defined msp430f5529
  #ifdef UART
      char buf[20];
      sprintf(buf, "Value: %d\n", elapsed); //Divide by 10 to get ms
      UART1_puts(buf);
  #endif
#endif

#ifdef apollo3
  //am_hal_gpio_state_write(1, AM_HAL_GPIO_OUTPUT_CLEAR);
  stopClock = am_hal_stimer_counter_get();
  //am_hal_gpio_state_write(46, AM_HAL_GPIO_OUTPUT_SET);

  if(stopClock < startClock){ // Overflow
    aesTime = (0xFFFFFFFF - startClock) + stopClock;
  }else{
    aesTime = stopClock - startClock;
  }

  aesTime /= 3;   // Convert from 3 MHz frequency to us
  #ifdef UART
    am_util_stdio_terminal_clear();
    am_util_stdio_printf("Encryption time: %u us\r\n", aesTime);
  #endif
#endif

#ifdef saml11
    #ifdef TIMER
        a = read_time_0_32_bit(); // add a watch point to this variable if you want to see it live.
        *(uint32_t *)(0x2000383C) = a; // store the timer data in the SRAM at @ 0x2000383C; plan is to get it out of the
        printf("%s", welcoming_str);
        printf("%lu\n",a);
    #endif
#endif

#ifdef riscv
    // Get the end cycle count
    if (metal_timer_get_cyclecount(hartid, &end_cycle_count) != 0) {
        printf("Failed to get the end cycle count.\n");
        return 1;
    }

    // Check for timer overflow
    unsigned long long elapsed_cycles;

    if (end_cycle_count >= start_cycle_count) {
        elapsed_cycles = end_cycle_count - start_cycle_count;
    } else {
        elapsed_cycles = (0xFFFFFFFFFFFFFFFF - start_cycle_count)
                + end_cycle_count + 1;
    }

    // Convert clock cycle count to milliseconds
    double elapsed_ms = cycles_to_ms(elapsed_cycles);

    //Time is printed in us to avoid floating point computations
    printf("%d Function execution time: %d us\n", verify,(unsigned int)(elapsed_ms*1000));

#endif

#ifdef adafruitm0express

  /** Calculate the elapsed time **/
  finished = micros();
  elapsed = finished - start;
  Serial.print("Time taken by the task: ");
  Serial.println(elapsed);

  // wait a second so as not to send massive amounts of data
  delay(1000);
#endif

#if !defined(adafruitm0express)
  while(1);
  return 0;
#endif
}

#ifndef MISC_DEFS_H
#define MISC_DEFS_H

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef unsigned int    DWORD;

// Set this define to true to show activity after network is joined.
#define USE_ACTIVITY_DISPLAY false

// Un-comment to enable multicast.
//#define USE_MCAST 1

#define RXDATA_LEN      1600
#define TXDATA_LEN      1600

// SD function numbers
#define SD_FUNC_BUS         0
#define SD_FUNC_BAK         1
#define SD_FUNC_RAD         2

// Fake function number, used on startup when bus data is swapped
#define SD_FUNC_SWAP        4
#define SD_FUNC_MASK        (SD_FUNC_SWAP - 1)
#define SD_FUNC_BUS_SWAP    (SD_FUNC_BUS | SD_FUNC_SWAP)

// SDIO bus config registers
#define BUS_CONTROL             0x000   // SPI_BUS_CONTROL
#define BUS_IOEN_REG            0x002   // SDIOD_CCCR_IOEN          I/O enable
#define BUS_IORDY_REG           0x003   // SDIOD_CCCR_IORDY         Ready indication
#define BUS_INTEN_REG           0x004   // SDIOD_CCCR_INTEN
#define BUS_INTPEND_REG         0x005   // SDIOD_CCCR_INTPEND
#define BUS_BI_CTRL_REG         0x007   // SDIOD_CCCR_BICTRL        Bus interface control
#define BUS_SPI_STATUS_REG      0x008   // SPI_STATUS_REGISTER
#define BUS_SPEED_CTRL_REG      0x013   // SDIOD_CCCR_SPEED_CONTROL Bus speed control  
#define BUS_BRCM_CARDCAP_REG    0x0f0   // SDIOD_CCCR_BRCM_CARDCAP
#define BUS_BAK_BLKSIZE_REG     0x110   // SDIOD_CCCR_F1BLKSIZE_0   Backplane blocksize 
#define BUS_RAD_BLKSIZE_REG     0x210   // SDIOD_CCCR_F2BLKSIZE_0   WiFi radio blocksize

#define ALIGN_UINT(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define CYW43_WRITE_BYTES_PAD(len) ALIGN_UINT((len), 64)

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define SWAP16(x) ((x&0xff)<<8 | (x&0xff00)>>8)
#define SWAP32(x) ((x&0xff)<<24 | (x&0xff00)<<8 | (x&0xff0000)>>8 | (x&0xff000000)>>24)
// Swap bytes in two 16-bit values
#define SWAP16_2(x) ((((x) & 0xff000000) >> 8) | (((x) & 0xff0000) << 8) | \
                    (((x) & 0xff00) >> 8)      | (((x) & 0xff) << 8))

// Display mask values
#define DISP_NOTHING    0       // No display
#define DISP_INFO       0x01    // General information
#define DISP_SPI        0x02    // SPI transfers
#define DISP_REG        0x04    // Register read/write
#define DISP_SDPCM      0x08    // SDPCM transfers
#define DISP_IOCTL      0x10    // IOCTL read/write
#define DISP_EVENT      0x20    // Event reception
#define DISP_DATA       0x40    // Data transfers
#define DISP_JOIN       0x80    // Network joining

#define DISP_ETH        0x1000  // Ethernet header
#define DISP_ARP        0x2000  // ARP header
#define DISP_ICMP       0x4000  // ICMP header
#define DISP_UDP        0x8000  // UDP header
#define DISP_DHCP       0x10000 // DHCP header
#define DISP_DNS        0x20000 // DNS header
#define DISP_SOCK       0x40000 // Socket
#define DISP_TCP        0x80000 // TCP
#define DISP_TCP_STATE  0x100000 // TCP state

#define LED_PIN         10

//#define USE_DEBUG_COLORS

#if defined (USE_DEBUG_COLORS)
//Foreground: reset = 0, black = 30, red = 31, green = 32, yellow = 33, blue = 34, magenta = 35, cyan = 36, and white = 37
//Background: reset = 0, black = 40, red = 41, green = 42, yellow = 43, blue = 44, magenta = 45, cyan = 46, and white = 47
#define SER_RED "\033[1;31m"
#define SER_GREEN "\033[1;32m"
#define SER_YELLOW "\033[1;33m"
#define SER_MAGENTA "\033[1;35m"
#define SER_CYAN "\033[1;36m"
#define SER_WHITE "\033[1;37m"
#define SER_RESET "\033[1;0m"

#define SER_TRACE "\033[38;2;182;222;215m"
#define SER_INFO "\033[38;2;200;200;200m"
#define SER_WARN "\033[38;2;221;230;112m"
#define SER_ERROR "\033[38;2;255;105;82m"
#define SER_USER "\033[38;2;55;255;28m"
#define SER_GREY "\033[38;2;128;128;128m"

#else
#define SER_RED ""
#define SER_GREEN ""
#define SER_YELLOW ""
#define SER_MAGENTA ""
#define SER_CYAN ""
#define SER_WHITE ""
#define SER_RESET ""

#define SER_TRACE ""
#define SER_INFO ""
#define SER_WARN ""
#define SER_ERROR ""
#define SER_USER ""
#define SER_GREY ""
#endif //USE_DEBUG_COLORS

#define COUNTRY         "US"
#define COUNTRY_REV     -1

#endif
// EOF

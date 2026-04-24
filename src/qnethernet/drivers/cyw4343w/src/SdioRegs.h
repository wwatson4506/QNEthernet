// ZeroWi bare-metal WiFi driver, see https://iosoft.blog/zerowi
// Raspberry Pi Memory and register definitions
//
// Copyright (c) 2020 Jeremy P Bentham
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef SdioRegs_h
#define SdioRegs_h

//SD function numbers
#define SD_FUNC_BUS     0
#define SD_FUNC_BAK     1
#define SD_FUNC_RAD     2

#define SD_FUNC_BUS_EN  0x01
#define SD_FUNC_BAK_EN  0x02
#define SD_FUNC_RAD_EN  0x04

//Read/write block sizes
#define SD_BUS_BLK_BYTES    32
#define SD_BAK_BLK_BYTES    64
#define SD_RAD_BLK_BYTES    512

//Read/write flags
#define SD_RD           0
#define SD_WR           1

//Delays
#define SD_CLK_DELAY    1   // Clock on/off time in usec
#define RSP_WAIT        20  // Number of clock cycles to wait for resp

// Bus config registers
#define BUS_IOEN_REG            0x002   // SDIOD_CCCR_IOEN          I/O enable
#define BUS_IORDY_REG           0x003   // SDIOD_CCCR_IORDY         Ready indication
#define BUS_INTEN_REG           0x004   // SDIOD_CCCR_INTEN
#define BUS_INTPEND_REG         0x005   // SDIOD_CCCR_INTPEND
#define BUS_BI_CTRL_REG         0x007   // SDIOD_CCCR_BICTRL        Bus interface control
#define BUS_SPEED_CTRL_REG      0x013   // SDIOD_CCCR_SPEED_CONTROL Bus speed control  
#define BUS_BRCM_CARDCAP        0x0f0   // SDIOD_CCCR_BRCM_CARDCAP
#define BUS_BRCM_CARDCTRL       0x0f1   // SDIO_CCCR_BRCM_CARDCTRL
#define BUS_SEP_INT_CTL         0x0f2   // SDIOD_SEP_INT_CTL //IRW added
#define SDIO_CCCR_BRCM_CARDCTRL_WLANRESET 1 << 1 //BIT(1)
#define BUS_SDIO_BLKSIZE_REG    0x010   // SDIOD_CCCR_F0BLKSIZE_0   SDIO blocksize //IRW added
#define BUS_BAK_BLKSIZE_REG     0x110   // SDIOD_CCCR_F1BLKSIZE_0   Backplane blocksize 
#define BUS_RAD_BLKSIZE_REG     0x210   // SDIOD_CCCR_F2BLKSIZE_0   WiFi radio blocksize

// Backplane config registers
#define BAK_WIN_ADDR_REG        0x1000a // SDIO_BACKPLANE_ADDRESS_LOW Window addr 
#define BAK_CHIP_CLOCK_CSR_REG  0x1000e // SDIO_CHIP_CLOCK_CSR      Chip clock ctrl 

// SDIO_CHIP_CLOCK_CSR bits
#define SBSDIO_HT_AVAIL            0x80
#define SBSDIO_ALP_AVAIL           0x40 
#define SBSDIO_FORCE_HW_CLKREQ_OFF 0x20
#define SBSDIO_HT_AVAIL_REQ        0x10
#define SBSDIO_ALP_AVAIL_REQ       0x08
#define SBSDIO_FORCE_ILP           0x04           // Idle low-power clock
#define SBSDIO_FORCE_HT            (uint32_t)0x02 // High throughput clock 
#define SBSDIO_FORCE_ALP           0x01           // Active low-power clock 

// For OOB interrupts
#define SDIO_CCCR_BRCM_SEPINT_MASK 0x01  // BIT(0)
#define SDIO_CCCR_BRCM_SEPINT_OE   0x02  // BIT(1)
#define SDIO_CCCR_IEN_FUNC0 0x01  // BIT(0)
#define SDIO_CCCR_IEN_FUNC1 0x02  // BIT(1)
#define SDIO_CCCR_IEN_FUNC2 0x04  // BIT(2)

#define BAK_PULLUP_REG          0x1000f // SDIO_PULL_UP             Pullups
#define BAK_WAKEUP_REG          0x1001e // SDIO_WAKEUP_CTRL

// Silicon backplane
#define BAK_BASE_ADDR           0x18000000              // CHIPCOMMON_BASE_ADDRESS
                                                        //
#define MAC_BASE_ADDR           (BAK_BASE_ADDR+0x1000)  // DOT11MAC_BASE_ADDRESS
#define MAC_BASE_WRAP           (MAC_BASE_ADDR+0x100000)
#define MAC_IOCTRL_REG          (MAC_BASE_WRAP+0x408)   // +AI_IOCTRL_OFFSET
#define MAC_RESETCTRL_REG       (MAC_BASE_WRAP+0x800)   // +AI_RESETCTRL_OFFSET
#define MAC_RESETSTATUS_REG     (MAC_BASE_WRAP+0x804)   // +AI_RESETSTATUS_OFFSET

#define SB_BASE_ADDR            (BAK_BASE_ADDR+0x2000)  // SDIO_BASE_ADDRESS
#define SB_INT_STATUS_REG       (SB_BASE_ADDR +0x20)    // SDIO_INT_STATUS
#define SB_INT_HOST_MASK_REG    (SB_BASE_ADDR +0x24)    // SDIO_INT_HOST_MASK
#define SB_FUNC_INT_MASK_REG    (SB_BASE_ADDR +0x34)    // SDIO_FUNCTION_INT_MASK
#define SB_TO_SB_MBOX_REG       (SB_BASE_ADDR +0x40)    // SDIO_TO_SB_MAILBOX
#define SB_TO_SB_MBOX_DATA_REG  (SB_BASE_ADDR +0x48)    // SDIO_TO_SB_MAILBOX_DATA
#define SB_TO_HOST_MBOX_DATA_REG (SB_BASE_ADDR+0x4C)    // SDIO_TO_HOST_MAILBOX_DATA

#define ARM_BASE_ADDR           (BAK_BASE_ADDR+0x3000)  // WLAN_ARMCM3_BASE_ADDRESS
#define ARM_BASE_WRAP           (ARM_BASE_ADDR+0x100000)
#define ARM_IOCTRL_REG          (ARM_BASE_WRAP+0x408)   // +AI_IOCTRL_OFFSET
#define ARM_RESETCTRL_REG       (ARM_BASE_WRAP+0x800)   // +AI_RESETCTRL_OFFSET
#define ARM_RESETSTATUS_REG     (ARM_BASE_WRAP+0x804)   // +AI_RESETSTATUS_OFFSET

#define SRAM_BASE_ADDR          (BAK_BASE_ADDR+0x4000)  // SOCSRAM_BASE_ADDRESS
#define SRAM_BANKX_IDX_REG      (SRAM_BASE_ADDR+0x10)   // SOCSRAM_BANKX_INDEX
#define SRAM_UNKNOWN_REG        (SRAM_BASE_ADDR+0x40)   // ??
#define SRAM_BANKX_PDA_REG      (SRAM_BASE_ADDR+0x44)   // SOCSRAM_BANKX_PDA
#define SRAM_BASE_WRAP          (SRAM_BASE_ADDR+0x100000)
#define SRAM_IOCTRL_REG         (SRAM_BASE_WRAP+0x408)  // +AI_IOCTRL_OFFSET
#define SRAM_RESETCTRL_REG      (SRAM_BASE_WRAP+0x800)  // +AI_RESETCTRL_OFFSET
#define SRAM_RESETSTATUS_REG    (SRAM_BASE_WRAP+0x804)  // +AI_RESETSTATUS_OFFSET

// Save-restore
#define SR_CONTROL1             (BAK_BASE_ADDR+0x508)   // CHIPCOMMON_SR_CONTROL1

// Backplane window
#define SB_32BIT_WIN    0x8000
#define SB_ADDR_MASK    0x7fff
#define SB_WIN_MASK     (~SB_ADDR_MASK)

#endif

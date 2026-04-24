/**
 * Copyright (c) 2011-2021 Bill Greiman
 * This file is part of the SdFat library for SD memory cards.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#ifndef WiFiCardInfo_h
#define WiFiCardInfo_h
#include <stdint.h>
// Based on the document:
//
// SD Specifications
// Part 1
// Physical Layer
// Simplified Specification
// Version 5.00
// Aug 10, 2016
//
// https://www.sdcard.org/downloads/pls/
//------------------------------------------------------------------------------
// WiFi card errors
// See the SD Specification for command info.

#define SD_ERROR_CODE_LIST\
  WIFI_CARD_ERROR(NONE, "No error")\
  WIFI_CARD_ERROR(CMD0, "Card reset failed")\
  WIFI_CARD_ERROR(CMD2, "SDIO read CID")\
  WIFI_CARD_ERROR(CMD3, "SDIO publish RCA")\
  WIFI_CARD_ERROR(CMD6, "Switch WiFi card function")\
  WIFI_CARD_ERROR(CMD7, "SDIO WiFi card select")\
  WIFI_CARD_ERROR(CMD8, "Send and check interface settings")\
  WIFI_CARD_ERROR(CMD9, "Read CSD data")\
  WIFI_CARD_ERROR(CMD10, "Read CID data")\
  WIFI_CARD_ERROR(CMD12, "Stop multiple block read")\
  WIFI_CARD_ERROR(CMD13, "Read WiFi card status")\
  WIFI_CARD_ERROR(CMD17, "Read single block")\
  WIFI_CARD_ERROR(CMD18, "Read multiple blocks")\
  WIFI_CARD_ERROR(CMD24, "Write single block")\
  WIFI_CARD_ERROR(CMD25, "Write multiple blocks")\
  WIFI_CARD_ERROR(CMD32, "Set first erase block")\
  WIFI_CARD_ERROR(CMD33, "Set last erase block")\
  WIFI_CARD_ERROR(CMD38, "Erase selected blocks")\
  WIFI_CARD_ERROR(CMD58, "Read OCR register")\
  WIFI_CARD_ERROR(CMD59, "Set CRC mode")\
  WIFI_CARD_ERROR(ACMD6, "Set SDIO bus width")\
  WIFI_CARD_ERROR(ACMD13, "Read extended status")\
  WIFI_CARD_ERROR(ACMD23, "Set pre-erased count")\
  WIFI_CARD_ERROR(ACMD41, "Activate card initialization")\
  WIFI_CARD_ERROR(READ_TOKEN, "Bad read data token")\
  WIFI_CARD_ERROR(READ_CRC, "Read CRC error")\
  WIFI_CARD_ERROR(READ_FIFO, "SDIO fifo read timeout")\
  WIFI_CARD_ERROR(READ_REG, "Read CID or CSD failed.")\
  WIFI_CARD_ERROR(READ_START, "Bad readStart argument")\
  WIFI_CARD_ERROR(READ_TIMEOUT, "Read data timeout")\
  WIFI_CARD_ERROR(STOP_TRAN, "Multiple block stop failed")\
  WIFI_CARD_ERROR(TRANSFER_COMPLETE, "SDIO transfer complete")\
  WIFI_CARD_ERROR(WRITE_DATA, "Write data not accepted")\
  WIFI_CARD_ERROR(WRITE_FIFO, "SDIO fifo write timeout")\
  WIFI_CARD_ERROR(WRITE_START, "Bad writeStart argument")\
  WIFI_CARD_ERROR(WRITE_PROGRAMMING, "Flash programming")\
  WIFI_CARD_ERROR(WRITE_TIMEOUT, "Write timeout")\
  WIFI_CARD_ERROR(DMA, "DMA transfer failed")\
  WIFI_CARD_ERROR(ERASE, "Card did not accept erase commands")\
  WIFI_CARD_ERROR(ERASE_SINGLE_SECTOR, "Card does not support erase")\
  WIFI_CARD_ERROR(ERASE_TIMEOUT, "Erase command timeout")\
  WIFI_CARD_ERROR(INIT_NOT_CALLED, "Card has not been initialized")\
  WIFI_CARD_ERROR(INVALID_CARD_CONFIG, "Invalid card config")\
  WIFI_CARD_ERROR(FUNCTION_NOT_SUPPORTED, "Unsupported SDIO command")


enum {
#define WIFI_CARD_ERROR(e, m) WIFI_CARD_ERROR_##e,
  SD_ERROR_CODE_LIST
#undef WIFI_CARD_ERROR
  WIFI_CARD_ERROR_UNKNOWN
};

//------------------------------------------------------------------------------
// SD card commands
/** GO_IDLE_STATE - init card in spi mode if CS low */
const uint8_t CMD0 = 0X00;
/** ALL_SEND_CID - Asks any card to send the CID. */
const uint8_t CMD2 = 0X02;
/** SEND_RELATIVE_ADDR - Ask the card to publish a new RCA. */
const uint8_t CMD3 = 0X03;
/** SWITCH_FUNC - Switch Function Command */
const uint8_t CMD6 = 0X06;
/** SELECT/DESELECT_CARD - toggles between the stand-by and transfer states. */
const uint8_t CMD7 = 0X07;
/** SEND_IF_COND - verify SD Memory Card interface operating condition.*/
const uint8_t CMD8 = 0X08;
/** SEND_CSD - read the Card Specific Data (CSD register) */
const uint8_t CMD9 = 0X09;
/** SEND_CID - read the card identification information (CID register) */
const uint8_t CMD10 = 0X0A;
/** VOLTAGE_SWITCH -Switch to 1.8V bus signaling level. */
const uint8_t CMD11 = 0X0B;
/** STOP_TRANSMISSION - end multiple sector read sequence */
const uint8_t CMD12 = 0X0C;
/** SEND_STATUS - read the card status register */
const uint8_t CMD13 = 0X0D;
/** READ_SINGLE_SECTOR - read a single data sector from the card */
const uint8_t CMD17 = 0X11;
/** READ_MULTIPLE_SECTOR - read multiple data sectors from the card */
const uint8_t CMD18 = 0X12;
/** WRITE_SECTOR - write a single data sector to the card */
const uint8_t CMD24 = 0X18;
/** WRITE_MULTIPLE_SECTOR - write sectors of data until a STOP_TRANSMISSION */
const uint8_t CMD25 = 0X19;
/** ERASE_WR_BLK_START - sets the address of the first sector to be erased */
const uint8_t CMD32 = 0X20;
/** ERASE_WR_BLK_END - sets the address of the last sector of the continuous
    range to be erased*/
const uint8_t CMD33 = 0X21;
/** ERASE - erase all previously selected sectors */
const uint8_t CMD38 = 0X26;
/** APP_CMD - escape for application specific command */
const uint8_t CMD55 = 0X37;
/** READ_OCR - read the OCR register of a card */
const uint8_t CMD58 = 0X3A;
/** CRC_ON_OFF - enable or disable CRC checking */
const uint8_t CMD59 = 0X3B;
/** SET_BUS_WIDTH - Defines the data bus width for data transfer. */
const uint8_t ACMD6 = 0X06;
/** SD_STATUS - Send the SD Status. */
const uint8_t ACMD13 = 0X0D;
/** SET_WR_BLK_ERASE_COUNT - Set the number of write sectors to be
     pre-erased before writing */
const uint8_t ACMD23 = 0X17;
/** SD_SEND_OP_COMD - Sends host capacity support information and
    activates the card's initialization process */
const uint8_t ACMD41 = 0X29;
#endif  // WiFiCardInfo_h

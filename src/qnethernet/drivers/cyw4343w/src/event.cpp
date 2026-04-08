// PicoWi IP functions, see http://iosoft.blog/picowi for details
//
// Copyright (c) 2022, Jeremy P Bentham
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// =====================================================================
// = Modified for testing with Dogbone06 CYW4343W board and T4.1/DB5   =
// =====================================================================

#include "Arduino.h"
#include <stdint.h>
#include "cyw43_T4_SDIO.h"
//#include "T4_SDIO.h"
#include "event.h"
#include "SdioRegs.h"
#include "misc_defs.h"

#define MAX_HANDLERS    20
#define MAX_EVENT_STATUS 16

//T4_SDIO sdio;

static int num_handlers = 0;
event_handler_t event_handlers[MAX_HANDLERS];
WORD event_ports[MAX_HANDLERS];

extern W4343WCard wifiCard;
extern int display_mode;

uint8_t rxdata[RXDATA_LEN];

uint8_t eventbuf[1600];
uint8_t event_mask[EVENT_MAX / 8];

sdpcm_header_t iehh;

ETH_EVENT_FRAME *eep = (ETH_EVENT_FRAME *)eventbuf;
EVT_STR *currentE_evts;

const char * event_status[MAX_EVENT_STATUS] = {
    "SUCCESS","FAIL","TIMEOUT","NO_NETWORK","ABORT","NO_ACK",
    "UNSOLICITED","ATTEMPT","PARTIAL","NEWSCAN","NEWASSOC",
    "11HQUIET","SUPPRESS","NOCHANS","CCXFASTRM","CS_ABORT" };

char ioctl_event_hdr_fields[] =  
    "2:len 2: 1:seq 1:chan 1: 1:hdrlen 1:flow 1:credit";

// Event field displays
char eth_hdr_fields[]   = "6:dest 6:srce 2;type";
char event_hdr_fields[] = "2;sub 2;len 1: 3;oui 2;usr";
char event_msg_fields[] = "2;ver 2;flags 4;type 4;status 4;reason 4:auth 4;dlen 6;addr 18:";

// ARP stuff
//ARPKT *arp = (ARPKT *)&eep->event.hdr;
//char arp_hdr_fields[]   = "2;hrd 2;pro 1;hln 1;pln 2;op 6:smac 4;sip 6:dmac 4;dip";

EVENT_INFO event_info;

TX_MSG tx_msg = {.sdpcm = {.chan=SDPCM_CHAN_DATA, .hdrlen=sizeof(SDPCM_HDR)+2},
                 .bdc =   {.flags=0x20}};

extern IOCTL_MSG ioctl_txmsg, ioctl_rxmsg;
uint8_t sd_tx_seq;

extern void rx_frame(void *buff, uint16_t len);
// Add an event handler to the chain
bool Event::add_event_handler(event_handler_t fn)
{
    return(add_server_event_handler(fn , 0));
}

// Add a server event handler to the chain (with local port number)
bool Event::add_server_event_handler(event_handler_t fn, WORD port)
{
    bool ok = num_handlers < MAX_HANDLERS;
    if (ok)
    {
        event_ports[num_handlers] = port;
        event_handlers[num_handlers++] = fn;
    }
    return (ok);
}


// Run event handlers, until one returns non-zero
int Event::event_handle(EVENT_INFO *eip)
{
    int i, ret=0;
    for (i=0; i<num_handlers && !ret; i++)
    {
        eip->server_port = event_ports[i];
        ret = event_handlers[i](eip);
    }
    return(ret);
}

// Enable events
int Event::ioctl_enable_evts(EVT_STR *evtp)
{
  currentE_evts = evtp;
  memset(event_mask, 0, sizeof(event_mask));
  while (evtp->num >= 0)
  {
      if (evtp->num / 8 < (int32_t)sizeof(event_mask))
          SET_EVENT(event_mask, evtp->num);
      evtp++;
  }
  return wifiCard.ioctl_set_data("event_msgs", 0, event_mask, sizeof(event_mask));
}

// Poll events
int Event::pollEvents() {
  int n, ret = 0;
  EVENT_INFO *eip = &event_info;
  
  //Check for an event response
  if((n=ioctl_get_event(&iehh, eventbuf, sizeof(eventbuf))) > 0) {
    eip->chan = iehh.sw_header.chan; // chan = ctrl, evt or data.
    eip->flags = SWAP16(eep->event.msg.flags);
    eip->event_type = SWAP32(eep->event.msg.event_type);
    eip->status = SWAP32(eep->event.msg.status);
    eip->reason = SWAP32(eep->event.msg.reason);
    eip->data = eventbuf+10; //NOTE: Need to move eventbuf ahead by 10 bytes.
                             //      ioctl_get_event() has a 10 byte prefix that
                             //      is not used by the picowi library. Not
                             //      sure what the 10 bytes are yet.
    eip->dlen = n; // Size of received data in bytes.
    eip->sock = -1;
    ret = event_handle(eip); // Distribute to proper event handler.
#if USE_ACTIVITY_DISPLAY == true    
    uint32_t startime=micros();
    Serial.printf("\n%2.3f ", (micros() - startime) / 1e6);
    wifiCard.disp_fields(&iehh, ioctl_event_hdr_fields, n);
    Serial.printf("\n");
    wifiCard.disp_bytes((uint8_t *)&iehh, sizeof(iehh));
    Serial.printf("\n");
    wifiCard.disp_fields(&eep->eth_hdr, eth_hdr_fields, sizeof(eep->eth_hdr));

    if(SWAP16(eep->eth_hdr.ethertype) == 0x886c) {
       wifiCard.disp_fields(&eep->event.hdr, event_hdr_fields, sizeof(eep->event.hdr));
       Serial.printf("\n");
       wifiCard.disp_fields(&eep->event.msg, event_msg_fields, sizeof(eep->event.msg));
       Serial.printf(SER_WHITE "%s %s" SER_RESET, ioctl_evt_str(SWAP32(eep->event.msg.event_type)),
                      ioctl_evt_status_str(SWAP32(eep->event.msg.status)));
     }

     if (SWAP16(eep->eth_hdr.ethertype) == PCOL_ARP) {
//        wifiCard.disp_fields(arp, arp_hdr_fields, sizeof(arp_hdr_fields));
        Serial.printf("\n");
//        ip_print_arp(arp);
	 }
     Serial.printf("\n");
     wifiCard.disp_block(eventbuf, n);
     Serial.printf("\n");
#endif
  }
  return ret;
}

// Get event data, return data length excluding header
uint32_t Event::ioctl_get_event(sdpcm_header_t *hp, uint8_t *data, int maxlen) {
    int n=0, dlen=0, blklen;
    bool res = false;

    hp->len = 0;
    res = wifiCard.cardCMD53_read(SD_FUNC_RAD, SB_32BIT_WIN, (uint8_t *)hp, sizeof(sdpcm_header_t), false);
    if(res == true && hp->len > sizeof(sdpcm_header_t) && hp->notlen > 0 && hp->len == (hp->notlen^0xffff)) {
      dlen = hp->len - sizeof(sdpcm_header_t);  //Strip off sdpcm_header_t.
      while (n < dlen && n < maxlen) {
        blklen = MIN(MIN(maxlen - n, hp->len - n), IOCTL_MAX_BLKLEN_T4);
        wifiCard.cardCMD53_read(SD_FUNC_RAD, SB_32BIT_WIN, (uint8_t *)(&data[n]), blklen, false);
        n += blklen;
      }
      //Read and discard remaining bytes over maxlen
      while (n < dlen) {
        blklen = MIN(hp->len - n, IOCTL_MAX_BLKLEN_T4);
        wifiCard.cardCMD53_read(SD_FUNC_RAD, SB_32BIT_WIN, 0, blklen, false);
        n += blklen;
      }
    }
    return dlen > maxlen ? maxlen : dlen;
}

// Return string corresponding to SDPCM channel number
char *Event::sdpcm_chan_str(int chan)
{
    return(chan==SDPCM_CHAN_CTRL ? (char *)"CTRL" : chan==SDPCM_CHAN_EVT ? (char *)"EVT ": 
           chan==SDPCM_CHAN_DATA ? (char *)"DATA" : (char *)"?");
}

// Return string corresponding to event number, without "WLC_E_" prefix
char *Event::event_str(int event)
{
    EVT_STR *evtp=currentE_evts;

    while (evtp && evtp->num>=0 && evtp->num!=event)
        evtp++;
    return(evtp && evtp->num>=0 && strlen((char *)evtp->str)>6 ? (char *)&evtp->str[6] : (char *)"?");
}

// Transmit network data
int Event::event_net_tx(void *data, int len) {
    TX_MSG *txp = &tx_msg;
    uint8_t *dp = (uint8_t *)txp;
    int txlen = sizeof(SDPCM_HDR)+2+sizeof(BDC_HDR_T4)+len;
    if(display_mode & DISP_DATA) {
      wifiCard.disp_bytes((uint8_t *)data, len);
      Serial.printf("\n");
    }
    txp->sdpcm.len = txlen;
    txp->sdpcm.notlen = ~txp->sdpcm.len;
    txp->sdpcm.seq = sd_tx_seq++;
    memcpy(txp->data, (uint8_t *)data, len);
    while (txlen & 3) dp[txlen++] = 0;
    return (wifiCard.cardCMD53_write(SD_FUNC_RAD, 0, dp, txlen, false));
}
//----------------------------------------------------------------------
// Return string corresponding to event status Added 02-21-25
//----------------------------------------------------------------------
const char *Event::ioctl_evt_status_str(int status)
{
    return(status>=0 && status<MAX_EVENT_STATUS ? event_status[status] : "?");
}
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// Return string corresponding to event number, without "WLC_E_" prefix Added 02-21-25
//----------------------------------------------------------------------
const char *Event::ioctl_evt_str(int event)
{
    EVT_STR *evtp=currentE_evts;

    while (evtp && evtp->num>=0 && evtp->num!=event)
        evtp++;
    return(evtp && evtp->num>=0 && strlen(evtp->str)>6 ? &evtp->str[6] : "?");
}
//----------------------------------------------------------------------

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
#include "event.h"
#include "SdioRegs.h"
#include "misc_defs.h"

using namespace qindesign::network;

#define MAX_HANDLERS    20
#define MAX_EVENT_STATUS 16

//T4_SDIO sdio;

static int num_handlers = 0;
event_handler_t event_handlers[MAX_HANDLERS];
WORD event_ports[MAX_HANDLERS];
extern void cwydump(unsigned char *memory, unsigned int len);

IPAddress my_ip; // = Ethernet.localIP();

extern W4343WCard wifiCard;
extern int display_mode;
extern uint8_t my_mac[6];
uint8_t rxdata[RXDATA_LEN];
BYTE txbuff[TXDATA_LEN];
uint8_t eventbuf[1600];
uint8_t event_mask[EVENT_MAX / 8];
Event local;
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

#define NUM_ARP_ENTRIES 10
ARP_ENTRY arp_entries[NUM_ARP_ENTRIES];
int arp_idx;

MACADDR bcast_mac={0xff,0xff,0xff,0xff,0xff,0xff};
EVENT_INFO event_info;

TX_MSG tx_msg = {.sdpcm = {.chan=SDPCM_CHAN_DATA, .hdrlen=sizeof(SDPCM_HDR)+2},
                 .bdc =   {.flags=0x20}};

extern IOCTL_MSG ioctl_txmsg, ioctl_rxmsg;
uint8_t sd_tx_seq;
uint32_t ping_tx_time, ping_rx_time;

// Initialise the IP stack, using static address if provided
//int ip_init(BYTE *ip)
int Event::ipInit(IPAddress addr) {
  my_ip = addr;
  return(1);
}

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

// Find saved ARP response
bool ip_find_arp(IPAddress addr, MACADDR mac) {
//printf("ip_find_arp()\n");
    int n=0, i=arp_idx;
    bool ok=0;
    
    do
    {
        i = i == 0 ? NUM_ARP_ENTRIES-1 : i-1;
        ok = (IP_CMP(addr, arp_entries[i].ipaddr));
    } while (!ok && ++n<NUM_ARP_ENTRIES);
    if (ok)
        MAC_CPY(mac, arp_entries[i].mac);
    return(ok);
}

// Transmit an ARP frame
int ip_tx_arp(MACADDR mac, IPAddress addr, WORD op) {
printf("ip_tx_arp()\n");
    int n = ip_make_arp(txbuff, mac, addr, op);
printf("(ARP)n = %d\n",n);
    return(local.ip_tx_eth(txbuff, n));
}

// Receive incoming ARP data
int ip_rx_arp(BYTE *data, int dlen) {
printf("ip_rx_arp()\n");
    ETHERHDR *ehp=(ETHERHDR *)data;
    ARPKT *arp = (ARPKT *)&data[sizeof(ETHERHDR)];
    WORD op = htons(arp->op);

    if (display_mode & DISP_ETH)
        ip_print_eth(data);
    if IP_CMP(arp->dip, my_ip)
    {
        if (display_mode & DISP_ARP)
            ip_print_arp(arp);
        if (op == ARPREQ)
            ip_tx_arp(ehp->srce, arp->sip, ARPRESP);
        else if (op == ARPRESP)
            ip_save_arp(arp->smac, arp->sip);
        return(1);
    }
    return(0);
}

// Create an ARP frame // Returning 12 bytes to many!!!!
int ip_make_arp(BYTE *buff, MACADDR mac, IPAddress addr, WORD op) {
printf("ip_make_arp()\n");
    int n = ip_add_eth(buff, op==ARPREQ ? bcast_mac : mac, my_mac, PCOL_ARP);
Serial.printf("(ip_make_arp)n = %d\n",n);

    ARPKT *arp = (ARPKT *)&buff[n];
    MAC_CPY(arp->smac, my_mac);
    MAC_CPY(arp->dmac, op==ARPREQ ? bcast_mac : mac);
    arp->hrd = htons(HTYPE);
    arp->pro = htons(ARPPRO);
    arp->hln = MACLEN;
    arp->pln = sizeof(DWORD);
    arp->op  = htons(op);
    arp->dip = addr;
    arp->sip = my_ip;
    if (display_mode & DISP_ARP)
        ip_print_arp(arp);
//print_mac_addr(arp->smac);
//printf("\n");
//print_mac_addr(arp->dmac);
printf("sizeof(ARPKT) = %d\n",sizeof(ARPKT));
    return(n + sizeof(ARPKT));
}

// Save ARP result
void ip_save_arp(MACADDR mac, IPAddress addr) {
printf("save_arp()\n");
    MAC_CPY(arp_entries[arp_idx].mac, mac);
    arp_entries[arp_idx].ipaddr = addr;
    arp_idx = (arp_idx+1) % NUM_ARP_ENTRIES;
}

// Check if IP frame
int ip_check_frame(BYTE *data, int dlen) {
    uint8_t *p = data;
    ETHERHDR *ehp=(ETHERHDR *)p;
    IPHDR *ip = (IPHDR *)&p[sizeof(ETHERHDR)];

    return ((uint8_t)dlen >= sizeof(ETHERHDR)+sizeof(ARPKT) &&
        (!MAC_IS_BCAST(ehp->dest) || MAC_CMP(ehp->dest, my_mac)) && // Changed "(MAC_IS_BCAST(ehp->dest)" to "(!MAC_IS_BCAST(ehp->dest)"
        (htons(ehp->ptype) == PCOL_IP) &&
        (IP_IS_BCAST(ip->dip) || IP_CMP(ip->dip, my_ip) || IP_IS_ZERO(my_ip)) &&
        sizeof(ETHERHDR) + htons(ip->len) <= (uint16_t)dlen);
}

// Handler for incoming ARP frame
int arp_event_handler(EVENT_INFO *eip) {
printf("arp_event_handler()\n");
    uint8_t *p = eip->data;
    ETHERHDR *ehp=(ETHERHDR *)p;
    if (eip->chan == SDPCM_CHAN_DATA &&
        (uint8_t)eip->dlen >= sizeof(ETHERHDR)+sizeof(ARPKT) &&
                               htons(ehp->ptype) == PCOL_ARP &&
                                    (MAC_IS_BCAST(ehp->dest) ||
                                  MAC_CMP(ehp->dest, my_mac) ))
    {
        return(ip_rx_arp(p, eip->dlen));
    }
    return(0);
}

// Handler for incoming ICMP frame
int icmp_event_handler(EVENT_INFO *eip) {
Serial.printf("icmp_event_handler()\n");
    uint8_t *p = eip->data;
    IPHDR *ip = (IPHDR *)&p[sizeof(ETHERHDR)];
    if (eip->chan == SDPCM_CHAN_DATA &&
        ip->pcol == PICMP &&
        ip_check_frame(p, eip->dlen) &&
        IP_CMP(ip->dip, my_ip) &&
        (uint8_t)eip->dlen > sizeof(ETHERHDR)+sizeof(IPHDR)+sizeof(ICMPHDR))
    {
        return(ip_rx_icmp(p, eip->dlen));
    }
    return(0);
}

/* Calculate TCP-style checksum, add to old value */
WORD add_csum(WORD sum, void *dp, int count) {
    WORD n=count>>1, *p=(WORD *)dp, last=sum;

    while (n--)
    {
        sum += *p++;
        if (sum < last)
            sum++;
        last = sum;
    }
    if (count & 1)
        sum += *p & 0x00ff;
    if (sum < last)
        sum++;
    return(sum);
}

// Add data to buffer, return length
int ip_add_data(BYTE *buff, void *data, int len) {
    if (len>0 && data)
        memcpy(buff, data, len);
    return(len);
}

// Add ICMP header to buffer, return byte count
int ip_add_icmp(BYTE *buff, BYTE type, BYTE code, void *data, WORD dlen) {
    ICMPHDR *icmp=(ICMPHDR *)buff;
    WORD len=sizeof(ICMPHDR);
    static WORD seq=1;

    icmp->type = type;
    icmp->code = code;
    icmp->seq = htons(seq++);
    icmp->ident = icmp->check = 0;
    len += ip_add_data(&buff[len], data, dlen);
    icmp->check = 0xffff ^ add_csum(0, icmp, len);
    return(len);
}

// Add IP header to buffer, return length
int ip_add_hdr(BYTE *buff, IPAddress dip, BYTE pcol, WORD dlen) {
    static WORD ident=1;
    IPHDR *ip=(IPHDR *)buff;

    ip->ident = htons(ident++);
    ip->frags = 0;
    ip->vhl = 0x40+(sizeof(IPHDR)>>2);
    ip->service = 0;
    ip->ttl = 100; // Time To Live.
    ip->pcol = pcol;
    ip->sip = my_ip;
    ip->dip = dip;
    ip->len = htons(dlen + sizeof(IPHDR));
    ip->check = 0;
    ip->check = 0xffff ^ add_csum(0, ip, sizeof(IPHDR));
    return(sizeof(IPHDR));
}

// Send transmit data
int Event::ip_tx_eth(BYTE *buff, int len) {
printf("ip_tx_eth()\n");
printf("len = %d\n",len);
  if(display_mode & DISP_ETH) ip_print_eth(buff);
    return(event_net_tx(buff, len));
}

// Add Ethernet header to buffer, return byte count
int ip_add_eth(BYTE *buff, MACADDR dmac, MACADDR smac, WORD pcol) {
    ETHERHDR *ehp = (ETHERHDR *)buff;

    MAC_CPY(ehp->dest, dmac);
    MAC_CPY(ehp->srce, smac);
    ehp->ptype = htons(pcol);
    return(sizeof(ETHERHDR));
}

// Create ICMP request
int ip_make_icmp(BYTE *buff, MACADDR mac, IPAddress dip, BYTE type, BYTE code, BYTE *data, int dlen) {
    int n = ip_add_eth(buff, mac, my_mac, PCOL_IP);
    
    n += ip_add_hdr(&buff[n], dip, PICMP, sizeof(ICMPHDR)+dlen);
    n += ip_add_icmp(&buff[n], type, code, data, dlen);
    return(n);
}

// Transmit ICMP request
int Event::ip_tx_icmp(MACADDR mac, IPAddress dip, BYTE type, BYTE code, BYTE *data, int dlen) {
    int n=ip_make_icmp(txbuff, mac, dip, type, code, data, dlen);
    
    if (display_mode & DISP_ICMP)
        ip_print_icmp((IPHDR *)&txbuff[sizeof(ETHERHDR)]);
    ping_tx_time = micros();
    return(ip_tx_eth(txbuff, n));
}

/*
// Handler for incoming ICMP frame
int Event::icmp_event_handler(EVENT_INFO *eip) {
Serial.printf("icmp_event_handler()\n");
    uint8_t *p = eip->data;
    IPHDR *ip = (IPHDR *)&p[sizeof(ETHERHDR)];
    if (eip->chan == SDPCM_CHAN_DATA &&
        ip->pcol == PICMP &&
        ip_check_frame(p, eip->dlen) &&
        IP_CMP(ip->dip, my_ip) &&
        (uint8_t)eip->dlen > sizeof(ETHERHDR)+sizeof(IPHDR)+sizeof(ICMPHDR))
    {
        return(ip_rx_icmp(p, eip->dlen));
    }
    return(0);
}
*/
// Run event handlers, until one returns non-zero
int Event::event_handle(EVENT_INFO *eip) {
Serial.printf("event_handle()\n");
    int i, ret=0;
    for (i=0; i<num_handlers && !ret; i++)
    {
        eip->server_port = event_ports[i];
        ret = event_handlers[i](eip);
    }
    return(ret);
}

// Receive incoming ICMP data
int ip_rx_icmp(BYTE *data, int dlen) {
Serial.printf("ip_rx_icmp()\n");
    uint8_t *p = data;
    ETHERHDR *ehp=(ETHERHDR *)p;
    IPHDR *ip = (IPHDR *)&p[sizeof(ETHERHDR)];
    ICMPHDR *icmp = (ICMPHDR *)&p[sizeof(ETHERHDR)+sizeof(IPHDR)];
    int n;
    if (display_mode & DISP_ICMP)
        ip_print_icmp(ip);
    if (icmp->type == ICREQ)
    {
        ip_add_eth(data, ehp->srce, my_mac, PCOL_IP);
        ip->dip = ip->sip;
        ip->sip = my_ip;
        icmp->check = add_csum(icmp->check, &icmp->type, 1);
        icmp->type = ICREP;
        n = htons(ip->len);

        return(local.ip_tx_eth(data, sizeof(ETHERHDR)+n+sizeof(ICMPHDR)));
    }
    else
      if (icmp->type == ICREP) {
        ping_rx_time = micros();
      }
    return(0);
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
Serial.printf("event_net_tx()\n");
Serial.printf("len = %d\n",len);
printf("***************** cwydump(data,len) ************************\n");
cwydump((uint8_t *)data,len); 
printf("**************************************************************************\n");
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
printf("***************** cwydump(txp->data,len) ************************\n");
cwydump((uint8_t *)txp->data,len); 
printf("**************************************************************************\n");
    while (txlen & 3) dp[txlen++] = 0;
printf("***************** cwydump(dp,txlen) ************************\n");
cwydump((uint8_t *)dp,txlen); 
printf("**************************************************************************\n");
    return (wifiCard.cardCMD53_write(SD_FUNC_RAD, 0, (uint8_t *)dp, txlen, false));
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

// Convert byte-order in a 'short' variable
WORD Event::htons(WORD w) {
    return(w<<8 | w>>8);
}

// Display MAC addresses in Ethernet frame
void ip_print_eth(BYTE *buff) {
    ETHERHDR *ehp = (ETHERHDR *)buff;

    print_mac_addr(ehp->srce);
    printf("->");
    print_mac_addr(ehp->dest);
    printf("\n");
    printf("ehp->ptype = %4.4x\n",htons(ehp->ptype));
    printf("\n");
}

// Display IP address
void print_ip_addr(IPAddress a) {
    printf("%u.%u.%u.%u", a[0],a[1],a[2],a[3]);
}

// Display IP addresses in IP header
void print_ip_addrs(IPHDR *ip) {
    print_ip_addr(ip->sip);
    Serial.printf("->");
    print_ip_addr(ip->dip);
}

// Display MAC address
void print_mac_addr(MACADDR mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

// Display ARP
void ip_print_arp(ARPKT *arp) {
    WORD op=htons(arp->op);

    print_ip_addr(arp->sip);
    printf("->");
    print_ip_addr(arp->dip);
    printf(" ARP %s\n", op==ARPREQ ? "request" : op==ARPRESP ? "response" : "");
}

// Display ICMP
void ip_print_icmp(IPHDR *ip) {
    ICMPHDR *icmp = (ICMPHDR *)((BYTE *)ip + sizeof(IPHDR));
    
    print_ip_addrs(ip);
    printf(" ICMP %s\n", icmp->type==ICREQ     ? "request" : 
                        icmp->type==ICREP     ? "response" : 
                        icmp->type==ICUNREACH ? "dest unreachable" : 
                        icmp->type==ICQUENCH  ? "srce quench" : "?");
}

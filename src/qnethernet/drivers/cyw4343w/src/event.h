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
#ifndef EVENT_H
#define EVENT_H

#include "Arduino.h"
#include <stdint.h>
#include "ioctl_T4.h"
#include "misc_defs.h"

#define EVT(e)      {e, #e}

#define NO_EVTS     {EVT(-1)}
#define ESCAN_EVTS  {EVT(WLC_E_ESCAN_RESULT), EVT(-1)}
#define JOIN_EVTS   {EVT(WLC_E_SET_SSID), EVT(WLC_E_LINK), EVT(WLC_E_AUTH), \
        EVT(WLC_E_DEAUTH_IND), EVT(WLC_E_DISASSOC_IND), EVT(WLC_E_PSK_SUP), EVT(-1)}

// Ethernet header (sdpcm_ethernet_header_t)
typedef struct {
    uint8_t dest_addr[6],
            srce_addr[6];
    uint16_t type;
} ETHER_HDR;

// Vendor-specific (Broadcom) Ethernet header (sdpcm_bcmeth_header_t) // 10 bytes
typedef struct {
    uint16_t subtype,
             len;
    uint8_t  ver,
             oui[3];
    uint16_t usr_subtype;
} BCMETH_HDR;

// Raw event header (sdpcm_raw_event_header_t)
typedef struct {
    uint16_t ver,
             flags;
    uint32_t event_type,
             status,
             reason,
             auth_type,
             datalen;
    uint8_t addr[6];
    char ifname[16];
    uint8_t ifidx,
            bsscfgidx;
} EVENT_HDR;

// Async event parameters, used internally
typedef struct {
    uint32_t chan;                      // From SDPCM header
    uint32_t event_type, status, reason;// From async event (null if not event)
    uint16_t flags;
    uint16_t link;                      // Link state
    uint32_t join;                      // Joining state
    uint8_t *data;                      // Data block
    int     dlen;
    int     server_port;                // Port number if server
    int     sock;                       // Socket number if TCP
} EVENT_INFO;

// Scan result header (part of wl_escan_result_t)
typedef struct {
    uint32_t buflen;
    uint32_t version;
    uint16_t sync_id;
    uint16_t bss_count;
} SCAN_RESULT_HDR;

// BSS info from EScan (part of wl_bss_info_t)
typedef struct
{
    uint32_t version;              // version field
    uint32_t length;               // byte length of data in this record, starting at version and including IEs
    uint8_t bssid[6];              // Unique 6-byte MAC address
    uint16_t beacon_period;        // Interval between two consecutive beacon frames. Units are Kusec
    uint16_t capability;           // Capability information
    uint8_t ssid_len;              // SSID length
    uint8_t ssid[32];              // Array to store SSID
    uint32_t nrates;               // Count of rates in this set
    uint8_t rates[16];             // rates in 500kbps units, higher bit set if basic
    uint16_t channel;              // Channel specification for basic service set
    uint16_t atim_window;          // Announcement traffic indication message window size. Units are Kusec
    uint8_t dtim_period;           // Delivery traffic indication message period
    int16_t rssi;                  // receive signal strength (in dBm)
    int8_t phy_noise;              // noise (in dBm)
    // The following fields assume the 'version' field is 109 (0x6D)
    uint8_t n_cap;                 // BSS is 802.11N Capable
    uint32_t nbss_cap;             // 802.11N BSS Capabilities (based on HT_CAP_*)
    uint8_t ctl_ch;                // 802.11N BSS control channel number
    uint32_t reserved32[1];        // Reserved for expansion of BSS properties
    uint8_t flags;                 // flags
    uint8_t reserved[3];           // Reserved for expansion of BSS properties
    uint8_t basic_mcs[16];         // 802.11N BSS required MCS set
    uint16_t ie_offset;            // offset at which IEs start, from beginning
    uint32_t ie_length;            // byte length of Information Elements
    int16_t snr;                   // Average SNR(signal to noise ratio) during frame reception
    // Variable-length Information Elements follow, see cyw43_ll_wifi_parse_scan_result
} BSS_INFO;

// Escan result event (excluding 12-byte IOCTL header and BDC header)
typedef struct {
    ETHER_HDR ether;
    BCMETH_HDR bcmeth;
    EVENT_HDR eventh;
    SCAN_RESULT_HDR scanh;
    BSS_INFO info;
} ESCAN_RESULT;

typedef struct
{
    SDPCM_HDR sdpcm;
    uint16_t pad;
    BDC_HDR_T4 bdc;
    uint8_t data[TXDATA_LEN];
} TX_MSG;

typedef int (*event_handler_t)(EVENT_INFO *eip);

class Event;
class Event {
  public:
  bool init();
  bool add_event_handler(event_handler_t);
  bool add_server_event_handler(event_handler_t fn, WORD port);
  int event_handle(EVENT_INFO *eip);
  int pollEvents(void);
  int ioctl_enable_evts(EVT_STR *evtp);  
  const char *ioctl_evt_status_str(int status);
  const char *ioctl_evt_str(int event);

  uint32_t ioctl_get_event(sdpcm_header_t *hp, uint8_t *data, int maxlen);
  char *sdpcm_chan_str(int chan);
  char *event_str(int event);
  int event_net_tx(void *data, int len);

  protected:
  
  private:
	
};
extern Event event;
#endif

#ifndef IOCTL_T4H
#define IOCTL_T4H


#include <Arduino.h>

//#include "../whd/whd_types.h"
//#include "../whd/whd_events.h"
#include "whd_wlioctl.h"

// IOCTL commands
#define IOCTL_UP                    2
#define IOCTL_SET_SCAN_CHANNEL_TIME 0xB9

#define IOCTL_POLL_MSEC     2
#define SCAN_CHAN_TIME      40
#define SCANTYPE_ACTIVE     0
#define SCANTYPE_PASSIVE    1

#define IOCTL_WAIT          30      // Time to wait for ioctl response (msec)
#define IOCTL_WAIT_USEC     2000
#define MAX_CHUNK_LEN       400

#define IOCTL_MAX_BLKLEN_T4 512  // cyw43_T4_SDIO needs this.
#define IOCTL_MAX_BLKLEN    1600 // pico versions need this.

#define SSID_MAXLEN         32

#define EVENT_SET_SSID      0
#define EVENT_JOIN          1
#define EVENT_AUTH          3
#define EVENT_LINK          16
#define EVENT_MAX           208
#define SET_EVENT(msk, e)   msk[e/8] |= 1 << (e & 7)

#define DL_BEGIN			0x0002
#define DL_END				0x0004
#define DL_TYPE_CLM		    2

#define SDPCM_CHAN_CTRL     0       // SDPCM control channel
#define SDPCM_CHAN_EVT      1       // SDPCM async event channel
#define SDPCM_CHAN_DATA     2       // SDPCM data channel

// WiFi bands
#define WIFI_BAND_ANY       0
#define WIFI_BAND_5GHZ      1
#define WIFI_BAND_2_4GHZ    2

typedef uint16_t wl_chanspec_t;  /**< Channel specified in uint16_t */
#define MCSSET_LEN    16 /**< Maximum allowed mcs rate */


#pragma pack(1)

typedef struct {
    int32_t num;
    const char * str;
} EVT_STR;

struct brcmf_dload_data_le {
	uint16_t flag;
	uint16_t dload_type;
	uint32_t len;
	uint32_t crc;
	uint8_t data[1];
};

struct brcmf_ssid_le {
	uint32_t SSID_len;
	uint8_t SSID[SSID_MAXLEN];
};

struct brcmf_scan_params_le {
    struct brcmf_ssid_le ssid_le;
    uint8_t bssid[6];
    int8_t  bss_type;
    int8_t  scan_type;
    int32_t nprobes;
    int32_t active_time;
    int32_t passive_time;
    int32_t home_time;
    uint16_t nchans;
    uint16_t nssids;
    uint16_t channel_list[1];   // channel list (not used)
    //uint8_t  chans[14][2],
    //         ssids[1][SSID_MAXLEN];
};

struct brcmf_scan_params_v2_le {
	uint16_t version;		/* structure version */
	uint16_t length;		/* structure length */
	struct brcmf_ssid_le ssid_le;
	uint8_t bssid[6];
	int8_t bss_type;
	uint8_t pad;
	uint32_t scan_type;
	int32_t nprobes;
	int32_t active_time;
    int32_t passive_time;
    int32_t home_time;
    uint16_t nchans;
    uint16_t nssids;
    uint8_t  chans[14][2],
             ssids[1][SSID_MAXLEN];
};

#define WHD_MSG_IFNAME_MAX 16 /**< Max length of Interface name */

/**
 * Structure to store ethernet header fields in event packets
 */
typedef struct whd_event_eth_hdr
{
    uint16_t subtype;      /**< Vendor specific..32769 */
    uint16_t length;       /**< Length of ethernet header*/
    uint8_t version;       /**< Version is 0 */
    uint8_t oui[3];        /**< Organizationally Unique Identifier */
    uint16_t usr_subtype;  /**< User specific data */
} whd_event_eth_hdr_t;

/**
 *  Structure to store fields after ethernet header in event message
 */
struct whd_event_msg
{
    uint16_t version;               /**< Version */
    uint16_t flags;                 /**< see flags below */
    uint32_t event_type;            /**< Event type indicating a response from firmware for IOCTLs/IOVARs sent */
    uint32_t status;                /**< Status code corresponding to any event type */
    uint32_t reason;                /**< Reason code associated with the event occurred */
    uint32_t auth_type;             /**< WLC_E_AUTH: 802.11 AUTH request */
    uint32_t datalen;               /**< Length of data in event message */
    whd_mac_t addr;                 /**< Station address (if applicable) */
    char ifname[WHD_MSG_IFNAME_MAX];               /**< name of the incoming packet interface */
    uint8_t ifidx;                                 /**< destination OS i/f index */
    uint8_t bsscfgidx;                             /**< source bsscfg index */
};

/**
 * Structure to store ethernet destination, source and ethertype in event packets
 */
typedef struct whd_event_ether_header
{
    whd_mac_t destination_address; /**< Ethernet destination address */
    whd_mac_t source_address;      /**< Ethernet source address */
    uint16_t ethertype;            /**< Ethertype for identifying event packets */
} whd_event_ether_header_t;

/** @cond */
typedef struct whd_event_msg whd_event_header_t;
/** @endcond */

/**
 * Event structure used by driver msgs
 */
typedef struct whd_event
{
    whd_event_ether_header_t eth;    /**< Variable to store ethernet destination, source and ethertype in event packets */
    whd_event_eth_hdr_t eth_evt_hdr; /**< Variable to store ethernet header fields in event message */
    whd_event_header_t whd_event;    /**< Variable to store rest of the event packet fields after ethernet header */
    /* data portion follows */
} whd_event_t;

struct brcmf_escan_params_le {
	uint32_t version;
	uint16_t action;
	uint16_t _;
	union {
		struct brcmf_scan_params_le params_le;
		struct brcmf_scan_params_v2_le params_v2_le;
	};
};

// Event structures
typedef struct {
    whd_event_eth_hdr_t   hdr;
    struct whd_event_msg  msg;
    uint8_t data[1];
} ETH_EVENT;

typedef struct {
    uint8_t pad[10];
    whd_event_ether_header_t eth_hdr;
    union {
        ETH_EVENT event;
        uint8_t data[1];
    };
} ETH_EVENT_FRAME;

typedef struct {
    uint8_t seq,      
            chan,
            nextlen,
            hdrlen,
            flow,
            credit,
            reserved[2];
} sdpcm_sw_header;

typedef struct {
    sdpcm_sw_header sw_header;
    uint32_t cmd;       // cdc_header
    uint16_t outlen,
             inlen;
    uint32_t flags,
             status;
    uint8_t data[IOCTL_MAX_BLKLEN_T4];
} IOCTL_CMD_T4;

// IOCTL header
typedef struct {
    uint32_t cmd;       // cdc_header
    uint16_t outlen,
             inlen;
    uint32_t flags,
             status;
} IOCTL_HDR;

typedef struct {
    uint16_t len;
    uint8_t  reserved1,
             flags,
             reserved2[2],
             pad[2];
} IOCTL_GLOM_HDR;

typedef struct {
    IOCTL_GLOM_HDR glom_hdr;
    IOCTL_CMD_T4  cmd;
} IOCTL_GLOM_CMD;

typedef struct
{
    uint16_t len,           // sdpcm_header.frametag
             notlen;
    union 
    {
        IOCTL_CMD_T4 cmd;
        IOCTL_GLOM_CMD glom_cmd;
    };
} IOCTL_MSG_T4;

typedef struct {
    uint16_t        len,       // sdpcm_header.frametag
                    notlen;
    sdpcm_sw_header sw_header;
} sdpcm_header_t;

// Escan result event (excluding 12-byte IOCTL header)
typedef struct {
    uint8_t pad[10];
    whd_event_t event;
    wl_escan_result_t escan;
} escan_result;

// SDPCM header
typedef struct {
    uint16_t len,       // sdpcm_header.frametag
             notlen;
    uint8_t  seq,       // sdpcm_sw_header
             chan,
             nextlen,
             hdrlen,
             flow,
             credit,
             reserved[2];
} SDPCM_HDR;

// BDC header
typedef struct {
    uint8_t flags;
    uint8_t priority;
    uint8_t flags2;
    uint8_t offset;
} BDC_HDR_T4;

// IOCTL response with SDPCM header
// (then an IOCTL header after some padding)
typedef union
{
    SDPCM_HDR sdpcm;
    uint8_t data[IOCTL_MAX_BLKLEN];
} IOCTL_RSP;

// IOCTL command or response message
typedef struct
{
    union 
    {
        IOCTL_CMD_T4 cmd;
        IOCTL_RSP rsp;
        uint8_t data[IOCTL_MAX_BLKLEN];
    };
} IOCTL_MSG;

#pragma pack()

/* List of events */
#define WLC_E_NONE                         (0x7FFFFFFE) /**< Indicates the end of the event array list */

#define WLC_E_SET_SSID                     0 /**< Indicates status of set SSID. This event occurs when STA tries to join the AP*/
#define WLC_E_AUTH                         3 /**< 802.11 AUTH request event occurs when STA tries to get authenticated with the AP  */
#define WLC_E_DEAUTH                       5 /**< 802.11 DEAUTH request event occurs when the the SOFTAP is stopped to deuthenticate the connected stations*/
#define WLC_E_DEAUTH_IND                   6 /**< 802.11 DEAUTH indication event occurs when the STA gets deauthenticated by the AP */
#define WLC_E_ASSOC                        7 /**< 802.11 ASSOC request event occurs when STA joins the AP */
#define WLC_E_ASSOC_IND                    8 /**< 802.11 ASSOC indication occurs when a station joins the SOFTAP that is started */
#define WLC_E_REASSOC                      9 /**< 802.11 REASSOC request event when the STA again gets associated with the AP */
#define WLC_E_REASSOC_IND                 10 /**< 802.11 REASSOC indication occurs when a station again reassociates with the SOFTAP*/
#define WLC_E_DISASSOC                    11 /**< 802.11 DISASSOC request occurs when the STA the tries to leave the AP*/
#define WLC_E_DISASSOC_IND                12 /**< 802.11 DISASSOC indication occurs when the connected station gets disassociates from SOFTAP,
                                                  also when STA gets diassociated by the AP*/
#define WLC_E_LINK                        16 /**< generic link indication */
#define WLC_E_PROBREQ_MSG                 44 /**< Indicates probe request received for the SOFTAP started*/
#define WLC_E_PSK_SUP                     46 /**< WPA Handshake fail during association*/
#define WLC_E_ACTION_FRAME                59 /**< Indicates Action frame Rx */
#define WLC_E_ACTION_FRAME_COMPLETE       60 /**< Indicates Action frame Tx complete */
#define WLC_E_ESCAN_RESULT                69 /**< escan result event occurs when we scan for the networks */

/* List of status codes - Applicable for any event type */
#define WLC_E_STATUS_SUCCESS        0   /**< operation was successful */
#define WLC_E_STATUS_FAIL           1   /**< operation failed */
#define WLC_E_STATUS_TIMEOUT        2   /**< operation timed out */
#define WLC_E_STATUS_NO_NETWORKS    3   /**< failed due to no matching network found */
#define WLC_E_STATUS_ABORT          4   /**< operation was aborted */
#define WLC_E_STATUS_NO_ACK         5   /**< protocol failure: packet not ack'd */
#define WLC_E_STATUS_UNSOLICITED    6   /**< AUTH or ASSOC packet was unsolicited */
#define WLC_E_STATUS_ATTEMPT        7   /**< attempt to assoc to an auto auth configuration */
#define WLC_E_STATUS_PARTIAL        8   /**< scan results are incomplete */
#define WLC_E_STATUS_NEWSCAN        9   /**< scan aborted by another scan */
#define WLC_E_STATUS_NEWASSOC       10  /**< scan aborted due to assoc in progress */
#define WLC_E_STATUS_11HQUIET       11  /**< 802.11h quiet period started */
#define WLC_E_STATUS_SUPPRESS       12  /**< user disabled scanning (WLC_SET_SCANSUPPRESS) */
#define WLC_E_STATUS_NOCHANS        13  /**< no allowable channels to scan */
#define WLC_E_STATUS_CCXFASTRM      14  /**< scan aborted due to CCX fast roam */
#define WLC_E_STATUS_CS_ABORT       15  /**< abort channel select */
#define WLC_E_STATUS_ERROR          16  /**< request failed due to error */
#define WLC_E_STATUS_INVALID        0xff /**< Invalid status code to init variables. */

#define WLC_SUP_STATUS_OFFSET      (256) /**< Status offset added to the status codes to match the values from firmware. */

#endif // IOCTL_H

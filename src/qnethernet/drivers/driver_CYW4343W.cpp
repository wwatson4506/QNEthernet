
//#include "driver_CYW4343W.h"

#include "qnethernet/lwip_driver.h"

#ifdef QNETHERNET_INTERNAL_DRIVER_CYW4343W

#pragma message("Using CYW4343W QNEthernet Driver")

#include "lwip/arch.h"
#include "lwip/debug.h"
#include "lwip/err.h"
#include "lwip/stats.h"
#include "qnethernet/internal/macro_funcs.h"
#include "qnethernet/platforms/pgmspace.h"

#include "cyw4343w/src/cyw43_T4_SDIO.h"
#include "cyw4343w/src/join.h"
#include "cyw4343w/src/secrets.h"

W4343WCard wifiCard;
Event evt;
void cywdump(unsigned char *memory, unsigned int len);
void waitMyInput(void);
static int s_checkLinkStatusState = 0;

uint32_t poll_ticks;
#define EVENT_POLL_USEC    100000 //100000

// Defines the control and status region of the receive buffer descriptor.
enum enet_rx_bd_control_status {
  kEnetRxBdEmpty           = 0x8000U,  // Empty bit
  kEnetRxBdRxSoftOwner1    = 0x4000U,  // Receive software ownership
  kEnetRxBdWrap            = 0x2000U,  // Wrap buffer descriptor
  kEnetRxBdRxSoftOwner2    = 0x1000U,  // Receive software ownership
  kEnetRxBdLast            = 0x0800U,  // Last BD in the frame (L bit)
  kEnetRxBdMiss            = 0x0100U,  // Miss; in promiscuous mode; needs L
  kEnetRxBdBroadcast       = 0x0080U,  // Broadcast
  kEnetRxBdMulticast       = 0x0040U,  // Multicast
  kEnetRxBdLengthViolation = 0x0020U,  // Receive length violation; needs L
  kEnetRxBdNonOctet        = 0x0010U,  // Receive non-octet aligned frame; needs L
  kEnetRxBdCrc             = 0x0004U,  // Receive CRC or frame error; needs L
  kEnetRxBdOverrun         = 0x0002U,  // Receive FIFO overrun; needs L
  kEnetRxBdTrunc           = 0x0001U,  // Frame is truncated
};

// Defines the control status of the transmit buffer descriptor.
enum enet_tx_bd_control_status {
  kEnetTxBdReady        = 0x8000U,  // Ready bit
  kEnetTxBdTxSoftOwner1 = 0x4000U,  // Transmit software ownership
  kEnetTxBdWrap         = 0x2000U,  // Wrap buffer descriptor
  kEnetTxBdTxSoftOwner2 = 0x1000U,  // Transmit software ownership
  kEnetTxBdLast         = 0x0800U,  // Last BD in the frame (L bit)
  kEnetTxBdTransmitCrc  = 0x0400U,  // Transmit CRC; needs L
};

typedef struct {
  uint16_t length;
  uint16_t status;
  void*    buffer;
  uint16_t extend0;
  uint16_t extend1;
  uint16_t checksum;
  uint8_t  prototype;
  uint8_t  headerlen;
  uint16_t unused0;
  uint16_t extend2;
  uint32_t timestamp;
  uint16_t unused1;
  uint16_t unused2;
  uint16_t unused3;
  uint16_t unused4;
} enetbufferdesc_t;


static struct LinkInfo s_linkInfo;

extern "C" {

FLASHMEM void driver_get_capabilities(struct DriverCapabilities* const dc) {
  dc->isMACSettable                = false;
  dc->isLinkStateDetectable        = true;
  dc->isLinkSpeedDetectable        = false;
  dc->isLinkSpeedSettable          = false;
  dc->isLinkFullDuplexDetectable   = false;
  dc->isLinkFullDuplexSettable     = false;
  dc->isAutoNegotiationSettable    = false;
  dc->isLinkCrossoverDetectable    = false;
  dc->isAutoNegotiationRestartable = false;
  dc->isPHYResettable              = false;
}

typedef enum {
  kInitStateStart,           // Unknown hardware
  kInitStateNoHardware,      // No PHY
  kInitStateHasHardware,     // Has PHY
  kInitStatePHYInitialized,  // PHY's been initialized
  kInitStateInitialized,     // PHY and MAC have been initialized
} enet_init_states_t;

static enet_init_states_t s_initState = kInitStateStart;

void driver_get_system_mac(uint8_t mac[ETH_HWADDR_LEN]) {
  printf("driver_get_system_mac\n");
  wifiCard.getMACAddress((uint8_t *)mac);
}

bool driver_get_mac(uint8_t mac[ETH_HWADDR_LEN]) {
//  printf("driver_get_mac\n");
  if(join_check() != JOIN_OK) return false;
  wifiCard.getMACAddress((uint8_t *)mac);
  return true;
}

bool driver_set_mac(const uint8_t mac[ETH_HWADDR_LEN]) {
//  printf("driver_set_mac\n");
  if(join_check() != JOIN_OK) return false;
  wifiCard.getMACAddress((uint8_t *)mac);
  return true;
}

bool driver_has_hardware() {
//  printf("\ndriver_has_hardware\n");
  switch (s_initState) {
    case kInitStateHasHardware:
      ATTRIBUTE_FALLTHROUGH;
    case kInitStatePHYInitialized:
      ATTRIBUTE_FALLTHROUGH;
    case kInitStateInitialized:
      return true;
    case kInitStateNoHardware:
      return false;
    default:
      break;
  }
  //////////////////////////////////////////
  //Begin parameters: 
  //SDIO1 (false), SDIO2 (true)
  //WL_REG_ON pin 
  //WL_IRQ pin (-1 to ignore)
  //EXT_LPO pin (optional, -1 to ignore)
  //////////////////////////////////////////
  if(wifiCard.begin(true, 33, 34, -1) == true) { 
    wifiCard.wifiSetup();
    return (s_initState != kInitStateNoHardware);
  } else {
    printf("Initialization: FAILED! \n");
    return (s_initState = kInitStateNoHardware);
  }
}

void driver_set_chip_select_pin(int pin) {}

bool driver_init(void) {
//  printf("driver_init\n");
  if (s_initState == kInitStateInitialized) {
    return true;
  }
  wifiCard.postInitSettings();
  // Add our event handler to the array of event handlers.
  evt.add_event_handler(join_event_handler);
  delayMicroseconds(1000);
  ustimeout(&poll_ticks, 0);

  // Use "secrets.h" to set MY_SSID, MY_PASSPHRASE, SECURITY.
  if(!join_start(MY_SSID, MY_PASSPHRASE, SECURITY)) {
    printf("Error: can't start network join\n");
    s_initState = kInitStateNoHardware;
    return false;
  }
  // Keep polling until link and join happens.
  while((link_check() != LINK_OK) && (join_check() != JOIN_OK)) {
    evt.pollEvents();
    join_state_poll(MY_SSID, MY_PASSPHRASE, SECURITY);
  }
  s_initState = kInitStateInitialized;
  printf("Initialization Done\n");
  return true;
}

void driver_deinit() {
  printf("driver_deinit\n");
  join_stop();
}

// driver_proc_input() NOT WORKING with ping!!!!
struct pbuf* driver_proc_input(struct netif *netif, int counter) {
  // Finish any pending link and join status check
  if(netif_is_link_up(netif) == 0) return NULL; 
  sdpcm_header_t hp;
  uint8_t bf[MAX_FRAME_LEN];
  uint32_t data_len;
  if((data_len = evt.ioctl_get_event(&hp, bf, MAX_FRAME_LEN)) > 0) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, data_len+ETH_PAD_SIZE, PBUF_RAM);
    if (p == NULL) {
      printf("Failed to allocate pbuf\n");
      return NULL;
    }
    p->len = p->tot_len = data_len+ETH_PAD_SIZE+ETH_PAD_SIZE;
    LWIP_ASSERT("Expected space for pbuf fill",
      pbuf_take(p, (uint8_t *)bf+10, p->tot_len) == ERR_OK);
//  printf("driver_proc_input()\n");
//cywdump((uint8_t *)p->payload,p->tot_len);
    return p;
  }
  return NULL;
}

void driver_poll(struct netif *netif) {
//printf("driver_poll()\n");
  // Get any events, poll the joining state machine
  if(ustimeout(&poll_ticks, EVENT_POLL_USEC)) {
    evt.pollEvents();
    join_state_poll(MY_SSID, MY_PASSPHRASE, SECURITY);
    ustimeout(&poll_ticks, 0);
  }
  uint8_t link_up = join_check() ? 1 : 0;
  if (netif_is_link_up(netif) != link_up) {
    if (link_up) {
      printf("Setting link up\n");
      netif_set_link_up(netif);
      s_checkLinkStatusState = link_up;
    } else {
      printf("Setting link down\n");
      netif_set_link_down(netif);
      s_checkLinkStatusState = link_up;
    }
  }
}


err_t driver_output(struct pbuf *p) {
//printf("driver_output()\n");
  uint8_t *buffer;
  buffer = (uint8_t *)malloc(p->tot_len*sizeof(uint8_t));

  const uint16_t copied = pbuf_copy_partial(p, buffer, p->tot_len, 0);
  if (copied != p->tot_len) {
    return ERR_BUF;
  }
  evt.event_net_tx(buffer, copied + ETH_PAD_SIZE);

//cywdump((uint8_t *)p,p->tot_len);  
//cywdump((uint8_t *)buffer,p->len);  
//waitMyInput();
  free(buffer);
  return ERR_OK;
}

#if QNETHERNET_ENABLE_RAW_FRAME_SUPPORT
bool driver_output_frame(const void *frame, size_t len) {
//  printf("driver_output_frame\n");

  if (len > (UINT16_MAX - ETH_PAD_SIZE)) {
    return false;
  }

  uint8_t *buffer;
  buffer = (uint8_t *)malloc(len*sizeof(uint8_t));

  (void)memcpy((uint8_t*)buffer + ETH_PAD_SIZE, frame, len);
  evt.event_net_tx(buffer, len + ETH_PAD_SIZE);

  free(buffer);

  return true;
}
#endif

void driver_get_link_info(struct LinkInfo* const li) {
  *li = s_linkInfo;
}

size_t driver_get_mtu() {
//  printf("driver_get_mtu()\n");
  return MTU;
}

size_t driver_get_max_frame_len() {
//  printf("driver_get_max_frame_len\n");
  return 1580 - 44;
}

bool driver_set_incoming_mac_address_allowed(const uint8_t mac[ETH_HWADDR_LEN],
                                             bool allow) {
//  printf("driver_set_incoming_address_allowed()\n");
  return false;
}


#if !QNETHERNET_ENABLE_PROMISCUOUS_MODE
bool driver_set_mac_address_allowed(const uint8_t mac[ETH_HWADDR_LEN], bool allow) {
//  printf("driver_set_mac_address_allowed\n");
  return false;
}
#endif

// these functions don't seem to be used right now...
bool driver_is_unknown() {
//  printf("driver_is_unknown\n");
  return false;
}
	 
bool driver_is_link_state_detectable() {
//  printf("driver_is_link_state_detectable\n");
  return true;
}

int driver_link_speed() {
//  printf("driver_link_speed\n"); return 0; }
}

bool driver_link_is_full_duplex() {
//  printf("driver_link_is_full_duplex\n");
  return true;
}

bool driver_link_is_crossover() {
//  printf("driver_link_is_crossover\n");
  return false;
}

} // extern "C"

// Simple wait for input routine.
void waitMyInput()
{
  Serial.println("Press anykey to continue...");
  while (Serial.read() == -1) ;
  while (Serial.read() != -1) ;
}

// Simple hex dump routine.
void cywdump(unsigned char *memory, unsigned int len)
{
   	unsigned int	i=0, j=0;
	unsigned char	c=0;

//	printf("                     (FLASH) MEMORY CONTENTS");
	Serial.printf("\n\rADDR          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
	Serial.printf("\n\r-------------------------------------------------------------\n\r");


	for(i = 0; i <= (len-1); i+=16) {
//		phex16((i + memory));
		Serial.printf("%8.8x",(unsigned int)(i + memory));
		Serial.printf("      ");
		for(j = 0; j < 16; j++) {
			c = memory[i+j];
			Serial.printf("%2.2x",c);
			Serial.printf(" ");
		}
		Serial.printf("  ");
		for(j = 0; j < 16; j++) {
			c = memory[i+j];
			if(c > 31 && c < 127)
				Serial.printf("%c",c);
			else
				Serial.printf(".");
		}
//		_delay_ms(10);
		Serial.printf("\n");
	}

}

#endif

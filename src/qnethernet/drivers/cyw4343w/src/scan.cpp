// Scan.cpp

#include "cyw43_T4_SDIO.h"
#include "SdioRegs.h"
#include "ioctl_T4.h"
#include "event.h"
#include "scan.h"

//extern void waitforInput();
extern W4343WCard wifiCard;
extern sdpcm_header_t iehh;
Event scnevt;

// Network scan parameters
brcmf_escan_params_le scan_params = {
    .version=1, .action=1, ._=0,
    .params_le {
      .ssid_le {
        .SSID_len=0, .SSID={0}
      }, 
    .bssid={0xff,0xff,0xff,0xff,0xff,0xff}, .bss_type=2,
    .scan_type=SCANTYPE_PASSIVE, .nprobes=-1, .active_time=-1,
    .passive_time=-1, .home_time=-1, 
#if SCAN_CHAN == 0
    .nchans=14, .nssids=0, 
//    .chans={{1,0x2b},{2,0x2b},{3,0x2b},{4,0x2b},{5,0x2b},{6,0x2b},{7,0x2b},
//      {8,0x2b},{9,0x2b},{10,0x2b},{11,0x2b},{12,0x2b},{13,0x2b},{14,0x2b}},
#else
    .nchans=1, .nssids=0, .chans={{SCAN_CHAN,0x2b}}, .ssids={{0}}
#endif
    }
};

int ScanNetworks() {
  uint8_t resp1[256];
  EVT_STR escan_evts[] = ESCAN_EVTS;
  uint8_t eventbuf[1600];
  escan_result *erp = (escan_result *)eventbuf;

  Serial.printf(SER_TRACE "\nSetting scan channel time\n", SER_RESET);

  wifiCard.ioctl_wr_int32(IOCTL_SET_SCAN_CHANNEL_TIME, 0, SCAN_CHAN_TIME);

  if (!wifiCard.ioctl_wr_int32(WLC_UP, 200, 0)) {
    Serial.printf(SER_RED "\nWiFi CPU not running\n" SER_RESET);
    return-1;
  } else {
    Serial.printf(SER_GREEN "\nWiFi CPU running\n" SER_RESET);
  }

  //Clear interrupt?? TODO
  wifiCard.backplaneWindow_write32(SB_INT_STATUS_REG, 0);

  wifiCard.cardCMD53_read(SD_FUNC_RAD, SB_32BIT_WIN, (uint8_t *)resp1, 64);

  if (scnevt.ioctl_enable_evts(escan_evts) == true) {
    Serial.printf(SER_TRACE "\nEvents enabled\n" SER_RESET);
  } else {
    Serial.printf(SER_RED "\nEvents not enabled\n" SER_RESET);
    return -1;
  }

  if (wifiCard.ioctl_set_data("escan", 0, &scan_params, sizeof(scan_params)) == true) {
    Serial.printf(SER_TRACE "\nSet data escan\n" SER_RESET);
  } else {
    Serial.printf(SER_RED "\nFailed to set data escan\n" SER_RESET);
    return-1;
  }

  int count = 0;
  while (1) {
    delay(125);
    uint32_t n = scnevt.ioctl_get_event(&iehh, eventbuf, sizeof(eventbuf));
    
    // If scan complete then return
    if(n == WLC_E_STATUS_SUCCESS) break; // Break out of while() loop;
    count++;
    if((n > sizeof(escan_result))) { // && (erp->escan.bss_info->SSID_len != 0)) {
      wifiCard.printMACAddress((uint8_t *)&erp->event.whd_event.addr);
      Serial.printf("  |  Signal:  %d dBm", erp->escan.bss_info->RSSI);
      Serial.printf("  |  Channel #%-2d | ", erp->escan.bss_info->chanspec & 0xFF);
      wifiCard.printSSID(&erp->escan.bss_info->SSID_len);
      Serial.printf("\n");
    }
  }
  return count;
}

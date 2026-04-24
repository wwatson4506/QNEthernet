// join.cpp

#include "cyw43_T4_SDIO.h"
#include "misc_defs.h"
#include "ioctl_T4.h"
//#include "event.h"
#include "join.h"

extern W4343WCard wifiCard;
//extern sdpcm_header_t ieh;
extern EVENT_INFO event_info;
Event joinevt;
EVT_STR no_evts[] = NO_EVTS;
EVT_STR join_evts[] = JOIN_EVTS;

wl_country_t country_struct = {.country_abbrev=COUNTRY, .rev=COUNTRY_REV, .ccode=COUNTRY};
const uint8_t mcast_addr[10*6] = {0x01,0x00,0x00,0x00,0x01,0x00,0x5E,0x00,0x00,0xFB};

bool join_start(const char *ssID, const char *passphrase, int security) {
//  int n, startime=micros();
  Serial.printf(SER_YELLOW "In joinNetworks\n", SER_RESET);

  // Process SSID
	wlc_ssid_t ssid;
	ssid.SSID_len = strlen(ssID);
	strcpy((char *)ssid.SSID, ssID);
  
  // Process PASSWORD
	wsec_pmk_t wsec_pmk;
	wsec_pmk.key_len = strlen(passphrase);
	wsec_pmk.flags = WSEC_PASSPHRASE;
	strcpy((char *)wsec_pmk.key, passphrase);

  if (!wifiCard.ioctl_wr_int32(WLC_UP, 200, 0)) {
    Serial.printf(SER_RED "\nWiFi CPU not running\n" SER_RESET);
    return false;
  } else {
    Serial.printf(SER_GREEN "WiFi CPU running\n" SER_RESET);
  }

  if (wifiCard.ioctl_set_data("country", 100, &country_struct, sizeof(country_struct)) == true) {
    Serial.printf(SER_TRACE "Set country succesfully\n" SER_RESET);
  } else {
    Serial.printf(SER_ERROR "\nFailed to set country\n" SER_RESET);
  }

  if (joinevt.ioctl_enable_evts(no_evts) == true) {
//    Serial.printf(SER_TRACE "\nNo events enabled\n" SER_RESET);
  } else {
    Serial.printf(SER_RED "\nNo events not enabled\n" SER_RESET);
    return false;
  }
  
  CHECK(wifiCard.ioctl_set_uint32, "ampdu_ba_wsize", 0, 8);

  CHECK(wifiCard.ioctl_wr_int32, WLC_SET_INFRA, 50, 1);
  CHECK(wifiCard.ioctl_wr_int32, WLC_SET_AUTH, 0, 0);

  if(security != 0) {
    CHECK(wifiCard.ioctl_wr_int32, WLC_SET_WSEC, 0, security == 2 ? 6 : 2);
    CHECK(wifiCard.ioctl_set_intx2, "bsscfg:sup_wpa", 0, 0, 1);
    CHECK(wifiCard.ioctl_set_intx2, "bsscfg:sup_wpa2_eapver", 0, 0, -1);
    CHECK(wifiCard.ioctl_set_intx2, "bsscfg:sup_wpa_tmo", 0, 0, 2500);
    CHECK(wifiCard.ioctl_wr_data, WLC_SET_WSEC_PMK, 0, &wsec_pmk, sizeof(wsec_pmk));
    CHECK(wifiCard.ioctl_wr_int32, WLC_SET_WPA_AUTH, 0, security==2 ? 0x80 : 4);
  } else {
    CHECK(wifiCard.ioctl_wr_int32, WLC_SET_WSEC, 0, 0);
    CHECK(wifiCard.ioctl_wr_int32, WLC_SET_WPA_AUTH, 0, 0);
  }
  if (joinevt.ioctl_enable_evts(join_evts) == true) {
    Serial.printf(SER_TRACE "Join events enabled\n" SER_RESET);
  } else {
    Serial.printf(SER_RED "Join events not enabled\n" SER_RESET);
    return false;
  }
  CHECK(wifiCard.ioctl_wr_data, WLC_SET_SSID, 100, &ssid, sizeof(ssid));

#if defined(USE_MCAST) 
  // Enable multicast
  wifiCard.ioctl_set_data2((char *)"mcast_list", IOCTL_WAIT, (void *)mcast_addr, sizeof(mcast_addr), false);
  delayMicroseconds(50000);
#endif
  // Register SSID and password with polling function
  join_state_poll((char *)ssID, (char *)passphrase, security);
  return true;
}

// Stop trying to join network
// (Set WiFi interface 'down', ignore IOCTL response)
bool join_stop(void)
{
    wifiCard.ioctl_wr_data(WLC_DOWN, 50, 0, 0); 
    return(true);
}

// Retry joining a network
bool join_restart(const char *ssid, const char *passwd, int security)
{
    uint32_t n;
    uint8_t data[100];
    bool ret=0;
    
    // Start up the interface
    wifiCard.ioctl_wr_data(WLC_UP, 50, 0, 0);

    ret = wifiCard.ioctl_wr_int32(WLC_SET_GMODE, IOCTL_WAIT, 0x01) > 0 &&
          wifiCard.ioctl_wr_int32(WLC_SET_BAND, IOCTL_WAIT, 0x00) > 0 &&
          wifiCard.ioctl_set_uint32((char *)"pm2_sleep_ret", IOCTL_WAIT, 0xc8) > 0 &&
          wifiCard.ioctl_set_uint32((char *)"bcn_li_bcn", IOCTL_WAIT, 0x01) > 0 &&
          wifiCard.ioctl_set_uint32((char *)"bcn_li_dtim", IOCTL_WAIT, 0x01) > 0 &&
          wifiCard.ioctl_set_uint32((char *)"assoc_listen", IOCTL_WAIT, 0x0a) > 0;
/*
#if POWERSAVE    
    // Enable power saving
    init_powersave();
#endif    
*/
    // Wireless security
    ret = ret && wifiCard.ioctl_wr_int32(WLC_SET_INFRA, 50, 1) > 0 &&
        wifiCard.ioctl_wr_int32(WLC_SET_AUTH, IOCTL_WAIT, 0) > 0;

  if(security != 0) {
    ret = ret && wifiCard.ioctl_wr_int32(WLC_SET_WSEC, IOCTL_WAIT, security==2 ? 6 : 2) > 0 &&
        wifiCard.ioctl_set_data((char *)"bsscfg:sup_wpa", IOCTL_WAIT, (void *)"\x00\x00\x00\x00\x01\x00\x00\x00", 8) > 0 &&
        wifiCard.ioctl_set_data((char *)"bsscfg:sup_wpa2_eapver", IOCTL_WAIT, (void *)"\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 8) > 0 &&
        wifiCard.ioctl_set_data((char *)"bsscfg:sup_wpa_tmo", IOCTL_WAIT, (void *)"\x00\x00\x00\x00\xC4\x09\x00\x00", 8) > 0;
    delayMicroseconds(2000);
    n = strlen(passwd);
    *(uint32_t *)data = n + 0x10000;
    strcpy((char *)&data[4], passwd);
    ret = ret && wifiCard.ioctl_wr_data(WLC_SET_WSEC_PMK, IOCTL_WAIT, data, n+4) >0 &&
        wifiCard.ioctl_wr_int32(WLC_SET_INFRA, IOCTL_WAIT, 0x01) > 0 &&
        wifiCard.ioctl_wr_int32(WLC_SET_AUTH, IOCTL_WAIT, 0x00) > 0 &&
        wifiCard.ioctl_wr_int32(WLC_SET_WPA_AUTH, IOCTL_WAIT, security==2 ? 0x80 : 4) > 0;
     } else {
       ret = ret && wifiCard.ioctl_wr_int32(WLC_SET_WSEC, IOCTL_WAIT, 0) > 0 &&
                   wifiCard.ioctl_wr_int32(WLC_SET_WPA_AUTH, IOCTL_WAIT, 0) > 0;
    }      
    n = strlen(ssid);
    *(uint32_t *)data = n;
    strcpy((char *)&data[4], ssid);
    ret = ret && wifiCard.ioctl_wr_data(WLC_SET_SSID, IOCTL_WAIT, data, n+4) > 0;
    return(ret);
}

// Handler for join events (link & auth changes)
int join_event_handler(EVENT_INFO *eip)
{
    int ret = 1;
    uint16_t news;
    if (eip->chan == SDPCM_CHAN_EVT)
    {
        news = eip->link;
        if (eip->event_type==WLC_E_LINK && eip->status==0)
            news = eip->flags&1 ? news|LINK_UP_OK : news&~LINK_UP_OK;
        else if (eip->event_type == WLC_E_PSK_SUP)
            news = (eip->status==6) ? news|LINK_AUTH_OK : news&~LINK_AUTH_OK;
        else if (eip->event_type == WLC_E_DISASSOC_IND)
            news = LINK_FAIL;
        else
            ret = 0;
        eip->link = news;
    } else {
        ret = 0;
    }
     return(ret);
}

// Poll the network joining state machine
void join_state_poll(const char *ssid, const char *passwd, int security)
{
    EVENT_INFO *eip = &event_info;
    static uint32_t join_ticks;
    static char *s = NULL, *p = NULL;

    if (ssid)
        s = (char *)ssid;
    if (passwd)
        p = (char *)passwd;
    if (eip->join == JOIN_IDLE)
    {
        Serial.printf("Joining network %s\n", s);
        eip->link = 0;
        eip->join = JOIN_JOINING;
        ustimeout(&join_ticks, 0);
        join_restart(s, p, security);
    }
    else if (eip->join == JOIN_JOINING)
    {
        if (link_check() > 0)
        {

            Serial.printf(SER_GREEN "\n********************* LINK Established *********************\n" SER_RESET);
            Serial.printf(SER_YELLOW "\n********************* Joined Network ***********************\n\n" SER_RESET);
            eip->join = JOIN_OK;
        }
        else if (link_check()<0 || ustimeout(&join_ticks, JOIN_TRY_USEC))
        {
            Serial.printf(SER_RED "\n******************** Failed to join network ************************\n\n" SER_RESET);
            ustimeout(&join_ticks, 0);
            join_stop();
            eip->join = JOIN_FAIL;
        }
    }
    else if (eip->join == JOIN_OK)
    {
        ustimeout(&join_ticks, 0);
        if (link_check() < 1)
        {
            Serial.printf("Leaving network\n");
            join_stop();
            eip->join = JOIN_FAIL;
        }
    }
    else  // JOIN_FAIL
    {
        if (ustimeout(&join_ticks, JOIN_RETRY_USEC))
            eip->join = JOIN_IDLE;
    }
}

// Return 1 if link to network, -1 if error linking
int link_check(void)
{
    EVENT_INFO *eip=&event_info;
    return((eip->link&LINK_OK) == LINK_OK ? 1 : 
            eip->link == LINK_FAIL ? -1 : 0);
}

// Return 2 if joined network, -1 if error joining
int join_check(void)
{
    EVENT_INFO *eip=&event_info;
    return((eip->join&JOIN_OK) == JOIN_OK ? 2 : eip->join == JOIN_FAIL ? -1 : 0);
}

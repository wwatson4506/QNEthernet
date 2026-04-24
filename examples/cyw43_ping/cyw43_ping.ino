// QNEthernet PING example for CYW4343W.
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

#include <QNEthernet.h>
#include "../src/qnethernet/drivers/cyw4343w/src/cyw43_T4_SDIO.h"
#include "../src/qnethernet/drivers/cyw4343w/src/event.h"
#include "../src/qnethernet/drivers/cyw4343w/src/secrets.h"
#include "../src/qnethernet/drivers/cyw4343w/src/join.h"
using namespace qindesign::network;

//W4343WCard wifi;
//MACADDR mac;
void waitForInput();
bool running = false;  // Whether the program is still running
#define EVENT_POLL_USEC     100000
#define PING_RESP_USEC      300000 
#define PING_DATA_SIZE      32

constexpr uint32_t kDHCPTimeout = 15000;  // 15 seconds
constexpr char kHostname[]{"wwatsond1.local"};

Event evnt;
extern uint32_t ping_tx_time, ping_rx_time;
IPAddress pingIP;
BYTE ping_data[PING_DATA_SIZE];
uint32_t led_ticks, ping_poll_ticks, ping_ticks;
bool ledon=false;
int i, ping_state=0, t;

void setup()
{
  Serial.begin(115200);
  // wait for serial port to connect.
  while (!Serial && millis() < 5000) {}
  Serial.printf("%c",12);

  if(CrashReport) {
	Serial.print(CrashReport);
    waitForInput();
  }
  Serial.printf("CPU speed: %ld MHz\n", F_CPU_ACTUAL / 1'000'000);
  pinMode(13, OUTPUT); // For debugging. Temporary usage.
  evnt.add_event_handler(icmp_event_handler);
  evnt.add_event_handler(arp_event_handler);

  Serial.printf("Starting Ethernet with DHCP...\r\n");
  if (!Ethernet.begin()) {
    Serial.printf("Failed to start Ethernet\r\n");
    return;
  }

  uint8_t mac[6];
  Ethernet.macAddress(mac);  // This is informative; it retrieves, not sets
  Serial.printf("MAC = %02x:%02x:%02x:%02x:%02x:%02x\r\n",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  Serial.printf("Waiting for local IP...\r\n");
  if (!Ethernet.waitForLocalIP(kDHCPTimeout)) {
    Serial.printf("Failed to get IP address from DHCP\r\n");
    return;
  }
  IPAddress ip = Ethernet.localIP();
  evnt.ipInit(ip);
  Serial.printf("    Local IP    = %u.%u.%u.%u\r\n", ip[0], ip[1], ip[2], ip[3]);
  ip = Ethernet.subnetMask();
  Serial.printf("    Subnet mask = %u.%u.%u.%u\r\n", ip[0], ip[1], ip[2], ip[3]);
  ip = Ethernet.gatewayIP();
  Serial.printf("    Gateway     = %u.%u.%u.%u\r\n", ip[0], ip[1], ip[2], ip[3]);
  ip = Ethernet.dnsServerIP();
  Serial.printf("    DNS         = %u.%u.%u.%u\r\n", ip[0], ip[1], ip[2], ip[3]);
  Serial.printf("\r\n");
  
  // Look up the hostname
  Serial.printf("Looking up \"%s\"...", kHostname);
  if (Ethernet.hostByName(kHostname, pingIP)) {
    Serial.printf("\r\nIP = %u.%u.%u.%u\r\n",
           pingIP[0], pingIP[1], pingIP[2], pingIP[3]);
    running = true;
  } else {
    Serial.printf("errno=%d\r\n", errno);
  }

        ustimeout(&led_ticks, 0);
        ustimeout(&ping_poll_ticks, 0);
        while (1)
        {
            // Toggle LED at 0.5 Hz if joined, 5 Hz if not
            if (ustimeout(&led_ticks, link_check() > 0 ? 1000000 : 100000))
            {
                digitalWriteFast(13,ledon = !ledon);
                ustimeout(&ping_ticks, 0);
                // If LED is on, and we have joined a network..
                if (ledon && link_check()>0)
                {
                    // If not ARPed, send ARP request
                    if (!ip_find_arp(pingIP, mac))
                    {
                        ip_tx_arp(mac, pingIP, ARPREQ);
                        ping_state = 1;
Serial.printf("ping_state = %d\n",ping_state);
                    }
                    // If ARPed, send ICMP request
                    else
                    {
                        evnt.ip_tx_icmp(mac, pingIP, ICREQ, 0, ping_data, sizeof(ping_data));
                        ping_rx_time = 0;
                        ping_state = 2;
Serial.printf("ping_state = %d\n",ping_state);
                   }
                }
            }
            // If awaiting ARP response..
            if (ping_state == 1)
            {
                // If we have an ARP response, send ICMP request
                if (ip_find_arp(pingIP, mac))
                {
Serial.printf("ping_state = %d\n",ping_state);
                    ustimeout(&ping_ticks, 0);
                    evnt.ip_tx_icmp(mac, pingIP, ICREQ, 0, ping_data, sizeof(ping_data));
                    ping_rx_time = 0;
                    ping_state = 2;
                }
            }
            // Check for timeout on ARP or ICMP request
            if ((ping_state==1 || ping_state==2) && 
                ustimeout(&ping_ticks, PING_RESP_USEC))
            {
                Serial.printf("%s timeout\n", ping_state==1 ? "ARP" : "ICMP");
                ping_state = 0;
            }
            // If ICMP response received, LED off, print time
            else if (ping_state == 2 && ping_rx_time)
            {
                t = (ping_rx_time - ping_tx_time + 50) / 100;
                Serial.printf("Round-trip time %d.%d ms\n", t/10, t%10);
                digitalWriteFast(13,LOW);
                ping_state = 0;
            }
            // Get any events, poll the network-join state machine
//            if (sdio.wifi_get_irq() || ustimeout(&ping_poll_ticks, EVENT_POLL_USEC))
            if (ustimeout(&ping_poll_ticks, EVENT_POLL_USEC))
            {
                evnt.pollEvents();
//                join_state_poll((char *)MY_SSID, (char *)MY_PASSPHRASE, SECURITY);
                ustimeout(&ping_poll_ticks, 0);
            }
         }
}

void loop() {

}

void waitForInput()
{
  Serial.println("Press anykey to continue...");
  while (Serial.read() == -1) ;
  while (Serial.read() != -1) ;
}

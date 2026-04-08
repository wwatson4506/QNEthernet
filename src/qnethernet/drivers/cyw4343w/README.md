# T4_WIFI_CYW4343W
Library for testing the Murata 1DX / CYW4343W WiFi chip on uSDHC1 and uSDHC2 on a Teensy 4.1 and custom Teensy boards. SdFat initially used as base.

## The updated imxrt.h file should be incorperated in the latest releases of TD1.60Bx.

### This is a new re-write of the WiFi driver for the T4.x and Devboard using an adapted version of the Picowi WIFI library by Jeremy P Bentham and our CYW4343W T4.1 modified driver.
### The documentation for the Picowi WIFI library is found at: 
### https://iosoft.blog/2022/12/06/picowi/
### and the library at:
### https://github.com/jbentham/picowi.

## Refer to https://forum.pjrc.com/index.php?threads/call-to-arms-teensy-wifi-true.77099/ for a description of the CYW4343W adapter board created by @Dogbone06 that is used with this library.
The CYW4343W wifi board can use either one of the two available SDIO ports on the Teensy 4.1 and DEV board 5.The T4.1 pinout is shown below (Have not tried the DB5 yet, will test later).
 ## PINOUT:
TEENSY 4.1   WIFI Board
- 23 --------> clk
- 22 --------> cmd
- 17 --------> D2
- 16 --------> D3
- 41 --------> D1
- 40 --------> D0
- 34 --------> INT
- 33 --------> WL_ON

## EXAMPLES:
- WiFi_scan_T4.ino  An example of the scan function.
- WiFi_join_T4.ino  An example of joining a network.
- ping_T4.ino       An example of pinging devices on a local network.
- udp_server_T4.ino An example of UDP usage. Use " echo -n "Teensy 4.1" | nc -4u -w1 192.168.0.103 8080 " with your assigned T4.1 IP address using your laptop or computer.
- DHCP_T4.ino       An example of getting an IP address for the T4.1 using DHCP.
- dns_T4.ino        An example of getting an IP address(S) and other information about a web site by name. pjrc.com is one example.
- web_server_T4.ino A partially working example of a web server accessed by a web browser on a laptop or computer on your local network. See picowi docs link above.
A few of the examples use a SSID, PASSPHRASE and SECURITY type. This info is setup in the "scr/secrets" file.

```
// The secrets file

// SSID
//#define MY_SSID            "yourssid"

//PASSPHRASE
//#define MY_PASSPHRASE      "yourpassphrase"

// Security settings: 0 for none, 1 for WPA_TKIP, 2 for WPA2
// The hard-coded password is for test purposes only!!!
#define SECURITY        2
```

 This is a complete re-write of https://github.com/wwatson4506/CYW4343W_t4 and adaption of picowi to the Teensy 4.1 and hopefully the DB5.

 ## This is a WIP project and may not go any further in development than this. 
 # USE AT YOUR OWN RISK!

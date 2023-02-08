Client for Alcatel/TCL routers
==============================

This is a super-simple client for Alcatel/TCL routers, in order to read
informations from it.

For example, in Germany, the Vodafone GigaCube 5G is effectively a TCL HH500,
and using this client we can retrieve (and monitor) interface statistics or
connection status (network, `RSSI`, `RSRP`, `RSRQ`, `SINR`, ...)

```typescript
const client = new AcatelClient('192.168.1.1', 'myPassword')
const data = client.poll()
// Data will be:
// {
//   imei: '350364240104600',        // The IMEI of the device              (from `GetSystemInfo -> IMEI`)
//   iccid: '89492028216017894497',  // The ICC-ID of the SIM card          (from `GetSystemInfo -> ICCID`)
//   device: 'HH500V',               // The name of the device              (from `GetSystemInfo -> DeviceName`)
//   connection_status: 'Connected', // The status of the connection        (from `GetConnectionState -> ConnectionStatus`)
//   bytes_in: 18972149764,          // The number of bytes in (downloaded) (from `GetConnectionState -> DlBytes`)
//   bytes_out: 1797941366,          // The number of bytes out (uploaded)  (from `GetConnectionState -> UlBytes`)
//   bytes_in_rate: 1187659,         // The rate (bytes/sec) of download    (from `GetConnectionState -> DlRate`)
//   bytes_out_rate: 418809,         // The rate (bytes/sec) of upload      (from `GetConnectionState -> UlRate`)
//   ipv4_addr: '10.17.152.95',      // The current IPv4 address or `null`  (from `GetConnectionState -> IPv4Adrress`)
//   ipv6_addr: null,                // The current IPv6 address or `null`  (from `GetConnectionState -> IPv6Adrress`)
//   network_name: 'vodafone.de',    // The network name                    (from `GetNetworkInfo -> NetworkName`)
//   network_type: '5G',             // The network type                    (from `GetNetworkInfo -> NetworkType`)
//   strength: 3,                    // The overall network strength (bars) (from `GetNetworkInfo -> SignalStrength`)
//   rssi: -65,                      // Received Signal Strength Indicator  (from `GetNetworkInfo -> RSSI`)
//   rsrp: -97                       // Reference Signal Received Power     (from `GetNetworkInfo -> RSRQ`)
//   sinr: 7,                        // Signal Interference + Noise Ratio   (from `GetNetworkInfo -> RSRP`)
//   rsrq: 11,                       // Reference Signal Received Quality   (from `GetNetworkInfo -> SINR`)
// }
```

To make sense of the various `RSSI`, `RSRP`, `RSRQ`, `SINR` values, see
[this post](https://www.rangeful.com/what-is-rssi-sinr-rsrp-rsrq-how-does-this-affect-signal-quality/)

This client is based on JSON-RPC, and all known methods for standard routers
are exposed by invoking `getXXX`. For a list, see [verbs](#verbs) below.

Verbs
-----

All known _verbs_ (JSON-RPC methods) are:

* Public (no authentication required)
  * `GetCurrentLanguage`
  * `GetLoginState`
  * `GetQuickSetup`
  * `GetSMSStorageState`
  * `GetSimStatus`
  * `GetSystemInfo`
  * `GetSystemStatus`
* Restricted (require authentication)
  * `GetAutoValidatePinState`
  * `GetBlockDeviceList`
  * `GetClientConfiguration`
  * `GetConnectedDeviceList`
  * `GetConnectionSettings`
  * `GetConnectionState`
  * `GetCurrentData`
  * `GetCurrentTime`
  * `GetDdnsSettings`
  * `GetDeviceDefaultRight`
  * `GetDeviceUpgradeState`
  * `GetExtendTimes`
  * `GetLanPortInfo`
  * `GetLanSettings`
  * `GetLanStatistics`
  * `GetLogcfg`
  * `GetMacFilterSettings`
  * `GetNetworkInfo`
  * `GetNetworkSettings`
  * `GetParentalSettings`
  * `GetPasswordChangeFlag`
  * `GetPingTraceroute`
  * `GetPortTriggering`
  * `GetProfileList`
  * `GetSIPAccountSettings`
  * `GetSIPServerSettings`
  * `GetSMSContactList`
  * `GetSMSSettings`
  * `GetSystemSettings`
  * `GetTransferProtocol`
  * `GetUpnpSettings`
  * `GetUsageRecord`
  * `GetUsageSettings`
  * `GetVpnClient`
  * `GetVpnClientStatus`
  * `GetWPSConnectionState`
  * `GetWPSSettings`
  * `GetWanCurrentMacAddr`
  * `GetWanIsConnInter`
  * `GetWanSettings`
  * `GetWlanSettings`
  * `GetWlanState`
  * `GetWlanStatistics`
  * `GetWlanSupportMode`
  * `GetWmmSwitch`

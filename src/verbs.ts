/** List of _public_ verbs (do not require authentication) */
export const publicVerbs = [
  'GetCurrentLanguage',
  'GetLoginState',
  'GetQuickSetup',
  'GetSMSStorageState',
  'GetSimStatus',
  'GetSystemInfo',
  'GetSystemStatus',
] as const

/** Union type for all {@link publicVerbs public verbs} */
export type PublicVerbs = typeof publicVerbs[number]

/** List of _restricted_ verbs (require authentication) */
export const restrictedVerbs = [
  'GetAutoValidatePinState',
  'GetBlockDeviceList',
  'GetClientConfiguration',
  'GetConnectedDeviceList',
  'GetConnectionSettings',
  'GetConnectionState',
  'GetCurrentData',
  'GetCurrentTime',
  'GetDdnsSettings',
  'GetDeviceDefaultRight',
  'GetDeviceUpgradeState',
  'GetExtendTimes',
  'GetLanPortInfo',
  'GetLanSettings',
  'GetLanStatistics',
  'GetLogcfg',
  'GetMacFilterSettings',
  'GetNetworkInfo',
  'GetNetworkSettings',
  'GetParentalSettings',
  'GetPasswordChangeFlag',
  'GetPingTraceroute',
  'GetPortTriggering',
  'GetProfileList',
  'GetSIPAccountSettings',
  'GetSIPServerSettings',
  'GetSMSContactList',
  'GetSMSSettings',
  'GetSystemSettings',
  'GetTransferProtocol',
  'GetUpnpSettings',
  'GetUsageRecord',
  'GetUsageSettings',
  'GetVpnClient',
  'GetVpnClientStatus',
  'GetWPSConnectionState',
  'GetWPSSettings',
  'GetWanCurrentMacAddr',
  'GetWanIsConnInter',
  'GetWanSettings',
  'GetWlanSettings',
  'GetWlanState',
  'GetWlanStatistics',
  'GetWlanSupportMode',
  'GetWmmSwitch',
] as const

/** Union type for all {@link restrictedVerbs restricted verbs} */
export type RestrictedVerbs = typeof restrictedVerbs[number]

/**
 * Union type for all known {@link publicVerbs public} and
 * {@link restrictedVerbs restricted} verbs
 */
export type Verbs = PublicVerbs | RestrictedVerbs

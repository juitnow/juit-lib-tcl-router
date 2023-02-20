import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
} from 'node:crypto'
import { isIPv4, isIPv6 } from 'node:net'

import { CONNECTION_STATUSES, NETWORK_TYPES } from './constants'
import { publicVerbs, restrictedVerbs } from './verbs'

import type { Verbs } from './verbs'

export type AlactelClientVerbs = {
  readonly [ verb in Verbs as Uncapitalize<verb> ]: () => Promise<Record<string, any>>
}


export interface AlcatelClientBasicStatus {
  /* The IMEI of the device              (from `GetSystemInfo -> IMEI`) */
  imei: string,
  /* The ICC-ID of the SIM card          (from `GetSystemInfo -> ICCID`) */
  iccid: string,
  /* The name of the device              (from `GetSystemInfo -> DeviceName`) */
  device: string,
  /* The status of the connection        (from `GetConnectionState -> ConnectionStatus`) */
  connection_status: typeof CONNECTION_STATUSES[keyof typeof CONNECTION_STATUSES] | 'Unknown',
  /* The network type                    (from `GetNetworkInfo -> NetworkType`) */
  network_type: typeof NETWORK_TYPES[keyof typeof NETWORK_TYPES] | 'Unknown',
  /* The network name                    (from `GetNetworkInfo -> NetworkName`) */
  network_name: string | null,
  /* The overall network strength (bars) (from `GetNetworkInfo -> SignalStrength`) */
  strength: number,
}

export interface AlcatelClientExtendedStatus extends AlcatelClientBasicStatus {
  /* The number of bytes in (downloaded) (from `GetConnectionState -> DlBytes`) */
  bytes_in: number,
  /* The number of bytes out (uploaded)  (from `GetConnectionState -> UlBytes`) */
  bytes_out: number,
  /* The rate (bytes/sec) of download    (from `GetConnectionState -> DlRate`) */
  bytes_in_rate: number,
  /* The rate (bytes/sec) of upload      (from `GetConnectionState -> UlRate`) */
  bytes_out_rate: number,
  /* The current IPv4 address or `null`  (from `GetConnectionState -> IPv4Adrress`) */
  ipv4_addr: string | null,
  /* The current IPv6 address or `null`  (from `GetConnectionState -> IPv6Adrress`) */
  ipv6_addr: string | null,
  /* Received Signal Strength Indicator  (from `GetNetworkInfo -> RSSI`) */
  rssi: number,
  /* Reference Signal Received Power     (from `GetNetworkInfo -> RSRQ`) */
  rsrp: number,
  /* Signal Interference + Noise Ratio   (from `GetNetworkInfo -> RSRP`) */
  sinr: number,
  /* Reference Signal Received Quality   (from `GetNetworkInfo -> SINR`) */
  rsrq: number,
}

export interface AlcatelClient extends AlactelClientVerbs {
  login(): Promise<void>
  connect(): Promise<void>
  disconnect(): Promise<void>
  pollExtended(): Promise<AlcatelClientExtendedStatus>
}

export interface AlcatelClientOptions {
  /** The user name used by the router (default: `admin`).*/
  userName?: string | undefined
  /** The encryption key used to invoke public verbs (default: `EE5GRouter2020`) */
  publicEncryptionKey?: string | undefined
  /** The TCL _verification key_ passed as a header (default: `KSDHSDFOGQ5WERYTUIQWERTYUISDFG1HJZXCVCXBN2GDSMNDHKVKFsVBNf`) */
  tclVerificationKey?: string | undefined

  /** The _system_ salt, used to hash the password before login (default: `e5dl12XYVggihggafXWf0f2YSf2Xngd1`) */
  pbkdf2Salt?: string | undefined
  /** The number of rounds used to hash the password (default: `1024`) */
  pbkdf2Rounds?: number | undefined
  /** The length (in bytes) of the hash to generate from the password (default: `64`) */
  pbkdf2KeyLength?: number | undefined
  /** The algorithm used to hash the password (default: `sha1`) */
  pbkdf2Algorithm?: string | undefined
}

export class AlcatelClient {
  private readonly _hostName: string
  private readonly _userName: string
  private readonly _hashedPassword: string
  private readonly _publicEncryptionKey: string
  private readonly _restrictedEncryptionKey: string
  private readonly _tclVerificationKey: string

  private __sequence: number = 1
  private __token: string | undefined

  constructor(hostName: string, password: string = '', options: AlcatelClientOptions = {}) {
    const {
      userName = 'admin',
      publicEncryptionKey = 'EE5GRouter2020',
      tclVerificationKey = 'KSDHSDFOGQ5WERYTUIQWERTYUISDFG1HJZXCVCXBN2GDSMNDHKVKFsVBNf',
      pbkdf2Salt = 'e5dl12XYVggihggafXWf0f2YSf2Xngd1',
      pbkdf2Rounds = 1024,
      pbkdf2KeyLength = 64,
      pbkdf2Algorithm = 'sha1',
    } = options

    this._hostName = hostName
    this._userName = userName
    this._tclVerificationKey = tclVerificationKey
    this._publicEncryptionKey = publicEncryptionKey

    // Hash the password right now, pointless to keep it around
    this._restrictedEncryptionKey = pbkdf2Sync(
        password,
        pbkdf2Salt,
        pbkdf2Rounds,
        pbkdf2KeyLength,
        pbkdf2Algorithm,
    ).toString('hex')

    // The **password** to be sent to the router is (hear, hear) simply the
    // same value of the PBKDF2-hashed password with its HEX halves swapped!
    const len = this._restrictedEncryptionKey.length
    const left = this._restrictedEncryptionKey.substring(0, len / 2)
    const right = this._restrictedEncryptionKey.substring(len / 2, len)
    this._hashedPassword = right + left // genius!

    // Inject all the public verbs right now (those are easy)
    for (const verb of publicVerbs) {
      const name = verb[0].toLowerCase() + verb.substring(1)
      Object.defineProperty(this, name, {
        value: () => this._post(verb, this._publicEncryptionKey, {}),
      })
    }

    // Inject all the restricted verbs, retrying call on 401 (token failure)
    for (const verb of [ ...restrictedVerbs, 'connect', 'disconnect' ]) {
      const name = verb[0].toLowerCase() + verb.substring(1)
      Object.defineProperty(this, name, { value: async () => {
        try {
          if (! this.__token) await this.login()
          return await this._post(verb, this._restrictedEncryptionKey, {}, this.__token)
        } catch (error: any) {
          // coverage ignore if
          if (! [ '401', '402', '403' ].includes(error.code)) throw error

          await this.login() // Retry logging in when error code is 401
          return this._post(verb, this._restrictedEncryptionKey, {}, this.__token)
        }
      } })
    }
  }

  private async _post(
      verb: string,
      encryptionKey: string,
      parameters: Record<string, any>,
      token?: string,
  ): Promise<Record<string, any>> {
    // Prepare the URL for the Alcatel/Lucent RPC service
    const url = `http://${this._hostName}/rpc?name=${verb}`

    // Prepare the headers, optionally adding authorization if needed
    const headers: Record<string, any> = { '_TclRequestVerificationKey': this._tclVerificationKey }
    if (token) headers['Authorization'] = `token=${token}`

    // Prepare and stringify our RPC request
    const request = {
      id: `${++ this.__sequence}.0`,
      jsonrpc: '2.0',
      method: verb,
      params: encrypt(parameters, encryptionKey),
    }
    const body = JSON.stringify(request)

    const response = await fetch(url, { method: 'POST', body, headers })

    // Check the status code of the response
    // coverage ignore if
    if (response.status !== 200) {
      throw new Error(`HTTP error (status=${response.status})`)
    }

    // Parse out the RPC response
    const result = await response.json()

    // Check the response version (always "2.0")
    // coverage ignore if
    if (result.jsonrpc !== '2.0') {
      throw new Error(`Wrong RPC response version (jsonrpc=${request.jsonrpc}`)
    }

    // Check the response id (correlates to request)
    // coverage ignore if
    if (result.id != request.id) {
      throw new Error(`RPC ID mismatch (request=${request.id}, response=${result.id}`)
    }

    // Check for possible RPC errors
    if (result.error) {
      const error = new Error(`RPC Error: ${result.error.message} (code=${result.error.code})`)
      ;(<NodeJS.ErrnoException> error).code = result.error.code
      throw error
    }

    // Make sure we _do_ have a result
    // coverage ignore if
    if (! result.result) throw new Error('RPC Error: No result')

    // Decrypt the RPC result string
    return decrypt(result.result, encryptionKey)
  }

  async login(): Promise<void> {
    const result = await this._post('Login', this._restrictedEncryptionKey, {
      UserName: this._userName,
      Password: this._hashedPassword,
      ClientType: 0,
    })

    // coverage ignore if
    if (! result.token) throw new Error('No token in response')
    this.__token = result.token
  }

  /** Poll basic status (does **not** require login). */
  async poll(): Promise<AlcatelClientBasicStatus> {
    const [ systemInfo, systemStatus ] = await Promise.all([
      this.getSystemInfo(),
      this.getSystemStatus(),
    ])

    return {
      imei: systemInfo['IMEI'] || '',
      iccid: systemInfo['ICCID'] || '',
      device: systemInfo['DeviceName'] || '',

      connection_status: (<any> CONNECTION_STATUSES)[systemStatus['ConnectionStatus']] || 'Unknown',
      network_type: (<any> NETWORK_TYPES)[systemStatus['NetworkType']] || 'Unknown',

      network_name: systemStatus['NetworkName'] || null,
      strength: systemStatus['SignalStrength'] || 0,
    }
  }

  /** Poll extended status (**does require** login). */
  async pollExtended(): Promise<AlcatelClientExtendedStatus> {
    const systemInfo = await this.getSystemInfo()
    const networkInfo = await this.getNetworkInfo()
    const connectionState = await this.getConnectionState()

    /* coverage ignore next */
    return {
      imei: systemInfo['IMEI'] || '',
      iccid: systemInfo['ICCID'] || '',
      device: systemInfo['DeviceName'] || '',

      connection_status: (<any> CONNECTION_STATUSES)[connectionState['ConnectionStatus']] || 'Unknown',
      bytes_in: connectionState['DlBytes'] || 0,
      bytes_out: connectionState['UlBytes'] || 0,
      bytes_in_rate: connectionState['DlRate'] || 0,
      bytes_out_rate: connectionState['UlRate'] || 0,
      ipv4_addr: isIPv4(connectionState['IPv4Adrress']) ? connectionState['IPv4Adrress'] : null,
      ipv6_addr: isIPv6(connectionState['IPv6Adrress']) ? connectionState['IPv6Adrress'] : null,

      network_name: networkInfo['NetworkName'] || null,
      network_type: (<any> NETWORK_TYPES)[networkInfo['NetworkType']] || 'Unknown',
      strength: networkInfo['SignalStrength'] || 0,
      rssi: parseInt(networkInfo['RSSI']) || -Infinity,
      rsrp: parseInt(networkInfo['RSRP']) || -Infinity,
      sinr: parseInt(networkInfo['SINR']) || Infinity,
      rsrq: parseInt(networkInfo['RSRQ']) || Infinity,
    }
  }
}

/* ========================================================================== */

/** OpenSSL style basic (and very insecure) key derivation function */
function kdf(
    xpassword: string,
    salt: Buffer | null | undefined,
    keyLen: number,
    ivLen: number,
): { key: Buffer, iv: Buffer, salt: Buffer } {
  const password = Buffer.from(xpassword, 'binary')

  if (! salt) salt = randomBytes(8)

  // coverage ignore if
  if (salt.length !== 8) throw new RangeError('SALT must be 8 bytes long')

  const key = Buffer.alloc(keyLen)
  const iv = Buffer.alloc(ivLen)

  let tmp = Buffer.alloc(0)
  while (keyLen > 0 || ivLen > 0) {
    const hash = createHash('md5')
    hash.update(tmp)
    hash.update(password)
    hash.update(salt)
    tmp = hash.digest()

    let used = 0

    if (keyLen > 0) {
      const keyStart = key.length - keyLen
      used = Math.min(keyLen, tmp.length)
      tmp.copy(key, keyStart, 0, used)
      keyLen -= used
    }

    if (used < tmp.length && ivLen > 0) {
      const ivStart = iv.length - ivLen
      const length = Math.min(ivLen, tmp.length - used)
      tmp.copy(iv, ivStart, used, used + length)
      ivLen -= length
    }
  }

  return { key, iv, salt }
}

/** Encrypt an object "OpenSSL style" (a `Salted__...` string) */
function encrypt(parameters: Record<string, any>, secret: string): string {
  // Create key, initialization vector and salt from our password
  const { key, iv, salt } = kdf(secret, null, 32, 16)

  // Create our chipher, and encrypt our parameters (in JSON)
  const cipher = createCipheriv('aes-256-cbc', key, iv)
  const encrypted1 = cipher.update(JSON.stringify(parameters))
  const encrypted2 = cipher.final()

  // Concatenate `Salted__`, salt, and encrypted data to create a message
  const result = Buffer.concat([ Buffer.from('Salted__'), salt, encrypted1, encrypted2 ])

  // Return the message encoded in base-64
  return result.toString('base64')
}

function decrypt(message: string, secret: string): any {
  // Our message is always a base64 encoded string
  const token = Buffer.from(message, 'base64')

  // Split the message, as `Salted__`, 8-bytes salt, and data
  const prefix = token.subarray(0, 8).toString('latin1')
  const salt = token.subarray(8, 16)
  const data = token.subarray(16)

  // Check the prefix, it must be `Salted__`
  // coverage ignore if
  if (prefix !== 'Salted__') throw new Error('Invalid message (not salted)')

  // Detrive decryption key and initialization vector from secret and salt
  const { key, iv } = kdf(secret, salt, 32, 16)
  const decipher = createDecipheriv('aes-256-cbc', key, iv)

  // Decrypt our message
  const decrypted1 = decipher.update(data)
  const decrypted2 = decipher.final()
  const decrypted = Buffer.concat([ decrypted1, decrypted2 ]).toString('utf-8')

  // Simply JSON-parse the decrypted string
  return JSON.parse(decrypted)
}

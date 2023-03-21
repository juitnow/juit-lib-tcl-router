import { log } from '@plugjs/plug'
import * as dotenv from 'dotenv'

import { AlcatelClient } from '../src/index'
import { publicVerbs, restrictedVerbs } from '../src/verbs'

dotenv.config()

describe('Alcatel Client', () => {
  const host = process.env.ALCATEL_HOST
  const pass = process.env.ALCATEL_PASSWORD
  const _describe = (host && pass) ? describe : xdescribe
  const _it = (host && pass) ? it : xit

  let client: AlcatelClient

  beforeAll(() => {
    if (! host) return log.warn('Environment variable "ALCATEL_HOST" undefined')
    if (! pass) return log.warn('Environment variable "ALCATEL_PASSWORD" undefined')

    client = new AlcatelClient(host, pass)
  })

  /* ======================================================================== *
   * BASIC CHECKS                                                             *
   * ======================================================================== */

  _it('should have some basic properties', () => {
    // client with some "well known" values that we can triple check
    const client = new AlcatelClient('localhost', 'password')

    expect(client).toEqual(jasmine.objectContaining({
      _hostName: 'localhost',
      _userName: 'admin',
      _publicEncryptionKey: 'EE5GRouter2020',
      _restrictedEncryptionKey: '727f78a7a0640c5e28bc5fabb5ee5e46d58f92ff8f33c2bb047b4851df170fc588789ee14c9db0bb07450f0d23e8c01ca429a026d2b99ea9dacaab4816167129',
      _hashedPassword: '88789ee14c9db0bb07450f0d23e8c01ca429a026d2b99ea9dacaab4816167129727f78a7a0640c5e28bc5fabb5ee5e46d58f92ff8f33c2bb047b4851df170fc5',
      _tclVerificationKey: 'KSDHSDFOGQ5WERYTUIQWERTYUISDFG1HJZXCVCXBN2GDSMNDHKVKFsVBNf',
    }))
  })

  /* ======================================================================== *
   * PUBLIC VERBS                                                             *
   * ======================================================================== */

  _describe('Public Verbs', () => {
    for (const verb of publicVerbs) {
      const method: keyof AlcatelClient = (verb[0]!.toLowerCase() + verb.substring(1)) as any

      it(`should request "${verb}"`, async () => {
        const response = await client[method]()
        log.info(response)
      })
    }
  })

  /* ======================================================================== *
   * LOGIN                                                                    *
   * ======================================================================== */

  _describe('Login conditions', () => {
    _it('should login', async () => {
      expect((<any> client).__token).toBeFalsy()
      await client.login()
      expect((<any> client).__token).toBeTruthy()
      log.info(`Authorization token: "${(<any> client).__token}"`)
    })

    _it('should login automatically', async () => {
      expect((<any> client).__token).toBeTruthy()
      ;(<any> client).__token = undefined
      expect((<any> client).__token).toBeFalsy()

      // get system settings is restricted, should automatically login!
      await client.getSystemSettings()

      expect((<any> client).__token).toBeTruthy()
      log.info(`Authorization token: "${(<any> client).__token}"`)
    })

    _it('should re-login when token fails', async () => {
      expect((<any> client).__token).toBeTruthy()
      ;(<any> client).__token = 'ThisIsTheWrongToken'
      expect((<any> client).__token).toBeTruthy()

      // get system settings is restricted, should fail but retry
      await client.getSystemSettings()

      expect((<any> client).__token).toBeTruthy()
      log.info(`Authorization token: "${(<any> client).__token}"`)
    })
  })

  /* ======================================================================== *
   * AUTOMATIC LOGIN                                                          *
   * ======================================================================== */

  _describe('Private Verbs', () => {
    for (const verb of restrictedVerbs) {
      const method: keyof AlcatelClient = (verb[0]!.toLowerCase() + verb.substring(1)) as any

      it(`should request "${verb}"`, async () => {
        const response = await client[method]()
        log.info(response)
      })
    }
  })

  /* ======================================================================== *
   * POLL                                                                     *
   * ======================================================================== */
  _it('should poll a basic status', async () => {
    const client = new AlcatelClient(host || '') // without password!
    log.notice(await client.pollBasic())
  })

  _it('should poll an extended status', async () => {
    log.notice(await client.pollExtended())
  })
})

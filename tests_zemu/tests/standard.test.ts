/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
// @ts-ignore
import AxelarApp from 'ledger-axelar-js'
import { APP_SEED, example_tx_str_basic, example_tx_str_basic2, models } from './common'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(60000)

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe('Standard', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 5, -5])
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('test_mode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 118, 5, 0, 3]
      const resp = await app.getAddressAndPubKey(path, 'axelar')

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      expect(resp).toHaveProperty('bech32_address')
      expect(resp).toHaveProperty('compressed_pk')

      expect(resp.bech32_address).toEqual('axelar1wkd9tfm5pqvhhaxq77wv9tvjcsazuaykwsld65')
      expect(resp.compressed_pk.length).toEqual(33)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 118, 5, 0, 3]
      const respRequest = app.showAddressAndPubKey(path, 'axelar')
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-show_address`, 2)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      expect(resp).toHaveProperty('bech32_address')
      expect(resp).toHaveProperty('compressed_pk')

      expect(resp.bech32_address).toEqual('axelar1wkd9tfm5pqvhhaxq77wv9tvjcsazuaykwsld65')
      expect(resp.compressed_pk.length).toEqual(33)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show address HUGE', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 118, 2147483647, 0, 4294967295]
      const resp = await app.showAddressAndPubKey(path, 'axelar')
      console.log(resp)

      expect(resp.return_code).toEqual(0x6985)
      expect(resp.error_message).toEqual('Conditions not satisfied')
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show address HUGE Expect', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      // Activate expert mode
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 118, 2147483647, 0, 4294967295]
      const respRequest = app.showAddressAndPubKey(path, 'axelar')

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // Now navigate the address / path
      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-show_address_huge`, 3)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      expect(resp).toHaveProperty('bech32_address')
      expect(resp).toHaveProperty('compressed_pk')

      expect(resp.bech32_address).toEqual('axelar1ex7gkwwmq4vcgdwcalaq3t20pgwr37u6ntkqzh')
      expect(resp.compressed_pk.length).toEqual(33)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign basic normal', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      const path = [44, 118, 0, 0, 0]
      const tx = JSON.stringify(example_tx_str_basic)

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'axelar')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')
      console.log(respPk)

      // do not wait here..
      const signatureRequest = app.sign(path, tx)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // Now navigate the address / path
      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_basic`, m.prefix == 'S' ? 6 : 5)

      const resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign basic normal2', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AxelarApp(sim.getTransport())

      const path = [44, 118, 0, 0, 0]
      const tx = JSON.stringify(example_tx_str_basic2)

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'axelar')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')
      console.log(respPk)

      // do not wait here..
      const signatureRequest = app.sign(path, tx)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // Now navigate the address / path
      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_basic2`, m.prefix == 'S' ? 7 : 6)

      const resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

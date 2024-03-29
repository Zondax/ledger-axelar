/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
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
import Transport from '@ledgerhq/hw-transport'
import { ResponseAddress, ResponseAppInfo, ResponseDeviceInfo, ResponseSign, ResponseVersion } from './types'
import {
  CHUNK_SIZE,
  errorCodeToString,
  getVersion,
  LedgerError,
  P1_VALUES,
  PAYLOAD_TYPE,
  processErrorResponse,
  serializePath,
} from './common'
import { CLA, INS, PKLEN } from './config'

export { LedgerError }
export * from './types'

function processGetAddrResponse(response: Buffer) {
  const errorCodeData = response.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  const publicKey = Buffer.from(response.slice(0, PKLEN))
  const address = Buffer.from(response.slice(PKLEN, -2)).toString()

  return {
    // Legacy
    bech32_address: address,
    compressed_pk: publicKey,
    //
    publicKey,
    address,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
    // legacy
    return_code: returnCode,
    error_message: errorCodeToString(returnCode),
  }
}

export default class AxelarApp {
  private transport: Transport

  constructor(transport: Transport) {
    if (!transport) {
      throw new Error('Transport has not been defined')
    }
    this.transport = transport
  }

  static prepareChunks(serializedPathBuffer: Buffer, message: Buffer) {
    const chunks = []

    // First chunk (only path)
    chunks.push(serializedPathBuffer)

    const messageBuffer = Buffer.from(message)

    const buffer = Buffer.concat([messageBuffer])
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > buffer.length) {
        end = buffer.length
      }
      chunks.push(buffer.slice(i, end))
    }

    return chunks
  }

  async signGetChunks(path: string | number[], message: string | Buffer) {
    if (typeof message === 'string') {
      return AxelarApp.prepareChunks(serializePath(path), Buffer.from(message))
    }

    return AxelarApp.prepareChunks(serializePath(path), message)
  }

  async getVersion(): Promise<ResponseVersion> {
    return getVersion(this.transport).catch(err => processErrorResponse(err))
  }

  async getAppInfo(): Promise<ResponseAppInfo> {
    return this.transport.send(0xb0, 0x01, 0, 0).then(response => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const result: { errorMessage?: string; returnCode?: LedgerError } = {}

      let appName = 'err'
      let appVersion = 'err'
      let flagLen = 0
      let flagsValue = 0

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.errorMessage = 'response format ID not recognized'
        result.returnCode = LedgerError.DeviceIsBusy
      } else {
        const appNameLen = response[1]
        appName = response.slice(2, 2 + appNameLen).toString('ascii')
        let idx = 2 + appNameLen
        const appVersionLen = response[idx]
        idx += 1
        appVersion = response.slice(idx, idx + appVersionLen).toString('ascii')
        idx += appVersionLen
        const appFlagsLen = response[idx]
        idx += 1
        flagLen = appFlagsLen
        flagsValue = response[idx]
      }

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        // legacy
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPINValidated: (flagsValue & 128) !== 0,
      }
    }, processErrorResponse)
  }

  async deviceInfo(): Promise<ResponseDeviceInfo> {
    return this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [0x6e00]).then(response => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: 'This command is only available in the Dashboard',
        }
      }

      const targetId = response.slice(0, 4).toString('hex')

      let pos = 4
      const secureElementVersionLen = response[pos]
      pos += 1
      const seVersion = response.slice(pos, pos + secureElementVersionLen).toString()
      pos += secureElementVersionLen

      const flagsLen = response[pos]
      pos += 1
      const flag = response.slice(pos, pos + flagsLen).toString('hex')
      pos += flagsLen

      const mcuVersionLen = response[pos]
      pos += 1
      // Patch issue in mcu version
      let tmp = response.slice(pos, pos + mcuVersionLen)
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.slice(pos, pos + mcuVersionLen - 1)
      }
      const mcuVersion = tmp.toString()

      return {
        returnCode: returnCode,
        errorMessage: errorCodeToString(returnCode),
        // legacy
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        targetId,
        seVersion,
        flag,
        mcuVersion,
      }
    }, processErrorResponse)
  }

  static serializeHRP(hrp: string) {
    if (hrp == null || hrp.length < 3 || hrp.length > 83) {
      throw new Error('Invalid HRP')
    }
    const buf = Buffer.alloc(1 + hrp.length)
    buf.writeUInt8(hrp.length, 0)
    buf.write(hrp, 1)
    return buf
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async getAddressAndPubKey(path: string | number[], bech32Prefix: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path)
    const data = Buffer.concat([AxelarApp.serializeHRP(bech32Prefix), serializedPath])

    return this.transport
      .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.ONLY_RETRIEVE, 0, data, [0x9000])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async showAddressAndPubKey(path: string | number[], bech32Prefix: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path)
    const data = Buffer.concat([AxelarApp.serializeHRP(bech32Prefix), serializedPath])

    return this.transport
      .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, data, [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST
    }

    return this.transport
      .send(CLA, INS.SIGN_SECP256K1, payloadType, 0, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        // let preSignHash = Buffer.alloc(0);
        // let signatureRS = Buffer.alloc(0);
        // let signatureDER = Buffer.alloc(0);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          const signature = response.slice(0, response.length - 2)
          return {
            signature,
            returnCode: returnCode,
            errorMessage: errorMessage,
            // legacy
            return_code: returnCode,
            error_message: errorCodeToString(returnCode),
          }
        }

        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
          // legacy
          return_code: returnCode,
          error_message: errorCodeToString(returnCode),
        } as ResponseSign
      }, processErrorResponse)
  }

  async sign(path: string | number[], message: string | Buffer) {
    return this.signGetChunks(path, message).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0]).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          // legacy
          return_code: response.returnCode,
          error_message: response.errorMessage,
          ///
          preSignHash: null as null | Buffer,
          signatureRS: null as null | Buffer,
          signatureDER: null as null | Buffer,
        } as ResponseSign

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i])
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)
  }
}

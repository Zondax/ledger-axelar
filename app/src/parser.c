/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
********************************************************************************/

#include <stdio.h>
#include <zxmacros.h>
#include <zxformat.h>
#include <tx_validate.h>
#include <zxtypes.h>
#include "tx_parser.h"
#include "tx_display.h"
#include "parser_impl.h"
#include "common/parser.h"
#include "coin.h"

parser_error_t parser_parse(parser_context_t *ctx,
                            const uint8_t *data,
                            size_t dataLen) {
    CHECK_PARSER_ERR(tx_display_readTx(ctx, data, dataLen))
    return parser_ok;
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(tx_validate(&parser_tx_obj.json))

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx __attribute__((unused)), uint8_t *num_items) {
    *num_items = 0;
    return tx_display_numItems(num_items);
}

__Z_INLINE bool_t parser_areEqual(uint16_t tokenidx, char *expected) {
    if (parser_tx_obj.json.tokens[tokenidx].type != JSMN_STRING) {
        return bool_false;
    }

    int32_t len = parser_tx_obj.json.tokens[tokenidx].end - parser_tx_obj.json.tokens[tokenidx].start;
    if (len < 0) {
        return bool_false;
    }

    if (strlen(expected) != (size_t) len) {
        return bool_false;
    }

    const char *p = parser_tx_obj.tx + parser_tx_obj.json.tokens[tokenidx].start;
    for (int32_t i = 0; i < len; i++) {
        if (expected[i] != *(p + i)) {
            return bool_false;
        }
    }

    return bool_true;
}

__Z_INLINE bool_t parser_isAmount(char *key) {
    if (strcmp(key, "fee/amount") == 0)
        return bool_true;

    if (strcmp(key, "msgs/inputs/coins") == 0)
        return bool_true;

    if (strcmp(key, "msgs/outputs/coins") == 0)
        return bool_true;

    if (strcmp(key, "msgs/value/amount") == 0)
        return bool_true;

    return bool_false;
}

__Z_INLINE bool_t is_default_denom_base(const char *denom, uint8_t denom_len) {
    if (tx_is_expert_mode()) {
        return false;
    }

    if (strlen(COIN_DEFAULT_DENOM_BASE) != denom_len) {
        return bool_false;
    }

    if (memcmp(denom, COIN_DEFAULT_DENOM_BASE, denom_len) == 0)
        return bool_true;

    return bool_false;
}

__Z_INLINE parser_error_t parser_formatAmount(uint16_t amountToken,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 0;
    if (parser_tx_obj.json.tokens[amountToken].type == JSMN_ARRAY) {
        amountToken++;
    }

    uint16_t numElements;

    CHECK_PARSER_ERR(array_get_element_count(&parser_tx_obj.json, amountToken, &numElements))

    if (numElements == 0) {
        *pageCount = 1;
        snprintf(outVal, outValLen, "Empty");
        return parser_ok;
    }

    if (numElements != 4)
        return parser_unexpected_field;

    if (parser_tx_obj.json.tokens[amountToken].type != JSMN_OBJECT)
        return parser_unexpected_field;

    if (!parser_areEqual(amountToken + 1u, "amount"))
        return parser_unexpected_field;

    if (!parser_areEqual(amountToken + 3u, "denom"))
        return parser_unexpected_field;

    char bufferUI[160];
    char tmpDenom[COIN_DENOM_MAXSIZE];
    char tmpAmount[COIN_AMOUNT_MAXSIZE];
    MEMZERO(tmpDenom, sizeof tmpDenom);
    MEMZERO(tmpAmount, sizeof(tmpAmount));
    MEMZERO(outVal, outValLen);
    MEMZERO(bufferUI, sizeof(bufferUI));

    const char *amountPtr = parser_tx_obj.tx + parser_tx_obj.json.tokens[amountToken + 2].start;
    if (parser_tx_obj.json.tokens[amountToken + 2].start < 0) {
        return parser_unexpected_buffer_end;
    }

    const int32_t amountLen = parser_tx_obj.json.tokens[amountToken + 2].end -
                              parser_tx_obj.json.tokens[amountToken + 2].start;
    const char *denomPtr = parser_tx_obj.tx + parser_tx_obj.json.tokens[amountToken + 4].start;
    const int32_t denomLen = parser_tx_obj.json.tokens[amountToken + 4].end -
                             parser_tx_obj.json.tokens[amountToken + 4].start;

    if (denomLen <= 0 || denomLen >= COIN_DENOM_MAXSIZE) {
        return parser_unexpected_error;
    }
    if (amountLen <= 0 || amountLen >= COIN_AMOUNT_MAXSIZE) {
        return parser_unexpected_error;
    }

    const size_t totalLen = amountLen + denomLen + 2;
    if (sizeof(bufferUI) < totalLen) {
        return parser_unexpected_buffer_end;
    }

    // Extract amount and denomination
    MEMCPY(tmpDenom, denomPtr, denomLen);
    MEMCPY(tmpAmount, amountPtr, amountLen);

    snprintf(bufferUI, sizeof(bufferUI), "%s ", tmpAmount);
    // If denomination has been recognized format and replace
    if (is_default_denom_base(denomPtr, denomLen)) {
        if (fpstr_to_str(bufferUI, sizeof(bufferUI), tmpAmount, COIN_DEFAULT_DENOM_FACTOR) != 0) {
            return parser_unexpected_error;
        }
        number_inplace_trimming(bufferUI, COIN_DEFAULT_DENOM_TRIMMING);
        snprintf(tmpDenom, sizeof(tmpDenom), " %s", COIN_DEFAULT_DENOM_REPR);
    }

    z_str3join(bufferUI, sizeof(bufferUI), "", tmpDenom);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 0;

    char tmpKey[100];

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);

    uint8_t numItems;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (numItems == 0) {
        return parser_unexpected_number_items;
    }

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }

    uint16_t ret_value_token_index = 0;
    CHECK_PARSER_ERR(tx_display_query(displayIdx, tmpKey, sizeof(tmpKey), &ret_value_token_index))
    CHECK_APP_CANARY()
    snprintf(outKey, outKeyLen, "%s", tmpKey);

    if (parser_isAmount(tmpKey)) {
        CHECK_PARSER_ERR(
                parser_formatAmount(ret_value_token_index,
                                    outVal, outValLen,
                                    pageIdx, pageCount))
    } else {
        CHECK_PARSER_ERR(tx_getToken(ret_value_token_index,
                                     outVal, outValLen,
                                     pageIdx, pageCount))
    }
    CHECK_APP_CANARY()

    CHECK_PARSER_ERR(tx_display_make_friendly())
    CHECK_APP_CANARY()

    snprintf(outKey, outKeyLen, "%s", tmpKey);
    CHECK_APP_CANARY()

    return parser_ok;
}

// Copyright 2007 The Closure Library Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @fileoverview Base64 en/decoding. Not much to say here except that we
 * work with decoded values in arrays of bytes. By "byte" I mean a number
 * in [0, 255].
 *
 * @author doughtie@google.com (Gavin Doughtie)
 */

// Static lookup maps, lazily populated by init_()

import _ from 'lodash';
import {stringToByteArray, byteArrayToString} from './crypt';

/**
 * Maps bytes to characters.
 * @type {Object}
 * @private
 */
let byteToCharMap_ = null,
    /**
     * Maps characters to bytes.
     * @type {Object}
     * @private
     */
    charToByteMap_ = null,
    /**
     * Maps bytes to websafe characters.
     * @type {Object}
     * @private
     */
    byteToCharMapWebSafe_ = null,
    /**
     * Maps websafe characters to bytes.
     * @type {Object}
     * @private
     */
    charToByteMapWebSafe_ = null;

function isArray (value) {
  return _.isArray(value) || value instanceof Uint8Array || value instanceof Buffer;
}

/**
 * Our default alphabet, shared between
 * ENCODED_VALS and ENCODED_VALS_WEBSAFE
 * @type {string}
 */
const ENCODED_VALS_BASE =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789',

    /**
     * Our default alphabet. Value 64 (=) is special; it means "nothing."
     * @type {string}
     */
    ENCODED_VALS = ENCODED_VALS_BASE + '+/=',

    /**
     * Our websafe alphabet.
     * @type {string}
     */
    ENCODED_VALS_WEBSAFE = ENCODED_VALS_BASE + '-_.',

    /**
     * Whether this browser supports the atob and btoa functions. This extension
     * started at Mozilla but is now implemented by many browsers. We use the
     * ASSUME_* variables to avoid pulling in the full useragent detection library
     * but still allowing the standard per-browser compilations.
     *
     * @type {boolean}
     */
    HAS_NATIVE_SUPPORT = typeof atob === 'function';

class Base64 {
  /**
   * Base64-encode an array of bytes.
   *
   * @param {Array<number>|Uint8Array} input An array of bytes (numbers with
   *     value in [0, 255]) to encode.
   * @param {boolean=} optWebSafe Boolean indicating we should use the
   *     alternative alphabet.
   * @return {string} The base64 encoded string.
   */
  static encodeByteArray (input, optWebSafe) {
    if (!isArray(input)) {
      throw Error('encodeByteArray takes an array as a parameter');
    }

    Base64.init_();

    let byteToCharMap = optWebSafe ?
                        byteToCharMapWebSafe_ :
                        byteToCharMap_,
        output = [],
        i, byte1, haveByte2, byte2, haveByte3, byte3, outByte1, outByte2, outByte3, outByte4;

    for (i = 0; i < input.length; i += 3) {
      byte1 = input[i];
      haveByte2 = i + 1 < input.length;
      byte2 = haveByte2 ? input[i + 1] : 0;
      haveByte3 = i + 2 < input.length;
      byte3 = haveByte3 ? input[i + 2] : 0;

      outByte1 = byte1 >> 2;
      outByte2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
      outByte3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
      outByte4 = byte3 & 0x3F;

      if (!haveByte3) {
        outByte4 = 64;

        if (!haveByte2) {
          outByte3 = 64;
        }
      }

      output.push(byteToCharMap[outByte1],
                  byteToCharMap[outByte2],
                  byteToCharMap[outByte3],
                  byteToCharMap[outByte4]);
    }

    return output.join('');
  }

  /**
   * Base64-encode a string.
   *
   * @param {string} input A string to encode.
   * @param {boolean=} optWebSafe If true, we should use the
   *     alternative alphabet.
   * @return {string} The base64 encoded string.
   */
  static encodeString (input, optWebSafe) {
    // Shortcut for Mozilla browsers that implement
    // a native base64 encoder in the form of "btoa/atob"
    if (HAS_NATIVE_SUPPORT && !optWebSafe) {
      return btoa(input);
    }
    return Base64.encodeByteArray(stringToByteArray(input), optWebSafe);
  };


  /**
   * Base64-decode a string.
   *
   * @param {string} input to decode.
   * @param {boolean=} optWebSafe True if we should use the
   *     alternative alphabet.
   * @return {string} string representing the decoded value.
   */
  static decodeString (input, optWebSafe) {
    // Shortcut for Mozilla browsers that implement
    // a native base64 encoder in the form of "btoa/atob"
    if (HAS_NATIVE_SUPPORT && !optWebSafe) {
      return atob(input);
    }
    return byteArrayToString(Base64.decodeStringToByteArray(input, optWebSafe));
  }

  /**
   * Base64-decode a string.
   *
   * In base-64 decoding, groups of four characters are converted into three
   * bytes.  If the encoder did not apply padding, the input length may not
   * be a multiple of 4.
   *
   * In this case, the last group will have fewer than 4 characters, and
   * padding will be inferred.  If the group has one or two characters, it decodes
   * to one byte.  If the group has three characters, it decodes to two bytes.
   *
   * @param {string} input Input to decode.
   * @param {boolean=} optWebSafe True if we should use the web-safe alphabet.
   * @return {!Array<number>} bytes representing the decoded value.
   */
  static decodeStringToByteArray (input, optWebSafe) {
    Base64.init_();

    let charToByteMap = optWebSafe ?
                        charToByteMapWebSafe_ :
                        charToByteMap_,
        output = [],
        i, byte1, haveByte2, byte2, haveByte3, byte3, haveByte4, byte4, outByte1, outByte2, outByte3;

    for (i = 0; i < input.length; ) {
      byte1 = charToByteMap[input.charAt(i++)];

      haveByte2 = i < input.length;
      byte2 = haveByte2 ? charToByteMap[input.charAt(i)] : 0;
      ++i;

      haveByte3 = i < input.length;
      byte3 = haveByte3 ? charToByteMap[input.charAt(i)] : 64;
      ++i;

      haveByte4 = i < input.length;
      byte4 = haveByte4 ? charToByteMap[input.charAt(i)] : 64;
      ++i;

      if (byte1 === null || byte2 === null ||
          byte3 === null || byte4 === null) {
        throw Error();
      }

      outByte1 = (byte1 << 2) | (byte2 >> 4);
      output.push(outByte1);

      if (byte3 !== 64) {
        outByte2 = ((byte2 << 4) & 0xF0) | (byte3 >> 2);
        output.push(outByte2);

        if (byte4 !== 64) {
          outByte3 = ((byte3 << 6) & 0xC0) | byte4;
          output.push(outByte3);
        }
      }
    }

    return output;
  }

  /**
   * Lazy static initialization function. Called before
   * accessing any of the static map variables.
   * @private
   */
  static init_ () {
    if (!byteToCharMap_) {
      byteToCharMap_ = {};
      charToByteMap_ = {};
      byteToCharMapWebSafe_ = {};
      charToByteMapWebSafe_ = {};

      // We want quick mappings back and forth, so we precompute two maps.
      for (let i = 0; i < ENCODED_VALS.length; i++) {
        byteToCharMap_[i] = ENCODED_VALS.charAt(i);
        charToByteMap_[byteToCharMap_[i]] = i;
        byteToCharMapWebSafe_[i] = ENCODED_VALS_WEBSAFE.charAt(i);
        charToByteMapWebSafe_[byteToCharMapWebSafe_[i]] = i;

        // Be forgiving when decoding and correctly decode both encodings.
        if (i >= ENCODED_VALS_BASE.length) {
          charToByteMap_[ENCODED_VALS_WEBSAFE.charAt(i)] = i;
          charToByteMapWebSafe_[ENCODED_VALS.charAt(i)] = i;
        }
      }
    }
  }
}

export default Base64;

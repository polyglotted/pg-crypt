import {assert} from 'chai';
import _ from 'lodash';

class Crypt {
  /**
   * Turns an array of numbers into the hex string given by the concatenation of
   * the hex values to which the numbers correspond.
   * @param {Uint8Array|Array<number>} array Array of numbers representing
   *     characters.
   * @return {string} Hex string.
   */
  static byteArrayToHex (array) {
    return _.map(array, (numByte) => {
      let hexByte = numByte.toString(16);
      return hexByte.length > 1 ? hexByte : '0' + hexByte;
    }).join('');
  }

  /**
   * Converts a hex string into an integer array.
   * @param {string} hexString Hex string of 16-bit integers (two characters
   *     per integer).
   * @return {!Array<number>} Array of {0,255} integers for the given string.
   */
  static hexToByteArray (hexString) {
    assert.equals(hexString.length % 2, 0, 'Key string length must be multiple of 2');
    let arr = [],
        i;
    for (i = 0; i < hexString.length; i += 2) {
      arr.push(parseInt(hexString.substring(i, i + 2), 16));
    }
    return arr;
  }

  /**
   * Turns a string into an array of bytes; a "byte" being a JS number in the
   * range 0-255.
   * @param {string} str String value to arrify.
   * @return {!Array<number>} Array of numbers corresponding to the
   *     UCS character codes of each character in str.
   */
   static stringToByteArray (str) {
    let output = [],
        p = 0,
        i,
        c;
    for (i = 0; i < str.length; i++) {
      c = str.charCodeAt(i);
      while (c > 0xff) {
        output[p++] = c & 0xff;
        c >>= 8;
      }
      output[p++] = c;
    }
    return output;
  }

  /**
   * Turns an array of numbers into the string given by the concatenation of the
   * characters to which the numbers correspond.
   * @param {Array<number>} bytes Array of numbers representing characters.
   * @return {string} Stringification of the array.
   */
  static byteArrayToString (array) {
    return String.fromCharCode.apply(null, array);
  }

  /**
   * Converts a JS string to a UTF-8 "byte" array.
   * @param {string} str 16-bit unicode string.
   * @return {!Array<number>} UTF-8 byte array.
   */
  static stringToUtf8ByteArray (s) {
    let str = s.replace(/\r\n/g, '\n'),
        out = [],
        p = 0,
        c,
        i;
    for (i = 0; i < str.length; i++) {
      c = str.charCodeAt(i);
      if (c < 128) {
        out[p++] = c;
      } else if (c < 2048) {
        out[p++] = (c >> 6) | 192;
        out[p++] = (c & 63) | 128;
      } else {
        out[p++] = (c >> 12) | 224;
        out[p++] = ((c >> 6) & 63) | 128;
        out[p++] = (c & 63) | 128;
      }
    }
    return out;
  }

  /**
   * Converts a UTF-8 byte array to JavaScript's 16-bit Unicode.
   * @param {Uint8Array|Array<number>} bytes UTF-8 byte array.
   * @return {string} 16-bit Unicode string.
   */
  static utf8ByteArrayToString (bytes) {
    let out = [],
        pos = 0,
        c = 0,
        c1,
        c2,
        c3;
    while (pos < bytes.length) {
      c1 = bytes[pos++];
      if (c1 < 128) {
        out[c++] = String.fromCharCode(c1);
      } else if (c1 > 191 && c1 < 224) {
        c2 = bytes[pos++];
        out[c++] = String.fromCharCode((c1 & 31) << 6 | c2 & 63);
      } else {
        c2 = bytes[pos++];
        c3 = bytes[pos++];
        out[c++] = String.fromCharCode((c1 & 15) << 12 | (c2 & 63) << 6 | c3 & 63);
      }
    }
    return out.join('');
  }
}

export default Crypt;

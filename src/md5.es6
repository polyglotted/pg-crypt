// Copyright 2011 The Closure Library Authors. All Rights Reserved.
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
 * @fileoverview MD5 cryptographic hash.
 * Implementation of http://tools.ietf.org/html/rfc1321 with common
 * optimizations and tweaks (see http://en.wikipedia.org/wiki/MD5).
 *
 * Usage:
 *   let md5 = new Md5();
 *   md5.update(bytes);
 *   let hash = md5.digest();
 *
 * Performance:
 *   Chrome 23              ~680 Mbit/s
 *   Chrome 13 (in a VM)    ~250 Mbit/s
 *   Firefox 6.0 (in a VM)  ~100 Mbit/s
 *   IE9 (in a VM)           ~27 Mbit/s
 *   Firefox 3.6             ~15 Mbit/s
 *   IE8 (in a VM)           ~13 Mbit/s
 *
 */

import Hash from './hash';
import _ from 'lodash';
import {byteArrayToHex} from './crypt';

/**
 * MD5 cryptographic hash constructor.
 * @constructor
 * @final
 * @struct
 */
class Md5 extends Hash {
  constructor () {
    super();

    this.blockSize = 512 / 8;

    /**
     * Holds the current values of accumulated A-D variables (MD buffer).
     * @type {!Array<number>}
     * @private
     */
    this.chain_ = new Array(4);

    /**
     * A buffer holding the data until the whole block can be processed.
     * @type {!Array<number>}
     * @private
     */
    this.block_ = new Array(this.blockSize);

    /**
     * The length of yet-unprocessed data as collected in the block.
     * @type {number}
     * @private
     */
    this.blockLength_ = 0;

    /**
     * The total length of the message so far.
     * @type {number}
     * @private
     */
    this.totalLength_ = 0;

    this.reset();
  }

  reset () {
    this.chain_[0] = 0x67452301;
    this.chain_[1] = 0xefcdab89;
    this.chain_[2] = 0x98badcfe;
    this.chain_[3] = 0x10325476;

    this.blockLength_ = 0;
    this.totalLength_ = 0;
  }

  /**
   * Internal compress helper function. It takes a block of data (64 bytes)
   * and updates the accumulator.
   * @param {Array<number>|Uint8Array|string} buf The block to compress.
   * @param {number=} optOffset Offset of the block in the buffer.
   * @private
   */
  compress_ (buf, optOffset) {
    let offset = optOffset,
        X, i, A, B, C, D, sum;
    if (!offset) {
      offset = 0;
    }

    // We allocate the array every time, but it's cheap in practice.
    X = new Array(16);

    // Get 16 little endian words. It is not worth unrolling this for Chrome 11.
    if (_.isString(buf)) {
      for (i = 0; i < 16; ++i) {
        X[i] = (buf.charCodeAt(offset++)) |
               (buf.charCodeAt(offset++) << 8) |
               (buf.charCodeAt(offset++) << 16) |
               (buf.charCodeAt(offset++) << 24);
      }
    } else {
      for (i = 0; i < 16; ++i) {
        X[i] = (buf[offset++]) |
               (buf[offset++] << 8) |
               (buf[offset++] << 16) |
               (buf[offset++] << 24);
      }
    }

    A = this.chain_[0];
    B = this.chain_[1];
    C = this.chain_[2];
    D = this.chain_[3];
    sum = 0;

    /*
     * This is an unrolled MD5 implementation, which gives ~30% speedup compared
     * to the abbreviated implementation above, as measured on Chrome 11. It is
     * important to keep 32-bit croppings to minimum and inline the integer
     * rotation.
     */
    sum = (A + (D ^ (B & (C ^ D))) + X[0] + 0xd76aa478) & 0xffffffff;
    A = B + (((sum << 7) & 0xffffffff) | (sum >>> 25));
    sum = (D + (C ^ (A & (B ^ C))) + X[1] + 0xe8c7b756) & 0xffffffff;
    D = A + (((sum << 12) & 0xffffffff) | (sum >>> 20));
    sum = (C + (B ^ (D & (A ^ B))) + X[2] + 0x242070db) & 0xffffffff;
    C = D + (((sum << 17) & 0xffffffff) | (sum >>> 15));
    sum = (B + (A ^ (C & (D ^ A))) + X[3] + 0xc1bdceee) & 0xffffffff;
    B = C + (((sum << 22) & 0xffffffff) | (sum >>> 10));
    sum = (A + (D ^ (B & (C ^ D))) + X[4] + 0xf57c0faf) & 0xffffffff;
    A = B + (((sum << 7) & 0xffffffff) | (sum >>> 25));
    sum = (D + (C ^ (A & (B ^ C))) + X[5] + 0x4787c62a) & 0xffffffff;
    D = A + (((sum << 12) & 0xffffffff) | (sum >>> 20));
    sum = (C + (B ^ (D & (A ^ B))) + X[6] + 0xa8304613) & 0xffffffff;
    C = D + (((sum << 17) & 0xffffffff) | (sum >>> 15));
    sum = (B + (A ^ (C & (D ^ A))) + X[7] + 0xfd469501) & 0xffffffff;
    B = C + (((sum << 22) & 0xffffffff) | (sum >>> 10));
    sum = (A + (D ^ (B & (C ^ D))) + X[8] + 0x698098d8) & 0xffffffff;
    A = B + (((sum << 7) & 0xffffffff) | (sum >>> 25));
    sum = (D + (C ^ (A & (B ^ C))) + X[9] + 0x8b44f7af) & 0xffffffff;
    D = A + (((sum << 12) & 0xffffffff) | (sum >>> 20));
    sum = (C + (B ^ (D & (A ^ B))) + X[10] + 0xffff5bb1) & 0xffffffff;
    C = D + (((sum << 17) & 0xffffffff) | (sum >>> 15));
    sum = (B + (A ^ (C & (D ^ A))) + X[11] + 0x895cd7be) & 0xffffffff;
    B = C + (((sum << 22) & 0xffffffff) | (sum >>> 10));
    sum = (A + (D ^ (B & (C ^ D))) + X[12] + 0x6b901122) & 0xffffffff;
    A = B + (((sum << 7) & 0xffffffff) | (sum >>> 25));
    sum = (D + (C ^ (A & (B ^ C))) + X[13] + 0xfd987193) & 0xffffffff;
    D = A + (((sum << 12) & 0xffffffff) | (sum >>> 20));
    sum = (C + (B ^ (D & (A ^ B))) + X[14] + 0xa679438e) & 0xffffffff;
    C = D + (((sum << 17) & 0xffffffff) | (sum >>> 15));
    sum = (B + (A ^ (C & (D ^ A))) + X[15] + 0x49b40821) & 0xffffffff;
    B = C + (((sum << 22) & 0xffffffff) | (sum >>> 10));
    sum = (A + (C ^ (D & (B ^ C))) + X[1] + 0xf61e2562) & 0xffffffff;
    A = B + (((sum << 5) & 0xffffffff) | (sum >>> 27));
    sum = (D + (B ^ (C & (A ^ B))) + X[6] + 0xc040b340) & 0xffffffff;
    D = A + (((sum << 9) & 0xffffffff) | (sum >>> 23));
    sum = (C + (A ^ (B & (D ^ A))) + X[11] + 0x265e5a51) & 0xffffffff;
    C = D + (((sum << 14) & 0xffffffff) | (sum >>> 18));
    sum = (B + (D ^ (A & (C ^ D))) + X[0] + 0xe9b6c7aa) & 0xffffffff;
    B = C + (((sum << 20) & 0xffffffff) | (sum >>> 12));
    sum = (A + (C ^ (D & (B ^ C))) + X[5] + 0xd62f105d) & 0xffffffff;
    A = B + (((sum << 5) & 0xffffffff) | (sum >>> 27));
    sum = (D + (B ^ (C & (A ^ B))) + X[10] + 0x02441453) & 0xffffffff;
    D = A + (((sum << 9) & 0xffffffff) | (sum >>> 23));
    sum = (C + (A ^ (B & (D ^ A))) + X[15] + 0xd8a1e681) & 0xffffffff;
    C = D + (((sum << 14) & 0xffffffff) | (sum >>> 18));
    sum = (B + (D ^ (A & (C ^ D))) + X[4] + 0xe7d3fbc8) & 0xffffffff;
    B = C + (((sum << 20) & 0xffffffff) | (sum >>> 12));
    sum = (A + (C ^ (D & (B ^ C))) + X[9] + 0x21e1cde6) & 0xffffffff;
    A = B + (((sum << 5) & 0xffffffff) | (sum >>> 27));
    sum = (D + (B ^ (C & (A ^ B))) + X[14] + 0xc33707d6) & 0xffffffff;
    D = A + (((sum << 9) & 0xffffffff) | (sum >>> 23));
    sum = (C + (A ^ (B & (D ^ A))) + X[3] + 0xf4d50d87) & 0xffffffff;
    C = D + (((sum << 14) & 0xffffffff) | (sum >>> 18));
    sum = (B + (D ^ (A & (C ^ D))) + X[8] + 0x455a14ed) & 0xffffffff;
    B = C + (((sum << 20) & 0xffffffff) | (sum >>> 12));
    sum = (A + (C ^ (D & (B ^ C))) + X[13] + 0xa9e3e905) & 0xffffffff;
    A = B + (((sum << 5) & 0xffffffff) | (sum >>> 27));
    sum = (D + (B ^ (C & (A ^ B))) + X[2] + 0xfcefa3f8) & 0xffffffff;
    D = A + (((sum << 9) & 0xffffffff) | (sum >>> 23));
    sum = (C + (A ^ (B & (D ^ A))) + X[7] + 0x676f02d9) & 0xffffffff;
    C = D + (((sum << 14) & 0xffffffff) | (sum >>> 18));
    sum = (B + (D ^ (A & (C ^ D))) + X[12] + 0x8d2a4c8a) & 0xffffffff;
    B = C + (((sum << 20) & 0xffffffff) | (sum >>> 12));
    sum = (A + (B ^ C ^ D) + X[5] + 0xfffa3942) & 0xffffffff;
    A = B + (((sum << 4) & 0xffffffff) | (sum >>> 28));
    sum = (D + (A ^ B ^ C) + X[8] + 0x8771f681) & 0xffffffff;
    D = A + (((sum << 11) & 0xffffffff) | (sum >>> 21));
    sum = (C + (D ^ A ^ B) + X[11] + 0x6d9d6122) & 0xffffffff;
    C = D + (((sum << 16) & 0xffffffff) | (sum >>> 16));
    sum = (B + (C ^ D ^ A) + X[14] + 0xfde5380c) & 0xffffffff;
    B = C + (((sum << 23) & 0xffffffff) | (sum >>> 9));
    sum = (A + (B ^ C ^ D) + X[1] + 0xa4beea44) & 0xffffffff;
    A = B + (((sum << 4) & 0xffffffff) | (sum >>> 28));
    sum = (D + (A ^ B ^ C) + X[4] + 0x4bdecfa9) & 0xffffffff;
    D = A + (((sum << 11) & 0xffffffff) | (sum >>> 21));
    sum = (C + (D ^ A ^ B) + X[7] + 0xf6bb4b60) & 0xffffffff;
    C = D + (((sum << 16) & 0xffffffff) | (sum >>> 16));
    sum = (B + (C ^ D ^ A) + X[10] + 0xbebfbc70) & 0xffffffff;
    B = C + (((sum << 23) & 0xffffffff) | (sum >>> 9));
    sum = (A + (B ^ C ^ D) + X[13] + 0x289b7ec6) & 0xffffffff;
    A = B + (((sum << 4) & 0xffffffff) | (sum >>> 28));
    sum = (D + (A ^ B ^ C) + X[0] + 0xeaa127fa) & 0xffffffff;
    D = A + (((sum << 11) & 0xffffffff) | (sum >>> 21));
    sum = (C + (D ^ A ^ B) + X[3] + 0xd4ef3085) & 0xffffffff;
    C = D + (((sum << 16) & 0xffffffff) | (sum >>> 16));
    sum = (B + (C ^ D ^ A) + X[6] + 0x04881d05) & 0xffffffff;
    B = C + (((sum << 23) & 0xffffffff) | (sum >>> 9));
    sum = (A + (B ^ C ^ D) + X[9] + 0xd9d4d039) & 0xffffffff;
    A = B + (((sum << 4) & 0xffffffff) | (sum >>> 28));
    sum = (D + (A ^ B ^ C) + X[12] + 0xe6db99e5) & 0xffffffff;
    D = A + (((sum << 11) & 0xffffffff) | (sum >>> 21));
    sum = (C + (D ^ A ^ B) + X[15] + 0x1fa27cf8) & 0xffffffff;
    C = D + (((sum << 16) & 0xffffffff) | (sum >>> 16));
    sum = (B + (C ^ D ^ A) + X[2] + 0xc4ac5665) & 0xffffffff;
    B = C + (((sum << 23) & 0xffffffff) | (sum >>> 9));
    sum = (A + (C ^ (B | (~D))) + X[0] + 0xf4292244) & 0xffffffff;
    A = B + (((sum << 6) & 0xffffffff) | (sum >>> 26));
    sum = (D + (B ^ (A | (~C))) + X[7] + 0x432aff97) & 0xffffffff;
    D = A + (((sum << 10) & 0xffffffff) | (sum >>> 22));
    sum = (C + (A ^ (D | (~B))) + X[14] + 0xab9423a7) & 0xffffffff;
    C = D + (((sum << 15) & 0xffffffff) | (sum >>> 17));
    sum = (B + (D ^ (C | (~A))) + X[5] + 0xfc93a039) & 0xffffffff;
    B = C + (((sum << 21) & 0xffffffff) | (sum >>> 11));
    sum = (A + (C ^ (B | (~D))) + X[12] + 0x655b59c3) & 0xffffffff;
    A = B + (((sum << 6) & 0xffffffff) | (sum >>> 26));
    sum = (D + (B ^ (A | (~C))) + X[3] + 0x8f0ccc92) & 0xffffffff;
    D = A + (((sum << 10) & 0xffffffff) | (sum >>> 22));
    sum = (C + (A ^ (D | (~B))) + X[10] + 0xffeff47d) & 0xffffffff;
    C = D + (((sum << 15) & 0xffffffff) | (sum >>> 17));
    sum = (B + (D ^ (C | (~A))) + X[1] + 0x85845dd1) & 0xffffffff;
    B = C + (((sum << 21) & 0xffffffff) | (sum >>> 11));
    sum = (A + (C ^ (B | (~D))) + X[8] + 0x6fa87e4f) & 0xffffffff;
    A = B + (((sum << 6) & 0xffffffff) | (sum >>> 26));
    sum = (D + (B ^ (A | (~C))) + X[15] + 0xfe2ce6e0) & 0xffffffff;
    D = A + (((sum << 10) & 0xffffffff) | (sum >>> 22));
    sum = (C + (A ^ (D | (~B))) + X[6] + 0xa3014314) & 0xffffffff;
    C = D + (((sum << 15) & 0xffffffff) | (sum >>> 17));
    sum = (B + (D ^ (C | (~A))) + X[13] + 0x4e0811a1) & 0xffffffff;
    B = C + (((sum << 21) & 0xffffffff) | (sum >>> 11));
    sum = (A + (C ^ (B | (~D))) + X[4] + 0xf7537e82) & 0xffffffff;
    A = B + (((sum << 6) & 0xffffffff) | (sum >>> 26));
    sum = (D + (B ^ (A | (~C))) + X[11] + 0xbd3af235) & 0xffffffff;
    D = A + (((sum << 10) & 0xffffffff) | (sum >>> 22));
    sum = (C + (A ^ (D | (~B))) + X[2] + 0x2ad7d2bb) & 0xffffffff;
    C = D + (((sum << 15) & 0xffffffff) | (sum >>> 17));
    sum = (B + (D ^ (C | (~A))) + X[9] + 0xeb86d391) & 0xffffffff;
    B = C + (((sum << 21) & 0xffffffff) | (sum >>> 11));

    this.chain_[0] = (this.chain_[0] + A) & 0xffffffff;
    this.chain_[1] = (this.chain_[1] + B) & 0xffffffff;
    this.chain_[2] = (this.chain_[2] + C) & 0xffffffff;
    this.chain_[3] = (this.chain_[3] + D) & 0xffffffff;
  }

  update (bytes, optLength) {
    let length = optLength,
        lengthMinusBlock,
        block,
        blockLength,
        i;

    if (_.isUndefined(length)) {
      length = bytes.length;
    }
    lengthMinusBlock = length - this.blockSize;

    // Copy some object properties to local variables in order to save on access
    // time from inside the loop (~10% speedup was observed on Chrome 11).
    block = this.block_;
    blockLength = this.blockLength_;
    i = 0;

    // The outer while loop should execute at most twice.
    while (i < length) {
      // When we have no data in the block to top up, we can directly process the
      // input buffer (assuming it contains sufficient data). This gives ~30%
      // speedup on Chrome 14 and ~70% speedup on Firefox 6.0, but requires that
      // the data is provided in large chunks (or in multiples of 64 bytes).
      if (blockLength === 0) {
        while (i <= lengthMinusBlock) {
          this.compress_(bytes, i);
          i += this.blockSize;
        }
      }

      if (_.isString(bytes)) {
        while (i < length) {
          block[blockLength++] = bytes.charCodeAt(i++);
          if (blockLength === this.blockSize) {
            this.compress_(block);
            blockLength = 0;
            // Jump to the outer loop so we use the full-block optimization.
            break;
          }
        }
      } else {
        while (i < length) {
          block[blockLength++] = bytes[i++];
          if (blockLength === this.blockSize) {
            this.compress_(block);
            blockLength = 0;
            // Jump to the outer loop so we use the full-block optimization.
            break;
          }
        }
      }
    }

    this.blockLength_ = blockLength;
    this.totalLength_ += length;
  }

  digest () {
    // This must accommodate at least 1 padding byte (0x80), 8 bytes of
    // total bitlength, and must end at a 64-byte boundary.
    let pad = new Array((this.blockLength_ < 56 ?
                         this.blockSize :
                         this.blockSize * 2) - this.blockLength_),
        i, totalBits, digest, n, j;

    // Add padding: 0x80 0x00*
    pad[0] = 0x80;
    for (i = 1; i < pad.length - 8; ++i) {
      pad[i] = 0;
    }
    // Add the total number of bits, little endian 64-bit integer.
    totalBits = this.totalLength_ * 8;
    for (i = pad.length - 8; i < pad.length; ++i) {
      pad[i] = totalBits & 0xff;
      totalBits /= 0x100; // Don't use bit-shifting here!
    }
    this.update(pad);

    digest = new Array(16);
    n = 0;
    for (i = 0; i < 4; ++i) {
      for (j = 0; j < 32; j += 8) {
        digest[n++] = (this.chain_[i] >>> j) & 0xff;
      }
    }
    return digest;
  }

  static hash (bytes, optLength) {
    let md5 = new Md5();
    md5.update(bytes, optLength);
    return byteArrayToHex(md5.digest());
  }
}

export default Md5;

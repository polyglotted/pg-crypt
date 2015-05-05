class Crypt {
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

  static byteArrayToString (array) {
    return String.fromCharCode.apply(null, array);
  }

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

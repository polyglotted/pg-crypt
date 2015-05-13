import Base64 from '../../src/base64';
import {stringToByteArray, byteArrayToString} from '../../src/crypt';

describe('Base64', () => {
  let tests = [
    '', '',
    'f', 'Zg==',
    'fo', 'Zm8=',
    'foo', 'Zm9v',
    'foob', 'Zm9vYg==',
    'fooba', 'Zm9vYmE=',
    'foobar', 'Zm9vYmFy',

    // Testing non-ascii characters (1-10 in chinese)
    '\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5' +
        '\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81',
    '5LiA5LqM5LiJ5Zub5LqU5YWt5LiD5YWr5Lmd5Y2B'];

  it('should encode byte arrays', () => {
    // Let's see if it's sane by feeding it some well-known values. Index i
    // has the input and index i+1 has the expected value.
    let i, enc, dec;
    for (i = 0; i < tests.length; i += 2) {
      enc = Base64.encodeByteArray(stringToByteArray(tests[i]));
      expect(tests[i + 1]).toEqual(enc);
      dec = byteArrayToString(Base64.decodeStringToByteArray(enc));
      expect(tests[i]).toEqual(dec);

      // Check that websafe decoding accepts non-websafe codes.
      dec = byteArrayToString(Base64.decodeStringToByteArray(enc, true /* websafe */));
      expect(tests[i]).toEqual(dec);

      // Re-encode as websafe.
      enc = Base64.encodeByteArray(stringToByteArray(tests[i], true /* websafe */));

      // Check that non-websafe decoding accepts websafe codes.
      dec = byteArrayToString(Base64.decodeStringToByteArray(enc));
      expect(tests[i]).toEqual(dec);

      // Check that websafe decoding accepts websafe codes.
      dec = byteArrayToString(Base64.decodeStringToByteArray(enc, true /* websafe */));
      expect(tests[i]).toEqual(dec);
    }
  });
});

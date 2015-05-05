import Crypt from '../../src/pg-crypt';

describe('Crypt', () => {
  let methods,
      tests,
      UTF8_RANGES_BYTE_ARRAY;

  methods = ['stringToUtf8ByteArray', 'utf8ByteArrayToString'];

  methods.forEach((method) => {
    it('should define method ' + method, () => {
      expect(Crypt[method]).toBeDefined();
    });
  });

  it('should handle char codes > 255', () => {
    expect(Crypt.stringToByteArray('\u0500')).toEqual([0, 5]);
  });

  UTF8_RANGES_BYTE_ARRAY = [
    0x00,
    0x7F,
    0xC2, 0x80,
    0xDF, 0xBF,
    0xE0, 0xA0, 0x80,
    0xEF, 0xBF, 0xBF
  ];

  tests = [{
    desc: 'ASCII',
    string: 'Hello, world',
    array: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]
  }, {
    desc: 'Latin',
    string: 'Sch\u00f6n',
    array: [83, 99, 104, 195, 182, 110]
  }, {
    desc: 'UTF-8 Char Range Limits',
    string: '\u0000\u007F\u0080\u07FF\u0800\uFFFF',
    array: UTF8_RANGES_BYTE_ARRAY
  }];

  tests.forEach((test) => {
    it('should convert ' + test.desc + ' string to utf8 byte array', () => {
      expect(Crypt.stringToUtf8ByteArray(test.string)).toEqual(test.array);
    });
    it('should convert utf8 byte array to ' + test.desc + ' string', () => {
      expect(Crypt.utf8ByteArrayToString(test.array)).toEqual(test.string);
    });
    if (test.desc === 'ASCII') {
      it('should convert ' + test.desc + ' string to byte array', () => {
        expect(Crypt.stringToByteArray(test.string)).toEqual(test.array);
      });
      it('should convert byte array to ' + test.desc + ' string', () => {
        expect(Crypt.byteArrayToString(test.array)).toEqual(test.string);
      });
    }
  });
});

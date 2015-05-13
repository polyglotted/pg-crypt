import crypt from '../../src/pg-crypt';

describe('crypt', () => {
  let exported = ['byteArrayToHex', 'hexToByteArray', 'stringToByteArray', 'byteArrayToString',
    'stringToUtf8ByteArray', 'utf8ByteArrayToString', 'Md5', 'Base64', 'Sha1'];

  exported.forEach((exp) => {
    it('should export ' + exp, () => {
      expect(crypt[exp]).toBeDefined();
    });
  });
});

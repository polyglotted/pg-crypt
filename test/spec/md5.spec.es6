import Md5 from '../../src/md5';
import {byteArrayToHex} from '../../src/crypt';
import HashTest from '../helper/hash-tester';

describe('Md5', () => {
  it('should handle empty array', () => {
    let md5 = new Md5(),
        empty = new Md5().digest(),
        reset = new Md5();
    md5.reset();
    md5.update([]);
    expect(empty).toEqual(md5.digest());
  });

  let tests = [{
    desc: 'empty stream',
    md5: new Md5(),
    expected: 'd41d8cd98f00b204e9800998ecf8427e'
  }, {
    desc: 'simple stream',
    md5: (() => {
      let md5 = new Md5();
      md5.update([97]);
      return md5;
    }()),
    expected: '0cc175b9c0f1b6a831c399e269772661'
  }, {
    desc: 'simple stream with two updates',
    md5: (() => {
      let md5 = new Md5();
      md5.update([97]);
      md5.update('bc');
      return md5;
    }()),
    expected: '900150983cd24fb0d6963f7d28e17f72'
  }, {
    desc: 'RFC 1321 standard test',
    md5: (() => {
      let md5 = new Md5();
      md5.update('abcdefghijklmnopqrstuvwxyz');
      return md5;
    }()),
    expected: 'c3fcd3d76192e4007dfb496cca67e13b'
  }, {
    desc: 'RFC 1321 standard test with two updates',
    md5: (() => {
      let md5 = new Md5();
      md5.update('message ');
      md5.update('digest');
      return md5;
    }()),
    expected: 'f96b697d7cb7938d525a2f31aaf161d0'
  }, {
    desc: 'RFC 1321 standard test with three updates',
    md5: (() => {
      let md5 = new Md5();
      md5.update('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      md5.update('abcdefghijklmnopqrstuvwxyz');
      md5.update('0123456789');
      return md5;
    }()),
    expected: 'd174ab98d277d9f5a5611c2c9f419d9f'
  }];

  tests.forEach((test) => {
    it('should hash ' + test.desc, () => {
      expect(byteArrayToHex(test.md5.digest())).toEqual(test.expected);
    });
  });

  it('should update, digest and return a hash string', () => {
    expect(Md5.hash([97])).toEqual('0cc175b9c0f1b6a831c399e269772661');
  });

  // HashTest.runBasicTests(new Md5());
  // HashTest.runBlockTests(new Md5(), 64);
});

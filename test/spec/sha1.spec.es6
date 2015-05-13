import Sha1 from '../../src/sha1';
import {byteArrayToHex} from '../../src/crypt';
import HashTest from '../helper/hash-tester';

describe('Sha1', () => {
  let tests = [{
    desc: 'empty stream',
    sha1: new Sha1(),
    expected: 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
  }, {
    desc: 'test one-block message',
    sha1: (() => {
      let sha1 = new Sha1();
      sha1.update([0x61, 0x62, 0x63]);
      return sha1;
    }()),
    expected: 'a9993e364706816aba3e25717850c26c9cd0d89d'
  }, {
    desc: 'test multi-block message',
    sha1: (() => {
      let sha1 = new Sha1();
      sha1.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
      return sha1;
    }()),
    expected: '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
  }, {
    desc: 'test standard message',
    sha1: (() => {
      let sha1 = new Sha1();
      sha1.update('The quick brown fox jumps over the lazy dog');
      return sha1;
    }()),
    expected: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
  }];

  tests.forEach((test) => {
    it('should hash ' + test.desc, () => {
      expect(byteArrayToHex(test.sha1.digest())).toEqual(test.expected);
    });
  });

  // HashTest.runBasicTests(new Sha1());
  // HashTest.runBlockTests(new Sha1(), 64);
});

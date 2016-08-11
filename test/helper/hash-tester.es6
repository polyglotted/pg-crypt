import {stringToByteArray} from '../../src/crypt';

class HashTester {

  /**
   * Runs basic tests.
   *
   * @param {Hash} hash A hash instance.
   */
   static runBasicTests (hash) {
    let golden1, golden2, empty;

    // Compute first hash.
    hash.update([97, 158]);
    golden1 = hash.digest();

    // Compute second hash.
    hash.reset();
    hash.update('aB');
    golden2 = hash.digest();

    it('Two different inputs resulted in a hash collision', () => {
      expect(golden1).not.toEqual(golden2);
    });

    // Empty hash.
    hash.reset();
    empty = hash.digest();
    it('Empty hash collided with a non-trivial one', () => {
      expect(golden1).not.toEqual(empty);
      expect(golden2).not.toEqual(empty);
    });

    // Zero-length array update.
    hash.reset();
    hash.update([]);
    it('Updating with an empty array did not give an empty hash', () => {
      expect(empty).toEqual(hash.digest());
    });

    // // Zero-length string update.
    hash.reset();
    hash.update('');
    it('Updating with an empty string did not give an empty hash', () => {
      expect(empty).toEqual(hash.digest());
    });

    // Recompute the first hash.
    hash.reset();
    hash.update([97, 158]);
    it('The reset did not produce the initial state', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Check for a trivial collision.
    hash.reset();
    hash.update([158, 97]);
    it('Swapping bytes resulted in a hash collision', () => {
      expect(golden1).not.toEqual(hash.digest());
    });

    // Compare array and string input.
    hash.reset();
    hash.update([97, 66]);
    it('String and array inputs should give the same result', () => {
      expect(golden2).toEqual(hash.digest());
    });

    // Compute in parts.
    hash.reset();
    hash.update('a');
    hash.update([158]);
    it('Partial updates resulted in a different hash', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Test update with specified length.
    hash.reset();
    hash.update('aB', 0);
    hash.update([97, 158, 32], 2);
    it('Updating with an explicit buffer length did not work', () => {
      expect(golden1).toEqual(hash.digest());
    });
  }

  /**
   * Runs block tests.
   *
   * @param {Hash} hash A hash instance.
   * @param {number} blockBytes Size of the hash block.
   */
  static runBlockTests (hash, blockBytes) {
    // Compute a message which is 1 byte shorter than hash block size.
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        message = '',
        i, golden1, golden2;
    for (i = 0; i < blockBytes - 1; i++) {
      message += chars.charAt(i % chars.length);
    }

    // Compute golden hash for 1 block + 2 bytes.
    hash.update(message + '123');
    golden1 = hash.digest();

    // Compute golden hash for 2 blocks + 1 byte.
    hash.reset();
    hash.update(message + message + '123');
    golden2 = hash.digest();

    // Almost fill a block, then overflow.
    hash.reset();
    hash.update(message);
    hash.update('123');
    it('Almost fill a block, then overflow', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Fill a block.
    hash.reset();
    hash.update(message + '1');
    hash.update('23');
    it('Fill a block', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Overflow a block.
    hash.reset();
    hash.update(message + '12');
    hash.update('3');
    it('Overflow a block', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Test single overflow with an array.
    hash.reset();
    hash.update(stringToByteArray(message + '123'));
    it('Test single overflow with an array', () => {
      expect(golden1).toEqual(hash.digest());
    });

    // Almost fill a block, then overflow this and the next block.
    hash.reset();
    hash.update(message);
    hash.update(message + '123');
    it('Almost fill a block, then overflow this and the next block', () => {
      expect(golden2).toEqual(hash.digest());
    });

    // Fill two blocks.
    hash.reset();
    hash.update(message + message + '12');
    hash.update('3');
    it('Fill two blocks', () => {
      expect(golden2).toEqual(hash.digest());
    });

    // Test double overflow with an array.
    hash.reset();
    hash.update(stringToByteArray(message));
    hash.update(stringToByteArray(message + '123'));
    it('Test double overflow with an array', () => {
      expect(golden2).toEqual(hash.digest());
    });
  }
}

export default HashTester;

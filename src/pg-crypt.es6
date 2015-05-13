import {byteArrayToHex, hexToByteArray, stringToByteArray, byteArrayToString,
  stringToUtf8ByteArray, utf8ByteArrayToString} from './crypt';
import Md5 from './md5';
import Base64 from './base64';
import Sha1 from './sha1';

let md5 = Md5.hash;

export default {byteArrayToHex, hexToByteArray, stringToByteArray, byteArrayToString, stringToUtf8ByteArray,
  utf8ByteArrayToString, md5, Md5, Base64, Sha1};

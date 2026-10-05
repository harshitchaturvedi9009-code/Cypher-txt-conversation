const {
  caesar,
  vigenere,
  atbash,
  xorCipher,
  base64Cipher,
  aesGcmCipher
} = require('./cipherService');

console.log('--- Testing Cipher Algorithms in Backend ---');

// 1. Caesar
const cEnc = caesar('Attack at dawn. Meet at Gate 7.', 3, true);
const cDec = caesar(cEnc, 3, false);
console.log('Caesar Enc:', cEnc);
console.log('Caesar Dec:', cDec);
console.assert(cDec === 'Attack at dawn. Meet at Gate 7.', 'Caesar failed');

// 2. Vigenere
const vEnc = vigenere('Attack at dawn.', 'CYBER', true);
const vDec = vigenere(vEnc, 'CYBER', false);
console.log('Vigenere Enc:', vEnc);
console.log('Vigenere Dec:', vDec);
console.assert(vDec === 'Attack at dawn.', 'Vigenere failed');

// 3. Atbash
const aEnc = atbash('Hello World!');
const aDec = atbash(aEnc);
console.log('Atbash Enc:', aEnc);
console.log('Atbash Dec:', aDec);
console.assert(aDec === 'Hello World!', 'Atbash failed');

// 4. XOR
const xEnc = xorCipher('Attack at dawn.', 'CYBER', true);
const xDec = xorCipher(xEnc, 'CYBER', false);
console.log('XOR Enc (hex):', xEnc);
console.log('XOR Dec:', xDec);
console.assert(xDec === 'Attack at dawn.', 'XOR failed');

// 5. Base64
const bEnc = base64Cipher('Attack at dawn.', true);
const bDec = base64Cipher(bEnc, false);
console.log('Base64 Enc:', bEnc);
console.log('Base64 Dec:', bDec);
console.assert(bDec === 'Attack at dawn.', 'Base64 failed');

// 6. AES-256-GCM
const aesEnc = aesGcmCipher('Secret Message 123', 'MyPassPhrase', true);
const aesDec = aesGcmCipher(aesEnc, 'MyPassPhrase', false);
console.log('AES Enc (base64):', aesEnc);
console.log('AES Dec:', aesDec);
console.assert(aesDec === 'Secret Message 123', 'AES failed');

console.log('ALL TESTS PASSED SUCCESSFULLY!');

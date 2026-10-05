const crypto = require('crypto');

const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function shiftChar(c, n) {
  const up = c >= "A" && c <= "Z";
  const lo = c >= "a" && c <= "z";
  if (!up && !lo) return c;
  const base = up ? 65 : 97;
  return String.fromCharCode((c.charCodeAt(0) - base + n + 260) % 26 + base);
}

// 1. Caesar Cipher
function caesar(text, shift, encrypt = true) {
  const n = encrypt ? shift : -shift;
  return [...text].map(c => shiftChar(c, n)).join("");
}

// 2. Vigenere Cipher
function vigenere(text, key, encrypt = true) {
  const ks = [...(key || "").toUpperCase()].filter(c => A.includes(c));
  if (!ks.length) {
    throw new Error("Key me kam se kam ek letter (A-Z) chahiye.");
  }
  let i = 0;
  return [...text]
    .map(c => {
      if (/[a-z]/i.test(c)) {
        const kShift = ks[i++ % ks.length].charCodeAt(0) - 65;
        return shiftChar(c, encrypt ? kShift : -kShift);
      }
      return c;
    })
    .join("");
}

// 3. Atbash Cipher
function atbash(text) {
  return [...text]
    .map(c => {
      const up = c >= "A" && c <= "Z";
      const lo = c >= "a" && c <= "z";
      if (!up && !lo) return c;
      const b = up ? 65 : 97;
      return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b));
    })
    .join("");
}

// 4. XOR Cipher
function xorCipher(text, key, encrypt = true) {
  if (!key) throw new Error("Key khali hai.");
  const keyBytes = Buffer.from(key, 'utf8');
  if (keyBytes.length === 0) throw new Error("Key khali hai.");

  if (encrypt) {
    const textBytes = Buffer.from(text, 'utf8');
    const xorBytes = Buffer.alloc(textBytes.length);
    for (let i = 0; i < textBytes.length; i++) {
      xorBytes[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return [...xorBytes].map(b => b.toString(16).padStart(2, '0')).join(' ');
  } else {
    const hex = text.replace(/\s+/g, '');
    if (!/^([0-9a-f]{2})+$/i.test(hex)) {
      throw new Error("Decrypt ke liye valid hex ciphertext paste karo.");
    }
    const matches = hex.match(/../g) || [];
    const inBytes = Buffer.from(matches.map(x => parseInt(x, 16)));
    const outBytes = Buffer.alloc(inBytes.length);
    for (let i = 0; i < inBytes.length; i++) {
      outBytes[i] = inBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return outBytes.toString('utf8');
  }
}

// 5. Base64 Encoding
function base64Cipher(text, encrypt = true) {
  if (encrypt) {
    return Buffer.from(text, 'utf8').toString('base64');
  } else {
    try {
      return Buffer.from(text.trim(), 'base64').toString('utf8');
    } catch {
      throw new Error("Valid Base64 string required for decoding.");
    }
  }
}

// 6. AES-256-GCM (matching PBKDF2 100,000 iterations SHA-256, 16-byte salt, 12-byte IV, 16-byte auth tag)
function aesGcmCipher(text, password, encrypt = true) {
  if (!password) throw new Error("Password khali hai.");

  if (encrypt) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Browser WebCrypto appends auth tag directly to ciphertext: [salt(16), iv(12), encrypted + tag]
    const combined = Buffer.concat([salt, iv, encrypted, tag]);
    return combined.toString('base64');
  } else {
    try {
      const all = Buffer.from(text.trim(), 'base64');
      if (all.length < 16 + 12 + 16) {
        throw new Error("Invalid ciphertext length.");
      }
      const salt = all.subarray(0, 16);
      const iv = all.subarray(16, 28);
      // Web Crypto ciphertext has tag as the last 16 bytes
      const ciphertextAndTag = all.subarray(28);
      const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
      const encryptedData = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);

      const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
      return decrypted.toString('utf8');
    } catch {
      throw new Error("Decrypt fail: galat password ya ciphertext badla hua hai.");
    }
  }
}

module.exports = {
  caesar,
  vigenere,
  atbash,
  xorCipher,
  base64Cipher,
  aesGcmCipher
};

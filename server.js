const express = require('express');
const cors = require('cors');
const path = require('path');
const {
  caesar,
  vigenere,
  atbash,
  xorCipher,
  base64Cipher,
  aesGcmCipher
} = require('./cipherService');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static frontend files directly
app.use(express.static(__dirname));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Generic transform endpoint: POST /api/transform
app.post('/api/transform', (req, res) => {
  try {
    const { cipher, mode, text, shift, key } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const inputText = text ?? '';

    let result = '';

    switch (cipher?.toLowerCase()) {
      case 'caesar': {
        const s = parseInt(shift, 10);
        const shiftVal = isNaN(s) ? 3 : Math.min(25, Math.max(1, s));
        result = caesar(inputText, shiftVal, isEncrypt);
        break;
      }
      case 'vigenere': {
        result = vigenere(inputText, key || '', isEncrypt);
        break;
      }
      case 'atbash': {
        result = atbash(inputText);
        break;
      }
      case 'xor': {
        result = xorCipher(inputText, key || '', isEncrypt);
        break;
      }
      case 'base64': {
        result = base64Cipher(inputText, isEncrypt);
        break;
      }
      case 'aes': {
        result = aesGcmCipher(inputText, key || '', isEncrypt);
        break;
      }
      default:
        return res.status(400).json({ error: `Unknown cipher type: '${cipher}'` });
    }

    return res.json({
      success: true,
      cipher,
      mode: isEncrypt ? 'encrypt' : 'decrypt',
      result
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.message || 'Error executing cipher algorithm'
    });
  }
});

// Dedicated endpoints for each cipher
app.post('/api/caesar', (req, res) => {
  try {
    const { text = '', shift = 3, mode = 'encrypt' } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const s = parseInt(shift, 10);
    const shiftVal = isNaN(s) ? 3 : Math.min(25, Math.max(1, s));
    const result = caesar(text, shiftVal, isEncrypt);
    res.json({ success: true, mode: isEncrypt ? 'encrypt' : 'decrypt', result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/vigenere', (req, res) => {
  try {
    const { text = '', key = '', mode = 'encrypt' } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const result = vigenere(text, key, isEncrypt);
    res.json({ success: true, mode: isEncrypt ? 'encrypt' : 'decrypt', result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/atbash', (req, res) => {
  try {
    const { text = '' } = req.body;
    const result = atbash(text);
    res.json({ success: true, result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/xor', (req, res) => {
  try {
    const { text = '', key = '', mode = 'encrypt' } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const result = xorCipher(text, key, isEncrypt);
    res.json({ success: true, mode: isEncrypt ? 'encrypt' : 'decrypt', result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/base64', (req, res) => {
  try {
    const { text = '', mode = 'encrypt' } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const result = base64Cipher(text, isEncrypt);
    res.json({ success: true, mode: isEncrypt ? 'encrypt' : 'decrypt', result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/aes', (req, res) => {
  try {
    const { text = '', key = '', mode = 'encrypt' } = req.body;
    const isEncrypt = mode !== 'decrypt';
    const result = aesGcmCipher(text, key, isEncrypt);
    res.json({ success: true, mode: isEncrypt ? 'encrypt' : 'decrypt', result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Fallback route to serve The Cipher Codebook.html for root requests
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'The Cipher Codebook.html'));
});

app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});

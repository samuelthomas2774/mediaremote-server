import * as crypto from 'crypto';
import assert = require('assert');

import * as chacha20poly1305 from './chacha20poly1305';

// i'd really prefer for this to be a direct call to
// Sodium.crypto_aead_chacha20poly1305_decrypt()
// but unfortunately the way it constructs the message to
// calculate the HMAC is not compatible with homekit
// (long story short, it uses [ AAD, AAD.length, CipherText, CipherText.length ]
// whereas homekit expects [ AAD, CipherText, AAD.length, CipherText.length ]
export function verifyAndDecrypt(cipherText: Buffer, mac: Buffer, AAD: Buffer | null, nonce: Buffer, key: Buffer): Buffer | null {
    // const key: Buffer;
    // const nonce: Buffer;
    const ciphertext: Buffer = cipherText;
    // const mac: Buffer;
    const addData: Buffer | null | undefined = AAD;
    const plaintext: Buffer = Buffer.alloc(ciphertext.length);

    const ctx = new chacha20poly1305.Chacha20Ctx();
    chacha20poly1305.chacha20_keysetup(ctx, key);
    chacha20poly1305.chacha20_ivsetup(ctx, nonce);
    const poly1305key = Buffer.alloc(64);
    const zeros = Buffer.alloc(64);
    chacha20poly1305.chacha20_update(ctx, poly1305key, zeros, zeros.length);

    const poly1305_contxt = new chacha20poly1305.Poly1305Ctx();
    chacha20poly1305.poly1305_init(poly1305_contxt, poly1305key);

    let addDataLength = 0;
    if (addData !== undefined && addData !== null) {
        addDataLength = addData.length;
        chacha20poly1305.poly1305_update(poly1305_contxt, addData, addData.length);
        if ((addData.length % 16) != 0) {
            chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(addData.length%16)), 16-(addData.length%16));
        }
    }

    chacha20poly1305.poly1305_update(poly1305_contxt, ciphertext, ciphertext.length);
    if ((ciphertext.length % 16) != 0) {
        chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(ciphertext.length%16)), 16-(ciphertext.length%16));
    }

    const leAddDataLen = Buffer.alloc(8);
    writeUInt64LE(addDataLength, leAddDataLen, 0);
    chacha20poly1305.poly1305_update(poly1305_contxt, leAddDataLen, 8);

    const leTextDataLen = Buffer.alloc(8);
    writeUInt64LE(ciphertext.length, leTextDataLen, 0);
    chacha20poly1305.poly1305_update(poly1305_contxt, leTextDataLen, 8);

    const poly_out = [] as unknown as Uint8Array;
    chacha20poly1305.poly1305_finish(poly1305_contxt, poly_out);

    if (chacha20poly1305.poly1305_verify(mac, poly_out) != 1) {
        console.debug('Verify data failed');
        return null;
    } else {
        const written = chacha20poly1305.chacha20_update(ctx, plaintext, ciphertext, ciphertext.length);
        chacha20poly1305.chacha20_final(ctx, plaintext.slice(written, ciphertext.length));
        return plaintext;
    }
}

// See above about calling directly into libsodium.
export function encryptAndSeal(plainText: Buffer, AAD: Buffer | null, nonce: Buffer, key: Buffer): [Buffer, Buffer] {
    // const key: Buffer;
    // const nonce: Buffer;
    const plaintext: Buffer = plainText;
    const addData: Buffer | null | undefined = AAD;
    const ciphertext: Buffer = Buffer.alloc(plaintext.length);
    const mac: Buffer = Buffer.alloc(16);

    const ctx = new chacha20poly1305.Chacha20Ctx();
    chacha20poly1305.chacha20_keysetup(ctx, key);
    chacha20poly1305.chacha20_ivsetup(ctx, nonce);
    const poly1305key = Buffer.alloc(64);
    const zeros = Buffer.alloc(64);
    chacha20poly1305.chacha20_update(ctx,poly1305key,zeros,zeros.length);

    const written = chacha20poly1305.chacha20_update(ctx,ciphertext,plaintext,plaintext.length);
    chacha20poly1305.chacha20_final(ctx,ciphertext.slice(written,plaintext.length));

    const poly1305_contxt = new chacha20poly1305.Poly1305Ctx();
    chacha20poly1305.poly1305_init(poly1305_contxt, poly1305key);

    let addDataLength = 0;
    if (addData != undefined) {
        addDataLength = addData.length;
        chacha20poly1305.poly1305_update(poly1305_contxt, addData, addData.length);
        if ((addData.length % 16) != 0) {
        chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(addData.length%16)), 16-(addData.length%16));
        }
    }

    chacha20poly1305.poly1305_update(poly1305_contxt, ciphertext, ciphertext.length);
    if ((ciphertext.length % 16) != 0) {
        chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(ciphertext.length%16)), 16-(ciphertext.length%16));
    }

    const leAddDataLen = Buffer.alloc(8);
    writeUInt64LE(addDataLength, leAddDataLen, 0);
    chacha20poly1305.poly1305_update(poly1305_contxt, leAddDataLen, 8);

    const leTextDataLen = Buffer.alloc(8);
    writeUInt64LE(ciphertext.length, leTextDataLen, 0);
    chacha20poly1305.poly1305_update(poly1305_contxt, leTextDataLen, 8);

    chacha20poly1305.poly1305_finish(poly1305_contxt, mac);

    return [ciphertext, mac];
}

const MAX_UINT32 = 0x00000000FFFFFFFF;
const MAX_INT53 =  0x001FFFFFFFFFFFFF;

function uintHighLow(number: number): [number, number] {
    assert(number > -1 && number <= MAX_INT53, 'number out of range');
    assert(Math.floor(number) === number, 'number must be an integer');
    let high = 0;
    const signbit = number & 0xFFFFFFFF;
    const low = signbit < 0 ? (number & 0x7FFFFFFF) + 0x80000000 : signbit;
    if (number > MAX_UINT32) {
        high = (number - low) / (MAX_UINT32 + 1);
    }
    return [high, low];
}

export function writeUInt64LE (number: number, buffer: Buffer, offset: number = 0) {
    const hl = uintHighLow(number)
    buffer.writeUInt32LE(hl[1], offset)
    buffer.writeUInt32LE(hl[0], offset + 4)
}

export function HKDF(hashAlg: string, salt: Buffer, ikm: Buffer, info: Buffer, size: number): Buffer {
    // create the hash alg to see if it exists and get its length
    const hash = crypto.createHash(hashAlg);
    const hashLength = hash.digest().length;

    // now we compute the PRK
    const hmac = crypto.createHmac(hashAlg, salt);
    hmac.update(ikm);
    const prk = hmac.digest();

    let prev = Buffer.alloc(0);
    const buffers: Buffer[] = [];
    const num_blocks = Math.ceil(size / hashLength);
    info = Buffer.from(info);

    for (let i = 0; i < num_blocks; i++) {
        const hmac = crypto.createHmac(hashAlg, prk);

        const input = Buffer.concat([
            prev,
            info,
            Buffer.from(String.fromCharCode(i + 1))
        ]);
        hmac.update(input);
        prev = hmac.digest();
        buffers.push(prev);
    }

    const output = Buffer.concat(buffers, size);
    return output.slice(0, size);
}

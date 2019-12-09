/**
 * Type Length Value encoding/decoding, used by HAP as a wire format.
 * https://en.wikipedia.org/wiki/Type-length-value
 *
 * Originally based on code from github:KhaosT/HAP-NodeJS@0c8fd88 used
 * used per the terms of the Apache Software License v2.
 *
 * Original code copyright Khaos Tian <khaos.tian@gmail.com>
 *
 * Modifications copyright Zach Bean <zb@forty2.com>
 *  * Reformatted for ES6-style module
 *  * Rewrote encode() to be non-recursive; also simplified the logic
 *  * Rewrote decode()
 */

export enum Type {
    METHOD = 0x00,
    USERNAME = 0x01,
    /** Salt is 16 bytes long */
    SALT = 0x02,

    /** Could be either the SRP client public key (384 bytes) or the ED25519 public key (32 bytes), depending on context */
    PUBLIC_KEY = 0x03,
    /** 64 bytes */
    PROOF = 0x04,
    ENCRYPTED_DATA = 0x05,
    SEQUENCE = 0x06,
    ERROR_CODE = 0x07,
    BACKOFF = 0x08,
    /** 64 bytes */
    SIGNATURE = 0x0a,

    MFI_CERTIFICATE = 0x09,
    MFI_SIGNATURE = 0x0a,
}

export function encode(type: Type, data: Buffer | number | string, ...args: any[]): Buffer
export function encode(data: Record<Type | number, Buffer | number | string | undefined>): Buffer
export function encode(type: Type | Record<any, any>, data?: Buffer | number | string, ...args: any[]): Buffer {
    if (!data || typeof type === 'object') {
        const args = [];

        for (const [k, v] of Object.entries(type)) {
            args.push(k, v);
        }

        // @ts-ignore
        return args.length ? encode(...args) : Buffer.alloc(0);
    }

    let encodedTLVBuffer = Buffer.alloc(0);

    // coerce data to Buffer if needed
    if (typeof data === 'number')
        data = Buffer.from([data]);
    else if (typeof data === 'string')
        data = Buffer.from(data);

    if (data.length <= 255) {
        encodedTLVBuffer = Buffer.concat([Buffer.from([type, data.length]), data]);
    } else {
        let leftLength = data.length;
        let tempBuffer = Buffer.alloc(0);
        let currentStart = 0;

        for (; leftLength > 0;) {
            if (leftLength >= 255) {
                tempBuffer = Buffer.concat([
                    tempBuffer,
                    Buffer.from([type, 0xFF]),
                    data.slice(currentStart, currentStart + 255),
                ]);
                leftLength -= 255;
                currentStart = currentStart + 255;
            } else {
                tempBuffer = Buffer.concat([
                    tempBuffer,
                    Buffer.from([type, leftLength]),
                    data.slice(currentStart, currentStart + leftLength),
                ]);
                leftLength -= leftLength;
            }
        }

        encodedTLVBuffer = tempBuffer;
    }

    // do we have more to encode?
    if (arguments.length > 2) {
        // @ts-ignore
        const remainingTLVBuffer = encode(...args);

        // append the remaining encoded arguments directly to the buffer
        encodedTLVBuffer = Buffer.concat([encodedTLVBuffer, remainingTLVBuffer]);
    }

    return encodedTLVBuffer;
}

export function decode(data: Buffer) {
    const objects = {} as Record<Type, Buffer | undefined>;

    let leftLength = data.length;
    let currentIndex = 0;

    for (; leftLength > 0;) {
        const type = data[currentIndex] as Type;
        const length = data[currentIndex + 1];
        currentIndex += 2;
        leftLength -= 2;

        const newData = data.slice(currentIndex, currentIndex + length);

        if (objects[type]) {
            objects[type] = Buffer.concat([objects[type]!, newData]);
        } else {
            objects[type] = newData;
        }

        currentIndex += length;
        leftLength -= length;
    }

    return objects;
}

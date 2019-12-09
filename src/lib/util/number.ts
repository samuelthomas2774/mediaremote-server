import * as assert from 'assert';

/*
 * Originally based on code from github:KhaosT/HAP-NodeJS@0c8fd88 used
 * used per the terms of the Apache Software License v2.
 *
 * Original code copyright Khaos Tian <khaos.tian@gmail.com>
 *
 * Modifications copyright Zach Bean <zb@forty2.com>
 *  * Reformatted for ES6-style module
 *  * renamed *UInt64* to *UInt53* to be more clear about range
 *  * renamed uintHighLow to be more clear about what it does
 *  * Refactored to return a buffer rather write into a passed-in buffer
 */

export function splitUInt53(number: number): [number, number] {
    const MAX_UINT32 = 0x00000000FFFFFFFF;
    const MAX_INT53 =  0x001FFFFFFFFFFFFF;

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

export function UInt53toBufferLE(number: number): Buffer {
    const [high, low] = splitUInt53(number)

    const buf = Buffer.alloc(8);
    buf.writeUInt32LE(low, 0);
    buf.writeUInt32LE(high, 4);

    return buf;
}

export function UInt16toBufferBE(number: number): Buffer {
    const buf = Buffer.alloc(2);
    buf.writeUInt16BE(number, 0);

    return buf;
}

import {Session, Encryption} from './server';
import Message from './message';
import * as encryption from './util/encryption';
import * as tlv from './util/tlv';
const Type = tlv.Type;

import * as crypto from 'crypto';
import * as util from 'util';
const randomBytes = util.promisify(crypto.randomBytes);

import * as srp from 'fast-srp-hap';
import * as tweetnacl from 'tweetnacl';

export default class PairingSession {
    nextSetupSequenceNumber: PairSetupState.M1 | PairSetupState.M3 | PairSetupState.M5 = PairSetupState.M1;
    nextVerifySequenceNumber: PairVerifyState.M1 | PairVerifyState.M3 = PairVerifyState.M1;
    srps: srp.Server | undefined = undefined;
    verify_data: {
        privatekey: Buffer;
        publickey: Buffer;
        sharedsecret: Buffer;
        encryptionkey: Buffer;
        clientpublickey: Buffer;
    } | undefined = undefined;

    constructor(readonly session: Session) {
        //
    }

    handle(message: Message) {
        const state: PairState = message.payload.state;

        if (state === PairState.PAIR_SETUP) return this.handleSetup(message);
        if (state === PairState.PAIR_VERIFY) return this.handleVerify(message);

        console.debug('DEBUG: Recieved invalid pairing message', message);
        this.session.connection.socket.end();
    }

    handleSetup(message: Message) {
        const data = tlv.decode(message.payload.pairingData);
        const state: PairSetupState = data[Type.SEQUENCE]![0];

        console.log('DEBUG: Received pair setup M%d message', state, data);

        if (state === this.nextSetupSequenceNumber || state === PairSetupState.M1) {
            this['handleSetupM' + state as 'handleSetupM1' | 'handleSetupM3' | 'handleSetupM5'](data);
        } else {
            console.debug('DEBUG: Received out of order pair setup message', data);
            this.session.connection.socket.end();
        }
    }

    async handleSetupM1(data: Record<tlv.Type, Buffer | undefined>) {
        const method: PairSetupMethod | undefined = data[Type.METHOD] && data[Type.METHOD]![0];

        if (method !== PairSetupMethod.PAIR_SETUP) {
            console.debug('DEBUG: Received invalid M1 data - unknown pair setup method', data);
            return this.session.connection.socket.end();
        }

        return this.handleSetupM2();
    }

    async handleSetupM2() {
        const code = await this.generateSetupCode();
        this.session.connection.server.mediaremote.emit('pair-setup', code, this.session);

        const salt = Buffer.alloc(16);
        const identity = Buffer.from('Pair-Setup');
        const password = Buffer.from(code);
        const privatekey = Buffer.alloc(384);

        this.srps = new srp.Server(srp.params[3072], salt, identity, password, privatekey);

        const publickey = this.srps.computeB();

        console.log('Private key %d', privatekey.length, privatekey);
        console.log('Public key %d', publickey.length, publickey);

        const response = {
            pairingData: tlv.encode({
                [Type.SALT]: salt,
                [Type.PUBLIC_KEY]: publickey,
                [Type.SEQUENCE]: PairSetupState.M2,
            }),
            status: 0,
        };
        this.session.sendMessage('CryptoPairingMessage', 'CryptoPairingMessage', response);
        this.nextSetupSequenceNumber = PairSetupState.M3;
    }

    async generateSetupCode() {
        const bytes = await randomBytes(2);

        return [...bytes].map(n => `00${n}`).map(n => n.substr(n.length - 2, 2)).join('');
    }

    handleSetupM3(data: Record<tlv.Type, Buffer | undefined>) {
        const publickey = data[Type.PUBLIC_KEY];
        const proof = data[Type.PROOF];

        if (!publickey || publickey.length !== 384) {
            console.debug('DEBUG: Received invalid M3 data - public key (A) isn\'t 384 bytes', data);
            return this.session.connection.socket.end();
        }
        if (!proof || proof.length !== 64) {
            console.debug('DEBUG: Received invalid M3 data - proof (M1) isn\'t 64 bytes', data);
            return this.session.connection.socket.end();
        }

        this.srps!.setA(publickey);

        try {
            this.srps!.checkM1(proof);
        } catch (err) {
            console.debug('DEBUG: Received invalid M3 data - proof (M1) isn\'t valid');
            console.debug('This probably means the client provided the wrong setup code', data);
            return this.session.connection.socket.end();
        }
        
        return this.handleSetupM4();
    }

    handleSetupM4() {
        const serverproof = this.srps!.computeM2();

        const response = {
            pairingData: tlv.encode({
                [Type.PROOF]: serverproof,
                [Type.SEQUENCE]: PairSetupState.M4,
            }),
            status: 0,
        };
        this.session.sendMessage('CryptoPairingMessage', 'CryptoPairingMessage', response);
        this.nextSetupSequenceNumber = PairSetupState.M5;
    }

    handleSetupM5(data: Record<tlv.Type, Buffer | undefined>) {
        const encrypted = data[Type.ENCRYPTED_DATA];

        if (!encrypted || encrypted.length !== 154) {
            console.debug('DEBUG: Received invalid M5 data - encrypted isn\'t 154 bytes', data);
            return this.session.connection.socket.end();
        }

        const sharedsecret = this.srps!.computeK();

        const encryptionkey = encryption.HKDF(
            'sha512', Buffer.from('Pair-Setup-Encrypt-Salt'), sharedsecret, Buffer.from('Pair-Setup-Encrypt-Info'), 32
        );

        const cipherText = encrypted.slice(0, -16);
        const hmac = encrypted.slice(-16);
        const decrypted = encryption.verifyAndDecrypt(cipherText, hmac, null, Buffer.from('PS-Msg05'), encryptionkey);

        if (!decrypted) {
            console.debug('DEBUG: Received invalid M5 data - failed to decrypt data', data);
            return this.session.connection.socket.end();
        }

        const decrypteddata: Record<tlv.Type, Buffer | undefined> = tlv.decode(decrypted);

        const username = decrypteddata[Type.USERNAME];
        const publickey = decrypteddata[Type.PUBLIC_KEY];
        const signature = decrypteddata[Type.SIGNATURE];

        if (!username) {
            console.debug('DEBUG: Received invalid M5 data - no username in decrypted data', data);
            return this.session.connection.socket.end();
        }
        if (!publickey || publickey.length !== 32) {
            console.debug('DEBUG: Received invalid M5 data - decrypted public key not 32 bytes', data);
            return this.session.connection.socket.end();
        }
        if (!signature || signature.length !== 64) {
            console.debug('DEBUG: Received invalid M5 data - decrypted signature not 64 bytes', data);
            return this.session.connection.socket.end();
        }

        console.log('Decrypted data', decrypted, decrypteddata);
        console.log('Username', username.toString());

        // TODO: verify device signature

        return this.handleSetupM6(sharedsecret, encryptionkey, username.toString(), publickey);
    }

    handleSetupM6(sharedsecret: Buffer, encryptionkey: Buffer, username: string, clientpublickey: Buffer) {
        // const keypair = tweetnacl.sign.keyPair();
        const keypair = {
            publicKey: Buffer.from([
                 73, 187, 59, 237, 204, 118, 119, 252,
                 48, 249, 42, 175,   1, 254, 101,  64,
                 31, 155, 72, 191, 234, 155, 198, 179,
                113, 170, 75,  90, 140,  88, 221, 233
            ]),
            secretKey: Buffer.from([
                255,  34,  30, 242,  70, 137,  20, 160,  57,  53, 227,
                114,  72, 104, 112,  45, 200, 191,  57, 241, 235,  79,
                238,  47, 201, 213,  55,  64,  96, 217, 141,  45,  73,
                187,  59, 237, 204, 118, 119, 252,  48, 249,  42, 175,
                  1, 254, 101,  64,  31, 155,  72, 191, 234, 155, 198,
                179, 113, 170,  75,  90, 140,  88, 221, 233
            ]),
        };
        // const privatekey = Buffer.from(keypair.secretKey);
        // const publickey = Buffer.from(keypair.publicKey);
        const privatekey = keypair.secretKey;
        const publickey = keypair.publicKey;

        console.debug('DEBUG: Server keypair', keypair);

        const serverhash = encryption.HKDF(
            'sha512', Buffer.from('Pair-Setup-Accessory-Sign-Salt'), sharedsecret,
            Buffer.from('Pair-Setup-Accessory-Sign-Info'), 32
        );
        const serverinfo = Buffer.concat([
            serverhash, Buffer.from(this.session.connection.server.mediaremote.uuid), publickey,
        ]);
        const serversignature = tweetnacl.sign.detached(serverinfo, privatekey);

        const data = tlv.encode({
            [Type.USERNAME]: Buffer.from(this.session.connection.server.mediaremote.uuid),
            [Type.PUBLIC_KEY]: publickey,
            [Type.SIGNATURE]: Buffer.from(serversignature),
        });
        const encrypteddata = Buffer.concat(
            encryption.encryptAndSeal(data, null, Buffer.from('PS-Msg06'), encryptionkey));
        const response = {
            pairingData: tlv.encode({
                [Type.ENCRYPTED_DATA]: encrypteddata,
                [Type.SEQUENCE]: PairSetupState.M6,
            }),
            status: 0,
        };
        this.session.sendMessage('CryptoPairingMessage', 'CryptoPairingMessage', response);
        this.nextSetupSequenceNumber = PairSetupState.M1;

        console.log('Client paired', {
            username,
            clientpublickey,
            from: [this.session.connection.address, this.session.connection.port],
            created_at: new Date(Date.now()),
        });
    }

    handleVerify(message: Message) {
        const data = tlv.decode(message.payload.pairingData);
        const state: PairVerifyState = data[Type.SEQUENCE]![0];

        console.log('DEBUG: Received M%d pair verify message', state, data);

        if (state === this.nextVerifySequenceNumber || state === PairVerifyState.M1) {
            this['handleVerifyM' + state as 'handleVerifyM1' | 'handleVerifyM3'](data);
        } else {
            console.debug('DEBUG: Received out of order pair setup message', data);
            this.session.connection.socket.end();
        }
    }

    handleVerifyM1(data: Record<tlv.Type, Buffer | undefined>) {
        const clientpublickey = data[Type.PUBLIC_KEY];

        if (!clientpublickey || clientpublickey.length !== 32) {
            console.debug('DEBUG: Received invalid M1 data - public key isn\'t 32 bytes', data);
            return this.session.connection.socket.end();
        }

        // Generate new encryption keys for this session
        const keypair = tweetnacl.box.keyPair();
        const privatekey = Buffer.from(keypair.secretKey);
        const publickey = Buffer.from(keypair.publicKey);
        const sharedsecret = Buffer.from(tweetnacl.scalarMult(privatekey, clientpublickey));

        const encryptionkey = encryption.HKDF('sha512', Buffer.from('Pair-Verify-Encrypt-Salt'), sharedsecret,
            Buffer.from('Pair-Verify-Encrypt-Info'), 32);

        this.verify_data = {privatekey, publickey, sharedsecret, encryptionkey, clientpublickey};
        console.debug('DEBUG: verify data', this.verify_data);

        return this.handleVerifyM2();
    }

    async handleVerifyM2() {
        const {privatekey, publickey, encryptionkey, clientpublickey} = this.verify_data!;
        const username = Buffer.from(this.session.connection.server.mediaremote.uuid);
        const keypair = await this.getKeypair();

        const material = Buffer.concat([publickey, username, clientpublickey]);
        const serversignature = Buffer.from(tweetnacl.sign.detached(material, keypair.privatekey));

        const data = tlv.encode({
            [Type.USERNAME]: username,
            [Type.SIGNATURE]: serversignature,
        });
        const encrypteddata = Buffer.concat(
            encryption.encryptAndSeal(data, null, Buffer.from('PV-Msg02'), encryptionkey));

        const response = {
            pairingData: tlv.encode({
                [Type.PUBLIC_KEY]: publickey,
                [Type.ENCRYPTED_DATA]: encrypteddata,
                [Type.SEQUENCE]: PairVerifyState.M2,
            }),
            status: 0,
        };
        this.session.sendMessage('CryptoPairingMessage', 'CryptoPairingMessage', response);
        this.nextVerifySequenceNumber = PairVerifyState.M3;
    }

    async handleVerifyM3(data: Record<tlv.Type, Buffer | undefined>) {
        const encrypted = data[Type.ENCRYPTED_DATA];

        if (!encrypted || encrypted.length !== 120) {
            console.debug('DEBUG: Received invalid M3 data - encrypted isn\'t 120 bytes', data);
            return this.session.connection.socket.end();
        }

        const {encryptionkey} = this.verify_data!;
        const keypair = await this.getKeypair();

        const cipherText = encrypted.slice(0, -16);
        const hmac = encrypted.slice(-16);
        const decrypted = encryption.verifyAndDecrypt(cipherText, hmac, null, Buffer.from('PV-Msg03'), encryptionkey);

        if (!decrypted) {
            console.debug('DEBUG: Received invalid M3 data - failed to decrypt data', data);
            return this.session.connection.socket.end();
        }

        const decrypteddata: Record<tlv.Type, Buffer | undefined> = tlv.decode(decrypted);

        const username = decrypteddata[Type.USERNAME];
        const signature = decrypteddata[Type.SIGNATURE];

        if (!username) {
            console.debug('DEBUG: Received invalid M3 data - no username in decrypted data', data);
            return this.session.connection.socket.end();
        }
        if (!signature || signature.length !== 64) {
            console.debug('DEBUG: Received invalid M3 data - decrypted signature not 64 bytes', data);
            return this.session.connection.socket.end();
        }

        console.log('Decrypted data', decrypted, decrypteddata);
        console.log('Username', username.toString());

        const pairing = await this.getPairingIdentity(username.toString()).catch(err => {
            console.error('Error getting pairing identity');
        });
        if (!pairing) {
            console.debug('DEBUG: No client with the username %s', username.toString(), data);
            return this.session.connection.socket.end();
        }

        // TODO: verify device signature

        return this.handleVerifyM4(pairing);
    }

    async getPairingIdentity(username: string): Promise<PairingIdentity | null> {
        // return this.session.connection.server.mediaremote.getPairingIdentity(username, this.session);

        return null;
    }

    async handleVerifyM4(pairing: PairingIdentity) {
        const response = {
            pairingData: tlv.encode({
                [Type.SEQUENCE]: PairVerifyState.M4,
            }),
            status: 0,
        };
        await this.session.sendMessage('CryptoPairingMessage', 'CryptoPairingMessage', response);
        this.nextVerifySequenceNumber = PairVerifyState.M1;

        const {sharedsecret} = this.verify_data!;

        // Because we're a server we need to swap the info data -
        // MediaRemote-Write-Encryption-Key is the decryption key and
        // MediaRemote-Read-Encryption-Key is the encryption key
        const readKey = encryption.HKDF('sha512', Buffer.from('MediaRemote-Salt'), sharedsecret,
            Buffer.from('MediaRemote-Write-Encryption-Key'), 32);
        const writeKey = encryption.HKDF('sha512', Buffer.from('MediaRemote-Salt'), sharedsecret,
            Buffer.from('MediaRemote-Read-Encryption-Key'), 32);

        // Enable encryption
        this.session.encryption = new Encryption(readKey, writeKey);
    }

    async getKeypair(): Promise<{publickey: Buffer; privatekey: Buffer;}> {
        return {
            publickey: Buffer.from([
                 73, 187, 59, 237, 204, 118, 119, 252,
                 48, 249, 42, 175,   1, 254, 101,  64,
                 31, 155, 72, 191, 234, 155, 198, 179,
                113, 170, 75,  90, 140,  88, 221, 233
            ]),
            privatekey: Buffer.from([
                255,  34,  30, 242,  70, 137,  20, 160,  57,  53, 227,
                114,  72, 104, 112,  45, 200, 191,  57, 241, 235,  79,
                238,  47, 201, 213,  55,  64,  96, 217, 141,  45,  73,
                187,  59, 237, 204, 118, 119, 252,  48, 249,  42, 175,
                  1, 254, 101,  64,  31, 155,  72, 191, 234, 155, 198,
                179, 113, 170,  75,  90, 140,  88, 221, 233
            ]),
        };
    }
}

enum PairState {
    PAIR_SETUP = 2,
    PAIR_VERIFY = 3,
}

enum PairSetupState {
    M1 = 0x01,
    M2 = 0x02,
    M3 = 0x03,
    M4 = 0x04,
    M5 = 0x05,
    M6 = 0x06,
}

enum PairSetupMethod {
    PAIR_SETUP = 0,
}

enum PairVerifyState {
    M1 = 0x01,
    M2 = 0x02,
    M3 = 0x03,
    M4 = 0x04,
}

export interface PairingIdentity {
    username: string;
    publickey: Buffer;
}

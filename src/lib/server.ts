import TypedEventEmitter from './events';
import * as net from 'net';
import * as util from 'util';
import {Message as ProtoMessage} from 'protobufjs';
import * as varint from 'varint';
import snake = require('snake-case');
// @ts-ignore
import camelcase = require('camelcase');

import {load} from '../protos';

import MediaRemoteServer from './mediaremote';
import * as encryption from './util/encryption';
import * as number from './util/number';
import Message from './message';
import PairingSession from './pairing';
import VoiceInputDevice from './voice-input-device';
import TouchInputDevice from './touch-input-device';

type ServerEvents = {
    'debug': [/** data */ string];

    'listening': [];
    'close': [];
    'connection': [/** connection */ Connection];
    'message': [/** message */ Message, /** session */ Session];
};

export default class Server extends TypedEventEmitter<Server, ServerEvents> {
    private readonly _connectionListener = this.connectionListener.bind(this);

    readonly socket = net.createServer(this._connectionListener);
    // @ts-ignore
    readonly address: string = undefined;
    // @ts-ignore
    readonly port: number = undefined;
    readonly connections: Connection[] = [];

    constructor(public readonly mediaremote: MediaRemoteServer) {
        super();

        this.socket.once('listening', () => {
            const address = this.socket.address() as net.AddressInfo;
            // @ts-ignore
            this.address = address.address;
            // @ts-ignore
            this.port = address.port;
            this.emit('listening');
        });
        this.socket.once('close', () => this.emit('close'));
    }

    private connectionListener(socket: net.Socket) {
        const connection = new Connection(this, socket);
        this.connections.push(connection);
        this.emit('connection', connection);

        connection.on('debug', data => this.emit('debug', data));
        connection.on('message', message => this.emit('message', message, connection.session));
        connection.once('close', () => this.connections.splice(this.connections.indexOf(connection), 1));

        connection.emit('debug', `DEBUG: New connection from [${connection.address}]:${connection.port}`);
    }
}

type ConnectionEvents = {
    'debug': [/** data */ string];
    'error': [/** error */ Error];
    'close': [];
    'message': [/** message */ Message];
};

export class Connection extends TypedEventEmitter<Connection, ConnectionEvents> {
    readonly server: Server;
    readonly socket: net.Socket;
    readonly connected = true;
    readonly address: string;
    readonly port: number;
    readonly session = new Session(this);
    private buffer = Buffer.alloc(0);

    constructor(server: Server, socket: net.Socket) {
        super();
        this.server = server;
        this.socket = socket;

        if (socket.destroyed) throw new Error('Invalid socket');

        this.address = socket.remoteAddress!;
        this.port = socket.remotePort!;

        this.socket.on('data', async data => {
            try {
                this.buffer = Buffer.concat([this.buffer, data]);
                const length = varint.decode(this.buffer);
                let messageBytes = this.buffer.slice(varint.decode.bytes, length + varint.decode.bytes);

                if (messageBytes.length < length) {
                    this.emit('debug', 'Message length mismatch');
                    return;
                }

                this.buffer = this.buffer.slice(length + varint.decode.bytes);

                this.emit('debug', 'DEBUG: <<<< Received Data=' + messageBytes.toString('hex'));

                if (this.session.encryption) {
                    messageBytes = this.session.encryption.decrypt(messageBytes)!;
                    if (!messageBytes) {
                        this.emit('debug', 'ERROR: Failed to decrypt data - closing connection');
                        return this.session.connection.socket.end();
                    }
                    this.emit('debug', 'DEBUG: Decrypted Data=' + messageBytes.toString('hex'));
                }

                try {
                    const protoMessage = await this.decodeMessage(messageBytes);
                    const message = new Message(protoMessage);
                    this.emit('message', message);
                } catch (error) {
                    this.emit('error', error);
                }
            } catch(error) {
                this.emit('error', error);
            }
        });

        this.socket.on('close', had_error => {
            // @ts-ignore
            this.connected = false;

            this.emit('close');

            this.emit('debug', 'DEBUG: Connection closed');
        });
    }

    private async decodeMessage(data: Buffer) {
        const preroot = await load('ProtocolMessage');
        const preProtocolMessage = preroot.lookupType('ProtocolMessage');
        const preMessage = preProtocolMessage.decode(data);
        const type = preMessage.toJSON().type;
        if (type == null) return preMessage;
        const name = type[0].toUpperCase() + camelcase(type).substring(1);
  
        const root = await load(name);
        const ProtocolMessage = root.lookupType('ProtocolMessage');
        const message = ProtocolMessage.decode(data);
        this.emit('debug', util.formatWithOptions({colors: true},
            'DEBUG: <<<< Received Protobuf=%O', message.toJSON()));
        return message;
    }

    private sendProtocolMessage(message: ProtoMessage<{}>, name: string, type: number) {
        const ProtocolMessage: any = message.$type;

        const data = ProtocolMessage.encode(message).finish();
        this.emit('debug', 'DEBUG: >>>> Send Data=' + data.toString('hex'));

        if (this.session.encryption) {
            const encrypted = this.session.encryption.encrypt(data);
            this.emit('debug', 'DEBUG: >>>> Send Encrypted Data=' + encrypted.toString('hex'));
            this.emit('debug', util.formatWithOptions({colors: true},
                'DEBUG: >>>> Send Protobuf=%O', message.toJSON()));
            const messageLength = Buffer.from(varint.encode(encrypted.length));
            const bytes = Buffer.concat([messageLength, encrypted]);
            this.socket.write(bytes);
        } else {
            this.emit('debug', util.formatWithOptions({colors: true},
                'DEBUG: >>>> Send Protobuf=%O', message.toJSON()));
            const messageLength = Buffer.from(varint.encode(data.length));
            const bytes = Buffer.concat([messageLength, data]);
            this.socket.write(bytes);
        }
    }

    send(message: ProtoMessage<{}>, priority: number, identifier?: string) {
        // @ts-ignore
        const ProtocolMessage = message.$type.parent!.ProtocolMessage;
        const types = ProtocolMessage.lookupEnum('Type');
        const name = message.$type.name;
        const typeName = snake.snakeCase(name).toUpperCase();
        const type = types.values[typeName];
        const outerMessage = ProtocolMessage.create({
            identifier,
            priority,
            type,
        });
        if (Object.keys(message.toJSON()).length > 0) {
            const field = outerMessage.$type.fieldsArray.filter((f: any) => f.type == message.$type.name)[0];
            outerMessage[field.name] = message;
        }
    
        return this.sendProtocolMessage(outerMessage, name, type);
    }

    /**
     * Send a Protobuf message to the AppleTV. This is for advanced usage only.
     * @param definitionFilename  The Protobuf filename of the message type.
     * @param messageType  The name of the message.
     * @param body  The message body
     * @returns A promise that resolves to the response from the AppleTV.
     */
    async sendMessage(file: string, messageType: string, body: {}, priority: number = 0, identifier?: string) {
        const root = await load(file);
        const type = root.lookupType(messageType);
        const message = type.create(body);
        return this.send(message, priority, identifier);
    }
}

export class Session {
    readonly connection: Connection;
    encryption?: Encryption = undefined;
    pairing?: PairingSession = undefined;

    readonly voiceInputDevices: VoiceInputDevice[] = [];
    readonly touchInputDevices: TouchInputDevice[] = [];

    nextDeviceId = 0;

    constructor(connection: Connection) {
        this.connection = connection;
    }

    sendMessage(file: string, type: string, body: object, priority = 0, identifier?: string) {
        return this.connection.sendMessage(file, type, body, priority, identifier);
    }

    setClientUpdatesConfig(clientUpdatesConfig: {
        artworkUpdates: boolean;
        nowPlayingUpdates: boolean;
        volumeUpdates: boolean;
        keyboardUpdates: boolean;
    }) {
        const mr = this.connection.server.mediaremote;

        mr.removeListener('artwork-update', this._handleArtworkUpdate);
        if (clientUpdatesConfig.artworkUpdates) mr.on('artwork-update', this._handleArtworkUpdate);
        mr.removeListener('now-playing-update', this._handleNowPlayingUpdate);
        if (clientUpdatesConfig.nowPlayingUpdates) mr.on('now-playing-update', this._handleNowPlayingUpdate);
        mr.removeListener('volume-update', this._handleVolumeUpdate);
        if (clientUpdatesConfig.volumeUpdates) mr.on('volume-update', this._handleVolumeUpdate);
        mr.removeListener('keyboard-update', this._handleKeyboardUpdate);
        if (clientUpdatesConfig.keyboardUpdates) mr.on('keyboard-update', this._handleKeyboardUpdate);
    }

    private _handleArtworkUpdate = () => {}
    private _handleNowPlayingUpdate = () => {}
    private _handleVolumeUpdate = () => {}
    private _handleKeyboardUpdate = () => {}
}

export class Encryption {
    private encryptCount = 0;
    private decryptCount = 0;

    constructor(public readKey: Buffer, public writeKey: Buffer) {}

    encrypt(message: Buffer): Buffer {
        const nonce = number.UInt53toBufferLE(this.encryptCount++);

        return Buffer.concat(encryption.encryptAndSeal(message, null, nonce, this.writeKey!));
    }

    decrypt(message: Buffer) {
        const nonce = number.UInt53toBufferLE(this.decryptCount++);
        const cipherText = message.slice(0, -16);
        const hmac = message.slice(-16);

        return encryption.verifyAndDecrypt(cipherText, hmac, null, nonce, this.readKey!);
    }
}

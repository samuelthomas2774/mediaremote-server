import TypedEventEmitter from './events';

import Server, {Session} from './server';
import Message, {Type as MessageType} from './message';
import PairingSession from './pairing';

import VoiceInputDevice from './voice-input-device';
import TouchInputDevice, {VirtualTouchEvent} from './touch-input-device';

export interface ClientUpdatesConfig {
    artworkUpdates: boolean;
    nowPlayingUpdates: boolean;
    volumeUpdates: boolean;
    keyboardUpdates: boolean;
}

type Events = {
    'debug': [/** data */ string];

    'pair-setup': [/** code */ string, /* session */ Session];

    'register-voice-input-device': [/* device */ VoiceInputDevice];
    'unregister-voice-input-device': [/* device */ VoiceInputDevice];

    'register-touch-input-device': [/* device */ TouchInputDevice];
    'unregister-touch-input-device': [/* device */ TouchInputDevice];
    'touch': [/** event */ VirtualTouchEvent, /* device */ TouchInputDevice];

    // TODO
    'artwork-update': never[];
    'now-playing-update': never[];
    'volume-update': never[];
    'keyboard-update': never[];
};

export default class MediaRemoteServer extends TypedEventEmitter<MediaRemoteServer, Events> {
    private readonly _handleMessage = this.handleMessage.bind(this);

    readonly name: string = 'Apple TV';
    readonly uuid: string = 'B52D1E7B-66FD-4632-8FBB-644614325855';

    private readonly servers: Server[] = [];

    readonly voiceInputDevices: VoiceInputDevice[] = [];
    readonly touchInputDevices: TouchInputDevice[] = [];

    constructor() {
        super();
    }

    async listen(port = 0, host?: string) {
        const server = new Server(this);

        server.socket.listen(port, host);

        let resolve: any, reject: any;
        await new Promise((rs, rj) => {
            resolve = rs;
            reject = rj;
            server.once('listening', resolve);
            server.socket.once('error', reject);
        });
        server.removeListener('listening', resolve);
        server.socket.removeListener('error', reject);

        server.on('message', this._handleMessage);
        server.on('close', () => this.servers.splice(this.servers.indexOf(server), 1));

        server.on('debug', data => this.emit('debug', data));

        return server;
    }

    private handleMessage(message: Message, session: Session) {
        if (message.type === MessageType.DeviceInfoMessage) return this.handleDeviceInfoMessage(message, session);
        if (message.type === MessageType.CryptoPairingMessage) return this.handlePairingMessage(message, session);
        if (message.type === MessageType.RegisterVoiceInputDeviceMessage) return this.handleRegisterVoiceInputDeviceMessage(message, session);
        if (message.type === MessageType.ClientUpdatesConfigMessage) return this.handleClientUpdatesConfigMessage(message, session);
        if (message.type === MessageType.GetKeyboardSessionMessage) return this.handleGetKeyboardSessionMessage(message, session);
        if (message.type === MessageType.RegisterHidDeviceMessage) return this.handleRegisterHidDeviceMessage(message, session);
        if (message.type === MessageType.SendVirtualTouchEventMessage) return this.handleSendVirtualTouchEventMessage(message, session);
        if (message.type === MessageType.SendHidEventMessage) return this.handleSendHidEventMessage(message, session);

        console.error('Received unsupported message from [%s]:%d', session.connection.address, session.connection.port, message);
        session.connection.socket.end();
    }

    private handleDeviceInfoMessage(message: Message, session: Session) {
        console.log('Received device info message', message);

        const deviceInfo = {
            uniqueIdentifier: this.uuid,
            name: this.name,
            // systemBuildVersion: '13Y825',
            // systemBuildVersion: '16J602',
            systemBuildVersion: '17K82',
            applicationBundleIdentifier: 'com.apple.mediaremoted',
            protocolVersion: 1,
        };
        session.sendMessage('DeviceInfoMessage', 'DeviceInfoMessage', deviceInfo, 0, message.identifier);
    }

    private handlePairingMessage(message: Message, session: Session) {
        const pairingSession = session.pairing || (session.pairing = new PairingSession(session));

        pairingSession.handle(message);
    }

    private handleRegisterVoiceInputDeviceMessage(message: Message, session: Session) {
        const deviceDescriptor = message.payload.deviceDescriptor;

        const device = new VoiceInputDevice(session, deviceDescriptor);

        this.voiceInputDevices.push(device);
        session.voiceInputDevices.push(device);

        this.emit('register-voice-input-device', device);

        const response = {
            deviceID: device.id,
            errorCode: 0,
        };
        session.sendMessage('RegisterVoiceInputDeviceResponseMessage', 'RegisterVoiceInputDeviceResponseMessage',
            response, 0, message.identifier);
    }

    private handleClientUpdatesConfigMessage(message: Message, session: Session) {
        const clientUpdatesConfig = message.payload as {
            artworkUpdates: boolean;
            nowPlayingUpdates: boolean;
            volumeUpdates: boolean;
            keyboardUpdates: boolean;
        };

        session.setClientUpdatesConfig(clientUpdatesConfig);
    }

    private async handleGetKeyboardSessionMessage(message: Message, session: Session) {
        const response = await this.getKeyboardSession();
        session.sendMessage('KeyboardMessage', 'KeyboardMessage', response, 0, message.identifier);
    }

    getKeyboardSession(): KeyboardSession {
        return {
            state: KeyboardState.INACTIVE,
        };
    }

    private handleRegisterHidDeviceMessage(message: Message, session: Session) {
        const deviceDescriptor = message.payload.deviceDescriptor;

        const device = new TouchInputDevice(session, deviceDescriptor);

        this.touchInputDevices.push(device);
        session.touchInputDevices.push(device);

        this.emit('register-touch-input-device', device);

        const response = {
            errorCode: 0,
            deviceIdentifier: device.id,
        };
        session.sendMessage('RegisterHIDDeviceResultMessage', 'RegisterHIDDeviceResultMessage',
            response, 0, message.identifier);
    }

    private handleSendVirtualTouchEventMessage(message: Message, session: Session) {
        const id = message.payload.deviceIdentifier as number;
        const device = this.touchInputDevices.find(d => d.session === session && d.id === id);
        if (!device) {
            this.emit('debug', 'DEBUG: Unknown touch input device with ID ' + id);
            return;
        }

        device.handleVirtualTouchEvent(message.payload.event);
    }

    private handleSendHidEventMessage(message: Message, session: Session) {
        // TODO
    }
}

export interface KeyboardSession {
    state?: number;
    attributes?: TextEditingAttributes;
    encryptedTextCyphertext?: Buffer;
}

export enum KeyboardState {
    INACTIVE = 0,
    ACTIVE = 1,
}

export interface TextEditingAttributes {
    title?: string;
    prompt?: string;
    inputTraits?: TextInputTraits;
}

export interface TextInputTraits {
    autocapitalizationType?: AutocapitalizationType;
    keyboardType?: KeyboardType;
    returnKeyType?: ReturnKeyType;
    autocorrection?: boolean;
    spellchecking?: boolean;
    enablesReturnKeyAutomatically?: boolean;
    secureTextEntry?: boolean;
    validTextRangeLocation?: number | bigint;
    validTextRangeLength?: number | bigint;
    PINEntrySeparatorIndexes?: number | bigint;
}

export enum AutocapitalizationType {
    NONE = 0,
    WORDS = 1,
    SENTENCES = 2,
    CHARACTERS = 3,
}

export enum KeyboardType {
    KEYBOARD_TYPE_DEFAULT = 0,
    ASCII_CAPABLE = 1,
    NUMBERS_AND_PUNCTUATION = 2,
    URL = 3,
    NUMBER_PAD = 4,
    PHONE_PAD = 5,
    NAME_PHONE_PAD = 6,
    EMAIL_ADDRESS = 7,
    DECIMAL_PAD = 8,
    TWITTER = 9,
    WEB_SEARCH = 10,
    // ALPHABET = 1,
}

export enum ReturnKeyType {
    RETURN_KEY_DEFAULT = 0,
    GO = 1,
    GOOGLE = 2,
    JOIN = 3,
    NEXT = 4,
    ROUTE = 5,
    SEARCH = 6,
    SEND = 7,
    YAHOO = 8,
    DONE = 9,
    EMERGENCY_CALL = 10,
    CONTINUE = 11,
}

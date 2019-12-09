import {Session} from './server';

export default class VoiceInputDevice {
    readonly id: number;

    constructor(readonly session: Session, readonly deviceDescriptor: any) {
        this.id = session.nextDeviceId++;
    }
}

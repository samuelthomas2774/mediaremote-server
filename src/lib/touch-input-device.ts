import {Session} from './server';
import TypedEventEmitter from './events';

type Events = {
    'touch': [/** event */ VirtualTouchEvent];
};

export default class TouchInputDevice extends TypedEventEmitter<TouchInputDevice, Events> {
    readonly id: number;

    constructor(readonly session: Session, readonly deviceDescriptor: VirtualTouchDeviceDescriptor) {
        super();
        this.id = session.nextDeviceId++;
    }

    handleVirtualTouchEvent(event: VirtualTouchEvent) {
        this.emit('touch', event);
        this.session.connection.server.mediaremote.emit('touch', event, this);

        // TODO: touch tracking?
    }
}

interface VirtualTouchDeviceDescriptor {
    absolute?: boolean;
    integratedDisplay?: boolean;
    screenSizeWidth?: number;
    screenSizeHeight?: number;
}

export interface VirtualTouchEvent {
    x?: number;
    y?: number;
    phase?: TouchPhase;
    finger?: number;
}

export enum TouchPhase {
    START = 1,
    MOVE = 2,

    UNKNOWN_4 = 4,
    END = 5,
}

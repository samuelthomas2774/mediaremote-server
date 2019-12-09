import * as mdns from 'mdns';

interface TxtRecord {
    /** A UUID matching the `psi` record of the _airplay._tcp service. This is set even if AirPlay is disabled. */
    LocalAirPlayReceiverPairingIdentity: string;
    SystemBuildVersion: string;
    BluetoothAddress: string;
    ModelName: string;
    macAddress: string;
    UniqueIdentifier: string; // UUID
    AllowPairing: 'YES' | 'NO';
    Name: string;
}

export default class Advertiser {
    readonly port: number;
    readonly name: string;
    private _started = false;
    private advertisment: mdns.Advertisement;
    private readonly txtRecord: TxtRecord;

    /**
     * Creates a new Advertiser.
     *
     * @param {number} port
     * @param {string} name
     * @param {object} data
     * @param {string} data.macAddress
     * @param {string} data.uuid
     * @param {string} [data.airplayuuid]
     * @param {boolean} [data.allowPairing=false]
     */
    constructor(port: number, name: string, data: {
        macAddress: string;
        uuid: string;
        airplayuuid?: string;
        allowPairing?: boolean;
    }) {
        this.port = port;
        this.name = name;
        
        this.advertisment = mdns.createAdvertisement(mdns.tcp('mediaremotetv'), port, {
            name: this.name,
            txtRecord: this.txtRecord = {
                LocalAirPlayReceiverPairingIdentity: data.airplayuuid || '00000000-0000-0000-0000-000000000000',
                // SystemBuildVersion: '13Y825',
                // SystemBuildVersion: '16J602',
                SystemBuildVersion: '17K82',
                BluetoothAddress: '',
                ModelName: '',
                macAddress: data.macAddress,
                UniqueIdentifier: data.uuid,
                AllowPairing: data.allowPairing ? 'YES' : 'NO',
                Name: this.name,
            },
        });
    }

    private updateTxtRecord(txtRecord?: TxtRecord) {
        // @ts-ignore
        this.advertisment.updateTXTRecord(txtRecord || this.txtRecord);
    }

    get macAddress() {
        return this.txtRecord.macAddress;
    }
    set macAddress(macAddress: string) {
        this.txtRecord.macAddress = macAddress;
        this.updateTxtRecord();
    }

    get uuid() {
        return this.txtRecord.UniqueIdentifier;
    }
    set uuid(uuid: string) {
        this.txtRecord.UniqueIdentifier = uuid;
        this.updateTxtRecord();
    }

    get airplayuuid() {
        return this.txtRecord.LocalAirPlayReceiverPairingIdentity === '00000000-0000-0000-0000-000000000000' ? null :
            this.txtRecord.LocalAirPlayReceiverPairingIdentity;
    }
    set airplayuuid(airplayuuid: string | null) {
        this.txtRecord.LocalAirPlayReceiverPairingIdentity = airplayuuid || '00000000-0000-0000-0000-000000000000';
        this.updateTxtRecord();
    }

    get allowPairing() {
        return this.txtRecord.AllowPairing === 'YES';
    }
    set allowPairing(allowPairing: boolean) {
        this.txtRecord.AllowPairing = allowPairing ? 'YES' : 'NO';
        this.updateTxtRecord();
    }

    start() {
        this._started = true;
        this.advertisment.start();
    }

    stop() {
        this._started = false;
        this.advertisment.stop();
    }

    get started() {
        return this._started;
    }
    set started(started: boolean) {
        if (started && !this._started) this.start();
        if (!started && this._started) this.stop();
    }
}

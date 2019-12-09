import MediaRemoteServer, {Advertiser} from '..';

(async () => {
    const mediaremote = new MediaRemoteServer();

    mediaremote.on('debug', data => console.debug(data));

    mediaremote.on('pair-setup', (code, session) => {
        console.log('Pair setup request from [%s]:%d', session.connection.address, session.connection.port);
        console.log('Setup code is %s', code);
    });

    const server = await mediaremote.listen(9000, '::');

    const advertiser = new Advertiser(server.port, mediaremote.name, {
        macAddress: '00:00:00:00:00:00',
        uuid: mediaremote.uuid,
        airplayuuid: mediaremote.uuid,
        allowPairing: true,
    });
    advertiser.start();

    console.log('Server listening and advertising');
})();

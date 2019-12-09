import {load as loadProto} from 'protobufjs';

export async function load(name: string) {
    return loadProto(require.resolve(`../protos/${name}.proto`));
}

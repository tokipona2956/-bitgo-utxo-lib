"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBufferV5 = exports.toBufferV4 = exports.writeOutputs = exports.writeInputs = exports.fromBufferV5 = exports.fromBufferV4 = exports.writeEmptySamplingBundle = exports.readEmptySaplingBundle = exports.writeEmptyOrchardBundle = exports.readEmptyOrchardBundle = exports.readEmptyVector = exports.readOutputs = exports.readInputs = exports.VALUE_INT64_ZERO = void 0;
const ZcashTransaction_1 = require("./ZcashTransaction");
exports.VALUE_INT64_ZERO = Buffer.from('0000000000000000', 'hex');
function readInputs(bufferReader) {
    const vinLen = bufferReader.readVarInt();
    const ins = [];
    for (let i = 0; i < vinLen; ++i) {
        ins.push({
            hash: bufferReader.readSlice(32),
            index: bufferReader.readUInt32(),
            script: bufferReader.readVarSlice(),
            sequence: bufferReader.readUInt32(),
            witness: [],
        });
    }
    return ins;
}
exports.readInputs = readInputs;
function readOutputs(bufferReader) {
    const voutLen = bufferReader.readVarInt();
    const outs = [];
    for (let i = 0; i < voutLen; ++i) {
        outs.push({
            value: bufferReader.readUInt64(),
            script: bufferReader.readVarSlice(),
        });
    }
    return outs;
}
exports.readOutputs = readOutputs;
function readEmptyVector(bufferReader) {
    const n = bufferReader.readVarInt();
    if (n !== 0) {
        throw new ZcashTransaction_1.UnsupportedTransactionError(`expected empty vector`);
    }
}
exports.readEmptyVector = readEmptyVector;
function readEmptyOrchardBundle(bufferReader) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/orchard.h#L66
    // https://github.com/zcash/librustzcash/blob/edcde252de221d4851f1e5145306c2caf95453bc/zcash_primitives/src/transaction/components/orchard.rs#L36
    const v = bufferReader.readUInt8();
    if (v !== 0x00) {
        throw new ZcashTransaction_1.UnsupportedTransactionError(`expected byte 0x00`);
    }
}
exports.readEmptyOrchardBundle = readEmptyOrchardBundle;
function writeEmptyOrchardBundle(bufferWriter) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/orchard.h#L66
    // https://github.com/zcash/librustzcash/blob/edcde252de221d4851f1e5145306c2caf95453bc/zcash_primitives/src/transaction/components/orchard.rs#L201
    bufferWriter.writeUInt8(0);
}
exports.writeEmptyOrchardBundle = writeEmptyOrchardBundle;
function readEmptySaplingBundle(bufferReader) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L283
    readEmptyVector(bufferReader) /* vSpendsSapling */;
    readEmptyVector(bufferReader) /* vOutputsSapling */;
}
exports.readEmptySaplingBundle = readEmptySaplingBundle;
function writeEmptySamplingBundle(bufferWriter) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L283
    bufferWriter.writeVarInt(0) /* vSpendsSapling */;
    bufferWriter.writeVarInt(0) /* vOutputsSapling */;
}
exports.writeEmptySamplingBundle = writeEmptySamplingBundle;
function fromBufferV4(bufferReader, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L855-L857
    tx.ins = readInputs(bufferReader);
    tx.outs = readOutputs(bufferReader);
    tx.locktime = bufferReader.readUInt32();
    if (tx.isOverwinterCompatible()) {
        tx.expiryHeight = bufferReader.readUInt32();
    }
    if (tx.isSaplingCompatible()) {
        const valueBalance = bufferReader.readSlice(8);
        if (!valueBalance.equals(exports.VALUE_INT64_ZERO)) {
            /* istanbul ignore next */
            throw new ZcashTransaction_1.UnsupportedTransactionError(`valueBalance must be zero`);
        }
        // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L863
        readEmptySaplingBundle(bufferReader);
    }
    if (tx.supportsJoinSplits()) {
        // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L869
        readEmptyVector(bufferReader) /* vJoinSplit */;
    }
}
exports.fromBufferV4 = fromBufferV4;
function fromBufferV5(bufferReader, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L815
    tx.consensusBranchId = bufferReader.readUInt32();
    tx.locktime = bufferReader.readUInt32();
    tx.expiryHeight = bufferReader.readUInt32();
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L828
    tx.ins = readInputs(bufferReader);
    tx.outs = readOutputs(bufferReader);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L835
    readEmptySaplingBundle(bufferReader);
    readEmptyOrchardBundle(bufferReader);
}
exports.fromBufferV5 = fromBufferV5;
function writeInputs(bufferWriter, ins) {
    bufferWriter.writeVarInt(ins.length);
    ins.forEach(function (txIn) {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
        bufferWriter.writeVarSlice(txIn.script);
        bufferWriter.writeUInt32(txIn.sequence);
    });
}
exports.writeInputs = writeInputs;
function writeOutputs(bufferWriter, outs) {
    bufferWriter.writeVarInt(outs.length);
    outs.forEach(function (txOut) {
        if (txOut.valueBuffer) {
            bufferWriter.writeSlice(txOut.valueBuffer);
        }
        else {
            bufferWriter.writeUInt64(txOut.value);
        }
        bufferWriter.writeVarSlice(txOut.script);
    });
}
exports.writeOutputs = writeOutputs;
function toBufferV4(bufferWriter, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1083
    writeInputs(bufferWriter, tx.ins);
    writeOutputs(bufferWriter, tx.outs);
    bufferWriter.writeUInt32(tx.locktime);
    if (tx.isOverwinterCompatible()) {
        bufferWriter.writeUInt32(tx.expiryHeight);
    }
    if (tx.isSaplingCompatible()) {
        bufferWriter.writeSlice(exports.VALUE_INT64_ZERO);
        bufferWriter.writeVarInt(0); // vShieldedSpendLength
        bufferWriter.writeVarInt(0); // vShieldedOutputLength
    }
    if (tx.supportsJoinSplits()) {
        bufferWriter.writeVarInt(0); // joinsSplits length
    }
}
exports.toBufferV4 = toBufferV4;
function toBufferV5(bufferWriter, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L825-L826
    bufferWriter.writeUInt32(tx.consensusBranchId);
    bufferWriter.writeUInt32(tx.locktime);
    bufferWriter.writeUInt32(tx.expiryHeight);
    writeInputs(bufferWriter, tx.ins);
    writeOutputs(bufferWriter, tx.outs);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1063
    writeEmptySamplingBundle(bufferWriter);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1081
    writeEmptyOrchardBundle(bufferWriter);
}
exports.toBufferV5 = toBufferV5;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiWmNhc2hCdWZmZXJ1dGlscy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby96Y2FzaC9aY2FzaEJ1ZmZlcnV0aWxzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQVVBLHlEQUFtRjtBQUV0RSxRQUFBLGdCQUFnQixHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsa0JBQWtCLEVBQUUsS0FBSyxDQUFDLENBQUM7QUFFdkUsU0FBZ0IsVUFBVSxDQUFDLFlBQTBCO0lBQ25ELE1BQU0sTUFBTSxHQUFHLFlBQVksQ0FBQyxVQUFVLEVBQUUsQ0FBQztJQUN6QyxNQUFNLEdBQUcsR0FBYyxFQUFFLENBQUM7SUFDMUIsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxFQUFFLENBQUMsRUFBRTtRQUMvQixHQUFHLENBQUMsSUFBSSxDQUFDO1lBQ1AsSUFBSSxFQUFFLFlBQVksQ0FBQyxTQUFTLENBQUMsRUFBRSxDQUFDO1lBQ2hDLEtBQUssRUFBRSxZQUFZLENBQUMsVUFBVSxFQUFFO1lBQ2hDLE1BQU0sRUFBRSxZQUFZLENBQUMsWUFBWSxFQUFFO1lBQ25DLFFBQVEsRUFBRSxZQUFZLENBQUMsVUFBVSxFQUFFO1lBQ25DLE9BQU8sRUFBRSxFQUFFO1NBQ1osQ0FBQyxDQUFDO0tBQ0o7SUFDRCxPQUFPLEdBQUcsQ0FBQztBQUNiLENBQUM7QUFiRCxnQ0FhQztBQUVELFNBQWdCLFdBQVcsQ0FBQyxZQUEwQjtJQUNwRCxNQUFNLE9BQU8sR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFDMUMsTUFBTSxJQUFJLEdBQWUsRUFBRSxDQUFDO0lBQzVCLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxPQUFPLEVBQUUsRUFBRSxDQUFDLEVBQUU7UUFDaEMsSUFBSSxDQUFDLElBQUksQ0FBQztZQUNSLEtBQUssRUFBRSxZQUFZLENBQUMsVUFBVSxFQUFFO1lBQ2hDLE1BQU0sRUFBRSxZQUFZLENBQUMsWUFBWSxFQUFFO1NBQ3BDLENBQUMsQ0FBQztLQUNKO0lBQ0QsT0FBTyxJQUFJLENBQUM7QUFDZCxDQUFDO0FBVkQsa0NBVUM7QUFFRCxTQUFnQixlQUFlLENBQUMsWUFBMEI7SUFDeEQsTUFBTSxDQUFDLEdBQUcsWUFBWSxDQUFDLFVBQVUsRUFBRSxDQUFDO0lBQ3BDLElBQUksQ0FBQyxLQUFLLENBQUMsRUFBRTtRQUNYLE1BQU0sSUFBSSw4Q0FBMkIsQ0FBQyx1QkFBdUIsQ0FBQyxDQUFDO0tBQ2hFO0FBQ0gsQ0FBQztBQUxELDBDQUtDO0FBRUQsU0FBZ0Isc0JBQXNCLENBQUMsWUFBMEI7SUFDL0QsMEVBQTBFO0lBQzFFLGlKQUFpSjtJQUNqSixNQUFNLENBQUMsR0FBRyxZQUFZLENBQUMsU0FBUyxFQUFFLENBQUM7SUFDbkMsSUFBSSxDQUFDLEtBQUssSUFBSSxFQUFFO1FBQ2QsTUFBTSxJQUFJLDhDQUEyQixDQUFDLG9CQUFvQixDQUFDLENBQUM7S0FDN0Q7QUFDSCxDQUFDO0FBUEQsd0RBT0M7QUFFRCxTQUFnQix1QkFBdUIsQ0FBQyxZQUEwQjtJQUNoRSwwRUFBMEU7SUFDMUUsa0pBQWtKO0lBQ2xKLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDN0IsQ0FBQztBQUpELDBEQUlDO0FBRUQsU0FBZ0Isc0JBQXNCLENBQUMsWUFBMEI7SUFDL0QsK0VBQStFO0lBQy9FLGVBQWUsQ0FBQyxZQUFZLENBQUMsQ0FBQyxvQkFBb0IsQ0FBQztJQUNuRCxlQUFlLENBQUMsWUFBWSxDQUFDLENBQUMscUJBQXFCLENBQUM7QUFDdEQsQ0FBQztBQUpELHdEQUlDO0FBRUQsU0FBZ0Isd0JBQXdCLENBQUMsWUFBMEI7SUFDakUsK0VBQStFO0lBQy9FLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsb0JBQW9CLENBQUM7SUFDakQsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxxQkFBcUIsQ0FBQztBQUNwRCxDQUFDO0FBSkQsNERBSUM7QUFFRCxTQUFnQixZQUFZLENBQUMsWUFBMEIsRUFBRSxFQUFvQjtJQUMzRSxvRkFBb0Y7SUFDcEYsRUFBRSxDQUFDLEdBQUcsR0FBRyxVQUFVLENBQUMsWUFBWSxDQUFDLENBQUM7SUFDbEMsRUFBRSxDQUFDLElBQUksR0FBRyxXQUFXLENBQUMsWUFBWSxDQUFDLENBQUM7SUFDcEMsRUFBRSxDQUFDLFFBQVEsR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFFeEMsSUFBSSxFQUFFLENBQUMsc0JBQXNCLEVBQUUsRUFBRTtRQUMvQixFQUFFLENBQUMsWUFBWSxHQUFHLFlBQVksQ0FBQyxVQUFVLEVBQUUsQ0FBQztLQUM3QztJQUVELElBQUksRUFBRSxDQUFDLG1CQUFtQixFQUFFLEVBQUU7UUFDNUIsTUFBTSxZQUFZLEdBQUcsWUFBWSxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUMvQyxJQUFJLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyx3QkFBZ0IsQ0FBQyxFQUFFO1lBQzFDLDBCQUEwQjtZQUMxQixNQUFNLElBQUksOENBQTJCLENBQUMsMkJBQTJCLENBQUMsQ0FBQztTQUNwRTtRQUVELCtFQUErRTtRQUMvRSxzQkFBc0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztLQUN0QztJQUVELElBQUksRUFBRSxDQUFDLGtCQUFrQixFQUFFLEVBQUU7UUFDM0IsK0VBQStFO1FBQy9FLGVBQWUsQ0FBQyxZQUFZLENBQUMsQ0FBQyxnQkFBZ0IsQ0FBQztLQUNoRDtBQUNILENBQUM7QUF6QkQsb0NBeUJDO0FBRUQsU0FBZ0IsWUFBWSxDQUFDLFlBQTBCLEVBQUUsRUFBb0I7SUFDM0UsK0VBQStFO0lBQy9FLEVBQUUsQ0FBQyxpQkFBaUIsR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFDakQsRUFBRSxDQUFDLFFBQVEsR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFDeEMsRUFBRSxDQUFDLFlBQVksR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFFNUMsK0VBQStFO0lBQy9FLEVBQUUsQ0FBQyxHQUFHLEdBQUcsVUFBVSxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBQ2xDLEVBQUUsQ0FBQyxJQUFJLEdBQUcsV0FBVyxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBRXBDLCtFQUErRTtJQUMvRSxzQkFBc0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztJQUNyQyxzQkFBc0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN2QyxDQUFDO0FBYkQsb0NBYUM7QUFFRCxTQUFnQixXQUFXLENBQUMsWUFBMEIsRUFBRSxHQUFjO0lBQ3BFLFlBQVksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBQ3JDLEdBQUcsQ0FBQyxPQUFPLENBQUMsVUFBVSxJQUFJO1FBQ3hCLFlBQVksQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBQ25DLFlBQVksQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3JDLFlBQVksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ3hDLFlBQVksQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQzFDLENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQVJELGtDQVFDO0FBRUQsU0FBZ0IsWUFBWSxDQUFDLFlBQTBCLEVBQUUsSUFBZ0I7SUFDdkUsWUFBWSxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDdEMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLEtBQUs7UUFDMUIsSUFBSyxLQUFhLENBQUMsV0FBVyxFQUFFO1lBQzlCLFlBQVksQ0FBQyxVQUFVLENBQUUsS0FBYSxDQUFDLFdBQVcsQ0FBQyxDQUFDO1NBQ3JEO2FBQU07WUFDTCxZQUFZLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUN2QztRQUVELFlBQVksQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBQzNDLENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQVhELG9DQVdDO0FBRUQsU0FBZ0IsVUFBVSxDQUFDLFlBQTBCLEVBQUUsRUFBb0I7SUFDekUsZ0ZBQWdGO0lBQ2hGLFdBQVcsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ2xDLFlBQVksQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBRXBDLFlBQVksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBRXRDLElBQUksRUFBRSxDQUFDLHNCQUFzQixFQUFFLEVBQUU7UUFDL0IsWUFBWSxDQUFDLFdBQVcsQ0FBQyxFQUFFLENBQUMsWUFBWSxDQUFDLENBQUM7S0FDM0M7SUFFRCxJQUFJLEVBQUUsQ0FBQyxtQkFBbUIsRUFBRSxFQUFFO1FBQzVCLFlBQVksQ0FBQyxVQUFVLENBQUMsd0JBQWdCLENBQUMsQ0FBQztRQUMxQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsdUJBQXVCO1FBQ3BELFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyx3QkFBd0I7S0FDdEQ7SUFFRCxJQUFJLEVBQUUsQ0FBQyxrQkFBa0IsRUFBRSxFQUFFO1FBQzNCLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxxQkFBcUI7S0FDbkQ7QUFDSCxDQUFDO0FBcEJELGdDQW9CQztBQUVELFNBQWdCLFVBQVUsQ0FBQyxZQUEwQixFQUFFLEVBQW9CO0lBQ3pFLG9GQUFvRjtJQUNwRixZQUFZLENBQUMsV0FBVyxDQUFDLEVBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO0lBQy9DLFlBQVksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQ3RDLFlBQVksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBQzFDLFdBQVcsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ2xDLFlBQVksQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBRXBDLGdGQUFnRjtJQUNoRix3QkFBd0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztJQUN2QyxnRkFBZ0Y7SUFDaEYsdUJBQXVCLENBQUMsWUFBWSxDQUFDLENBQUM7QUFDeEMsQ0FBQztBQVpELGdDQVlDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBUcmFuc2FjdGlvbiAoZGUpc2VyaWFsaXphdGlvbiBoZWxwZXJzLlxuICogT25seSBzdXBwb3J0cyBmdWxsIHRyYW5zcGFyZW50IHRyYW5zYWN0aW9ucyB3aXRob3V0IHNoaWVsZGVkIGlucHV0cyBvciBvdXRwdXRzLlxuICpcbiAqIFJlZmVyZW5jZXM6XG4gKiAtIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w3NzFcbiAqL1xuaW1wb3J0IHsgVHhJbnB1dCwgVHhPdXRwdXQgfSBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCB7IEJ1ZmZlclJlYWRlciwgQnVmZmVyV3JpdGVyIH0gZnJvbSAnYml0Y29pbmpzLWxpYi9zcmMvYnVmZmVydXRpbHMnO1xuXG5pbXBvcnQgeyBVbnN1cHBvcnRlZFRyYW5zYWN0aW9uRXJyb3IsIFpjYXNoVHJhbnNhY3Rpb24gfSBmcm9tICcuL1pjYXNoVHJhbnNhY3Rpb24nO1xuXG5leHBvcnQgY29uc3QgVkFMVUVfSU5UNjRfWkVSTyA9IEJ1ZmZlci5mcm9tKCcwMDAwMDAwMDAwMDAwMDAwJywgJ2hleCcpO1xuXG5leHBvcnQgZnVuY3Rpb24gcmVhZElucHV0cyhidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlcik6IFR4SW5wdXRbXSB7XG4gIGNvbnN0IHZpbkxlbiA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KCk7XG4gIGNvbnN0IGluczogVHhJbnB1dFtdID0gW107XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdmluTGVuOyArK2kpIHtcbiAgICBpbnMucHVzaCh7XG4gICAgICBoYXNoOiBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDMyKSxcbiAgICAgIGluZGV4OiBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpLFxuICAgICAgc2NyaXB0OiBidWZmZXJSZWFkZXIucmVhZFZhclNsaWNlKCksXG4gICAgICBzZXF1ZW5jZTogYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKSxcbiAgICAgIHdpdG5lc3M6IFtdLFxuICAgIH0pO1xuICB9XG4gIHJldHVybiBpbnM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkT3V0cHV0cyhidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlcik6IFR4T3V0cHV0W10ge1xuICBjb25zdCB2b3V0TGVuID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJJbnQoKTtcbiAgY29uc3Qgb3V0czogVHhPdXRwdXRbXSA9IFtdO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHZvdXRMZW47ICsraSkge1xuICAgIG91dHMucHVzaCh7XG4gICAgICB2YWx1ZTogYnVmZmVyUmVhZGVyLnJlYWRVSW50NjQoKSxcbiAgICAgIHNjcmlwdDogYnVmZmVyUmVhZGVyLnJlYWRWYXJTbGljZSgpLFxuICAgIH0pO1xuICB9XG4gIHJldHVybiBvdXRzO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcmVhZEVtcHR5VmVjdG9yKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIGNvbnN0IG4gPSBidWZmZXJSZWFkZXIucmVhZFZhckludCgpO1xuICBpZiAobiAhPT0gMCkge1xuICAgIHRocm93IG5ldyBVbnN1cHBvcnRlZFRyYW5zYWN0aW9uRXJyb3IoYGV4cGVjdGVkIGVtcHR5IHZlY3RvcmApO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkRW1wdHlPcmNoYXJkQnVuZGxlKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy9vcmNoYXJkLmgjTDY2XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC9saWJydXN0emNhc2gvYmxvYi9lZGNkZTI1MmRlMjIxZDQ4NTFmMWU1MTQ1MzA2YzJjYWY5NTQ1M2JjL3pjYXNoX3ByaW1pdGl2ZXMvc3JjL3RyYW5zYWN0aW9uL2NvbXBvbmVudHMvb3JjaGFyZC5ycyNMMzZcbiAgY29uc3QgdiA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDgoKTtcbiAgaWYgKHYgIT09IDB4MDApIHtcbiAgICB0aHJvdyBuZXcgVW5zdXBwb3J0ZWRUcmFuc2FjdGlvbkVycm9yKGBleHBlY3RlZCBieXRlIDB4MDBgKTtcbiAgfVxufVxuXG5leHBvcnQgZnVuY3Rpb24gd3JpdGVFbXB0eU9yY2hhcmRCdW5kbGUoYnVmZmVyV3JpdGVyOiBCdWZmZXJXcml0ZXIpOiB2b2lkIHtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL29yY2hhcmQuaCNMNjZcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL2xpYnJ1c3R6Y2FzaC9ibG9iL2VkY2RlMjUyZGUyMjFkNDg1MWYxZTUxNDUzMDZjMmNhZjk1NDUzYmMvemNhc2hfcHJpbWl0aXZlcy9zcmMvdHJhbnNhY3Rpb24vY29tcG9uZW50cy9vcmNoYXJkLnJzI0wyMDFcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDgoMCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkRW1wdHlTYXBsaW5nQnVuZGxlKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0wyODNcbiAgcmVhZEVtcHR5VmVjdG9yKGJ1ZmZlclJlYWRlcikgLyogdlNwZW5kc1NhcGxpbmcgKi87XG4gIHJlYWRFbXB0eVZlY3RvcihidWZmZXJSZWFkZXIpIC8qIHZPdXRwdXRzU2FwbGluZyAqLztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHdyaXRlRW1wdHlTYW1wbGluZ0J1bmRsZShidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlcik6IHZvaWQge1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMMjgzXG4gIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKSAvKiB2U3BlbmRzU2FwbGluZyAqLztcbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KDApIC8qIHZPdXRwdXRzU2FwbGluZyAqLztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21CdWZmZXJWNChidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlciwgdHg6IFpjYXNoVHJhbnNhY3Rpb24pOiB2b2lkIHtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDg1NS1MODU3XG4gIHR4LmlucyA9IHJlYWRJbnB1dHMoYnVmZmVyUmVhZGVyKTtcbiAgdHgub3V0cyA9IHJlYWRPdXRwdXRzKGJ1ZmZlclJlYWRlcik7XG4gIHR4LmxvY2t0aW1lID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKTtcblxuICBpZiAodHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgdHguZXhwaXJ5SGVpZ2h0ID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKTtcbiAgfVxuXG4gIGlmICh0eC5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICBjb25zdCB2YWx1ZUJhbGFuY2UgPSBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDgpO1xuICAgIGlmICghdmFsdWVCYWxhbmNlLmVxdWFscyhWQUxVRV9JTlQ2NF9aRVJPKSkge1xuICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICAgIHRocm93IG5ldyBVbnN1cHBvcnRlZFRyYW5zYWN0aW9uRXJyb3IoYHZhbHVlQmFsYW5jZSBtdXN0IGJlIHplcm9gKTtcbiAgICB9XG5cbiAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMODYzXG4gICAgcmVhZEVtcHR5U2FwbGluZ0J1bmRsZShidWZmZXJSZWFkZXIpO1xuICB9XG5cbiAgaWYgKHR4LnN1cHBvcnRzSm9pblNwbGl0cygpKSB7XG4gICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDg2OVxuICAgIHJlYWRFbXB0eVZlY3RvcihidWZmZXJSZWFkZXIpIC8qIHZKb2luU3BsaXQgKi87XG4gIH1cbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21CdWZmZXJWNShidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlciwgdHg6IFpjYXNoVHJhbnNhY3Rpb24pOiB2b2lkIHtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDgxNVxuICB0eC5jb25zZW5zdXNCcmFuY2hJZCA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKCk7XG4gIHR4LmxvY2t0aW1lID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKTtcbiAgdHguZXhwaXJ5SGVpZ2h0ID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKTtcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMODI4XG4gIHR4LmlucyA9IHJlYWRJbnB1dHMoYnVmZmVyUmVhZGVyKTtcbiAgdHgub3V0cyA9IHJlYWRPdXRwdXRzKGJ1ZmZlclJlYWRlcik7XG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDgzNVxuICByZWFkRW1wdHlTYXBsaW5nQnVuZGxlKGJ1ZmZlclJlYWRlcik7XG4gIHJlYWRFbXB0eU9yY2hhcmRCdW5kbGUoYnVmZmVyUmVhZGVyKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHdyaXRlSW5wdXRzKGJ1ZmZlcldyaXRlcjogQnVmZmVyV3JpdGVyLCBpbnM6IFR4SW5wdXRbXSk6IHZvaWQge1xuICBidWZmZXJXcml0ZXIud3JpdGVWYXJJbnQoaW5zLmxlbmd0aCk7XG4gIGlucy5mb3JFYWNoKGZ1bmN0aW9uICh0eEluKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UodHhJbi5oYXNoKTtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHhJbi5pbmRleCk7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UodHhJbi5zY3JpcHQpO1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLnNlcXVlbmNlKTtcbiAgfSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB3cml0ZU91dHB1dHMoYnVmZmVyV3JpdGVyOiBCdWZmZXJXcml0ZXIsIG91dHM6IFR4T3V0cHV0W10pOiB2b2lkIHtcbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KG91dHMubGVuZ3RoKTtcbiAgb3V0cy5mb3JFYWNoKGZ1bmN0aW9uICh0eE91dCkge1xuICAgIGlmICgodHhPdXQgYXMgYW55KS52YWx1ZUJ1ZmZlcikge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoKHR4T3V0IGFzIGFueSkudmFsdWVCdWZmZXIpO1xuICAgIH0gZWxzZSB7XG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQodHhPdXQudmFsdWUpO1xuICAgIH1cblxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKHR4T3V0LnNjcmlwdCk7XG4gIH0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdG9CdWZmZXJWNChidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlciwgdHg6IFpjYXNoVHJhbnNhY3Rpb24pOiB2b2lkIHtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDEwODNcbiAgd3JpdGVJbnB1dHMoYnVmZmVyV3JpdGVyLCB0eC5pbnMpO1xuICB3cml0ZU91dHB1dHMoYnVmZmVyV3JpdGVyLCB0eC5vdXRzKTtcblxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHgubG9ja3RpbWUpO1xuXG4gIGlmICh0eC5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHguZXhwaXJ5SGVpZ2h0KTtcbiAgfVxuXG4gIGlmICh0eC5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShWQUxVRV9JTlQ2NF9aRVJPKTtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJJbnQoMCk7IC8vIHZTaGllbGRlZFNwZW5kTGVuZ3RoXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KDApOyAvLyB2U2hpZWxkZWRPdXRwdXRMZW5ndGhcbiAgfVxuXG4gIGlmICh0eC5zdXBwb3J0c0pvaW5TcGxpdHMoKSkge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKTsgLy8gam9pbnNTcGxpdHMgbGVuZ3RoXG4gIH1cbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRvQnVmZmVyVjUoYnVmZmVyV3JpdGVyOiBCdWZmZXJXcml0ZXIsIHR4OiBaY2FzaFRyYW5zYWN0aW9uKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w4MjUtTDgyNlxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHguY29uc2Vuc3VzQnJhbmNoSWQpO1xuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHgubG9ja3RpbWUpO1xuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHguZXhwaXJ5SGVpZ2h0KTtcbiAgd3JpdGVJbnB1dHMoYnVmZmVyV3JpdGVyLCB0eC5pbnMpO1xuICB3cml0ZU91dHB1dHMoYnVmZmVyV3JpdGVyLCB0eC5vdXRzKTtcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMMTA2M1xuICB3cml0ZUVtcHR5U2FtcGxpbmdCdW5kbGUoYnVmZmVyV3JpdGVyKTtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDEwODFcbiAgd3JpdGVFbXB0eU9yY2hhcmRCdW5kbGUoYnVmZmVyV3JpdGVyKTtcbn1cbiJdfQ==
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.unspentSum = exports.addToTransactionBuilder = exports.toPrevOutput = exports.getOutputIdForInput = exports.formatOutputId = exports.parseOutputId = exports.toOutput = void 0;
const address_1 = require("../address");
/**
 * @return TxOutput from Unspent
 */
function toOutput(u, network) {
    return {
        script: address_1.toOutputScript(u.address, network),
        value: u.value,
    };
}
exports.toOutput = toOutput;
/**
 * @param outputId
 * @return TxOutPoint
 */
function parseOutputId(outputId) {
    const parts = outputId.split(':');
    if (parts.length !== 2) {
        throw new Error(`invalid outputId, must have format txid:vout`);
    }
    const [txid, voutStr] = parts;
    const vout = Number(voutStr);
    if (txid.length !== 64) {
        throw new Error(`invalid txid ${txid} ${txid.length}`);
    }
    if (Number.isNaN(vout) || vout < 0 || !Number.isSafeInteger(vout)) {
        throw new Error(`invalid vout: must be integer >= 0`);
    }
    return { txid, vout };
}
exports.parseOutputId = parseOutputId;
/**
 * @param txid
 * @param vout
 * @return outputId
 */
function formatOutputId({ txid, vout }) {
    return `${txid}:${vout}`;
}
exports.formatOutputId = formatOutputId;
function getOutputIdForInput(i) {
    return {
        txid: Buffer.from(i.hash).reverse().toString('hex'),
        vout: i.index,
    };
}
exports.getOutputIdForInput = getOutputIdForInput;
/**
 * @return PrevOutput from Unspent
 */
function toPrevOutput(u, network) {
    return {
        ...parseOutputId(u.id),
        ...toOutput(u, network),
    };
}
exports.toPrevOutput = toPrevOutput;
/**
 * @param txb
 * @param u
 * @param sequence - sequenceId
 */
function addToTransactionBuilder(txb, u, sequence) {
    const { txid, vout, script, value } = toPrevOutput(u, txb.network);
    txb.addInput(txid, vout, sequence, script, value);
}
exports.addToTransactionBuilder = addToTransactionBuilder;
function unspentSum(unspents) {
    return unspents.reduce((sum, u) => sum + u.value, 0);
}
exports.unspentSum = unspentSum;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVW5zcGVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9iaXRnby9VbnNwZW50LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLHdDQUE0QztBQXVCNUM7O0dBRUc7QUFDSCxTQUFnQixRQUFRLENBQUMsQ0FBVSxFQUFFLE9BQWdCO0lBQ25ELE9BQU87UUFDTCxNQUFNLEVBQUUsd0JBQWMsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQztRQUMxQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLEtBQUs7S0FDZixDQUFDO0FBQ0osQ0FBQztBQUxELDRCQUtDO0FBRUQ7OztHQUdHO0FBQ0gsU0FBZ0IsYUFBYSxDQUFDLFFBQWdCO0lBQzVDLE1BQU0sS0FBSyxHQUFHLFFBQVEsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDbEMsSUFBSSxLQUFLLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtRQUN0QixNQUFNLElBQUksS0FBSyxDQUFDLDhDQUE4QyxDQUFDLENBQUM7S0FDakU7SUFDRCxNQUFNLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHLEtBQUssQ0FBQztJQUM5QixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDN0IsSUFBSSxJQUFJLENBQUMsTUFBTSxLQUFLLEVBQUUsRUFBRTtRQUN0QixNQUFNLElBQUksS0FBSyxDQUFDLGdCQUFnQixJQUFJLElBQUksSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUM7S0FDeEQ7SUFDRCxJQUFJLE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLElBQUksSUFBSSxHQUFHLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLEVBQUU7UUFDakUsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFDO0tBQ3ZEO0lBQ0QsT0FBTyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsQ0FBQztBQUN4QixDQUFDO0FBZEQsc0NBY0M7QUFFRDs7OztHQUlHO0FBQ0gsU0FBZ0IsY0FBYyxDQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBYztJQUN2RCxPQUFPLEdBQUcsSUFBSSxJQUFJLElBQUksRUFBRSxDQUFDO0FBQzNCLENBQUM7QUFGRCx3Q0FFQztBQUVELFNBQWdCLG1CQUFtQixDQUFDLENBQWtDO0lBQ3BFLE9BQU87UUFDTCxJQUFJLEVBQUUsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsT0FBTyxFQUFFLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQztRQUNuRCxJQUFJLEVBQUUsQ0FBQyxDQUFDLEtBQUs7S0FDZCxDQUFDO0FBQ0osQ0FBQztBQUxELGtEQUtDO0FBZ0JEOztHQUVHO0FBQ0gsU0FBZ0IsWUFBWSxDQUFDLENBQVUsRUFBRSxPQUFnQjtJQUN2RCxPQUFPO1FBQ0wsR0FBRyxhQUFhLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztRQUN0QixHQUFHLFFBQVEsQ0FBQyxDQUFDLEVBQUUsT0FBTyxDQUFDO0tBQ3hCLENBQUM7QUFDSixDQUFDO0FBTEQsb0NBS0M7QUFFRDs7OztHQUlHO0FBQ0gsU0FBZ0IsdUJBQXVCLENBQUMsR0FBMkIsRUFBRSxDQUFVLEVBQUUsUUFBaUI7SUFDaEcsTUFBTSxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxHQUFHLFlBQVksQ0FBQyxDQUFDLEVBQUUsR0FBRyxDQUFDLE9BQWtCLENBQUMsQ0FBQztJQUM5RSxHQUFHLENBQUMsUUFBUSxDQUFDLElBQUksRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRSxLQUFLLENBQUMsQ0FBQztBQUNwRCxDQUFDO0FBSEQsMERBR0M7QUFFRCxTQUFnQixVQUFVLENBQUMsUUFBbUI7SUFDNUMsT0FBTyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLENBQUM7QUFDdkQsQ0FBQztBQUZELGdDQUVDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgVHhPdXRwdXQsIE5ldHdvcmsgfSBmcm9tICcuLic7XG5pbXBvcnQgeyB0b091dHB1dFNjcmlwdCB9IGZyb20gJy4uL2FkZHJlc3MnO1xuaW1wb3J0IHsgVXR4b1RyYW5zYWN0aW9uQnVpbGRlciB9IGZyb20gJy4vVXR4b1RyYW5zYWN0aW9uQnVpbGRlcic7XG5cbi8qKlxuICogUHVibGljIHVuc3BlbnQgZGF0YSBpbiBCaXRHby1zcGVjaWZpYyByZXByZXNlbnRhdGlvbi5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBVbnNwZW50IHtcbiAgLyoqXG4gICAqIEZvcm1hdDogJHt0eGlkfToke3ZvdXR9LlxuICAgKiBVc2UgYHBhcnNlT3V0cHV0SWQoaWQpYCB0byBwYXJzZS5cbiAgICovXG4gIGlkOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgbmV0d29yay1zcGVjaWZpYyBlbmNvZGVkIGFkZHJlc3MuXG4gICAqIFVzZSBgdG9PdXRwdXRTY3JpcHQoYWRkcmVzcywgbmV0d29yaylgIHRvIG9idGFpbiBzY3JpcHRQdWJLZXkuXG4gICAqL1xuICBhZGRyZXNzOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgYW1vdW50IGluIHNhdG9zaGkuXG4gICAqL1xuICB2YWx1ZTogbnVtYmVyO1xufVxuXG4vKipcbiAqIEByZXR1cm4gVHhPdXRwdXQgZnJvbSBVbnNwZW50XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB0b091dHB1dCh1OiBVbnNwZW50LCBuZXR3b3JrOiBOZXR3b3JrKTogVHhPdXRwdXQge1xuICByZXR1cm4ge1xuICAgIHNjcmlwdDogdG9PdXRwdXRTY3JpcHQodS5hZGRyZXNzLCBuZXR3b3JrKSxcbiAgICB2YWx1ZTogdS52YWx1ZSxcbiAgfTtcbn1cblxuLyoqXG4gKiBAcGFyYW0gb3V0cHV0SWRcbiAqIEByZXR1cm4gVHhPdXRQb2ludFxuICovXG5leHBvcnQgZnVuY3Rpb24gcGFyc2VPdXRwdXRJZChvdXRwdXRJZDogc3RyaW5nKTogVHhPdXRQb2ludCB7XG4gIGNvbnN0IHBhcnRzID0gb3V0cHV0SWQuc3BsaXQoJzonKTtcbiAgaWYgKHBhcnRzLmxlbmd0aCAhPT0gMikge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBvdXRwdXRJZCwgbXVzdCBoYXZlIGZvcm1hdCB0eGlkOnZvdXRgKTtcbiAgfVxuICBjb25zdCBbdHhpZCwgdm91dFN0cl0gPSBwYXJ0cztcbiAgY29uc3Qgdm91dCA9IE51bWJlcih2b3V0U3RyKTtcbiAgaWYgKHR4aWQubGVuZ3RoICE9PSA2NCkge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCB0eGlkICR7dHhpZH0gJHt0eGlkLmxlbmd0aH1gKTtcbiAgfVxuICBpZiAoTnVtYmVyLmlzTmFOKHZvdXQpIHx8IHZvdXQgPCAwIHx8ICFOdW1iZXIuaXNTYWZlSW50ZWdlcih2b3V0KSkge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCB2b3V0OiBtdXN0IGJlIGludGVnZXIgPj0gMGApO1xuICB9XG4gIHJldHVybiB7IHR4aWQsIHZvdXQgfTtcbn1cblxuLyoqXG4gKiBAcGFyYW0gdHhpZFxuICogQHBhcmFtIHZvdXRcbiAqIEByZXR1cm4gb3V0cHV0SWRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGZvcm1hdE91dHB1dElkKHsgdHhpZCwgdm91dCB9OiBUeE91dFBvaW50KTogc3RyaW5nIHtcbiAgcmV0dXJuIGAke3R4aWR9OiR7dm91dH1gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0T3V0cHV0SWRGb3JJbnB1dChpOiB7IGhhc2g6IEJ1ZmZlcjsgaW5kZXg6IG51bWJlciB9KTogVHhPdXRQb2ludCB7XG4gIHJldHVybiB7XG4gICAgdHhpZDogQnVmZmVyLmZyb20oaS5oYXNoKS5yZXZlcnNlKCkudG9TdHJpbmcoJ2hleCcpLFxuICAgIHZvdXQ6IGkuaW5kZXgsXG4gIH07XG59XG5cbi8qKlxuICogUmVmZXJlbmNlIHRvIG91dHB1dCBvZiBhbiBleGlzdGluZyB0cmFuc2FjdGlvblxuICovXG5leHBvcnQgdHlwZSBUeE91dFBvaW50ID0ge1xuICB0eGlkOiBzdHJpbmc7XG4gIHZvdXQ6IG51bWJlcjtcbn07XG5cbi8qKlxuICogT3V0cHV0IHJlZmVyZW5jZSBhbmQgc2NyaXB0IGRhdGEuXG4gKiBTdWl0YWJsZSBmb3IgdXNlIGZvciBgdHhiLmFkZElucHV0KClgXG4gKi9cbmV4cG9ydCB0eXBlIFByZXZPdXRwdXQgPSBUeE91dFBvaW50ICYgVHhPdXRwdXQ7XG5cbi8qKlxuICogQHJldHVybiBQcmV2T3V0cHV0IGZyb20gVW5zcGVudFxuICovXG5leHBvcnQgZnVuY3Rpb24gdG9QcmV2T3V0cHV0KHU6IFVuc3BlbnQsIG5ldHdvcms6IE5ldHdvcmspOiBQcmV2T3V0cHV0IHtcbiAgcmV0dXJuIHtcbiAgICAuLi5wYXJzZU91dHB1dElkKHUuaWQpLFxuICAgIC4uLnRvT3V0cHV0KHUsIG5ldHdvcmspLFxuICB9O1xufVxuXG4vKipcbiAqIEBwYXJhbSB0eGJcbiAqIEBwYXJhbSB1XG4gKiBAcGFyYW0gc2VxdWVuY2UgLSBzZXF1ZW5jZUlkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhZGRUb1RyYW5zYWN0aW9uQnVpbGRlcih0eGI6IFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXIsIHU6IFVuc3BlbnQsIHNlcXVlbmNlPzogbnVtYmVyKTogdm9pZCB7XG4gIGNvbnN0IHsgdHhpZCwgdm91dCwgc2NyaXB0LCB2YWx1ZSB9ID0gdG9QcmV2T3V0cHV0KHUsIHR4Yi5uZXR3b3JrIGFzIE5ldHdvcmspO1xuICB0eGIuYWRkSW5wdXQodHhpZCwgdm91dCwgc2VxdWVuY2UsIHNjcmlwdCwgdmFsdWUpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdW5zcGVudFN1bSh1bnNwZW50czogVW5zcGVudFtdKTogbnVtYmVyIHtcbiAgcmV0dXJuIHVuc3BlbnRzLnJlZHVjZSgoc3VtLCB1KSA9PiBzdW0gKyB1LnZhbHVlLCAwKTtcbn1cbiJdfQ==
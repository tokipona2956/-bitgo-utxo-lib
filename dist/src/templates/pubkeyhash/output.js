// OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG
var bscript = require('../../script');
var types = require('../../types');
var typeforce = require('typeforce');
var OPS = require('bitcoin-ops');
function check(script) {
    var buffer = bscript.compile(script);
    return buffer.length === 25 &&
        buffer[0] === OPS.OP_DUP &&
        buffer[1] === OPS.OP_HASH160 &&
        buffer[2] === 0x14 &&
        buffer[23] === OPS.OP_EQUALVERIFY &&
        buffer[24] === OPS.OP_CHECKSIG;
}
check.toJSON = function () { return 'pubKeyHash output'; };
function encode(pubKeyHash) {
    typeforce(types.Hash160bit, pubKeyHash);
    return bscript.compile([
        OPS.OP_DUP,
        OPS.OP_HASH160,
        pubKeyHash,
        OPS.OP_EQUALVERIFY,
        OPS.OP_CHECKSIG
    ]);
}
function decode(buffer) {
    typeforce(check, buffer);
    return buffer.slice(3, 23);
}
module.exports = {
    check: check,
    decode: decode,
    encode: encode
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3V0cHV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL3RlbXBsYXRlcy9wdWJrZXloYXNoL291dHB1dC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSw0REFBNEQ7QUFFNUQsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLGNBQWMsQ0FBQyxDQUFBO0FBQ3JDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQTtBQUNsQyxJQUFJLFNBQVMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUE7QUFDcEMsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBRWhDLFNBQVMsS0FBSyxDQUFFLE1BQU07SUFDcEIsSUFBSSxNQUFNLEdBQUcsT0FBTyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUVwQyxPQUFPLE1BQU0sQ0FBQyxNQUFNLEtBQUssRUFBRTtRQUN6QixNQUFNLENBQUMsQ0FBQyxDQUFDLEtBQUssR0FBRyxDQUFDLE1BQU07UUFDeEIsTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLEdBQUcsQ0FBQyxVQUFVO1FBQzVCLE1BQU0sQ0FBQyxDQUFDLENBQUMsS0FBSyxJQUFJO1FBQ2xCLE1BQU0sQ0FBQyxFQUFFLENBQUMsS0FBSyxHQUFHLENBQUMsY0FBYztRQUNqQyxNQUFNLENBQUMsRUFBRSxDQUFDLEtBQUssR0FBRyxDQUFDLFdBQVcsQ0FBQTtBQUNsQyxDQUFDO0FBQ0QsS0FBSyxDQUFDLE1BQU0sR0FBRyxjQUFjLE9BQU8sbUJBQW1CLENBQUEsQ0FBQyxDQUFDLENBQUE7QUFFekQsU0FBUyxNQUFNLENBQUUsVUFBVTtJQUN6QixTQUFTLENBQUMsS0FBSyxDQUFDLFVBQVUsRUFBRSxVQUFVLENBQUMsQ0FBQTtJQUV2QyxPQUFPLE9BQU8sQ0FBQyxPQUFPLENBQUM7UUFDckIsR0FBRyxDQUFDLE1BQU07UUFDVixHQUFHLENBQUMsVUFBVTtRQUNkLFVBQVU7UUFDVixHQUFHLENBQUMsY0FBYztRQUNsQixHQUFHLENBQUMsV0FBVztLQUNoQixDQUFDLENBQUE7QUFDSixDQUFDO0FBRUQsU0FBUyxNQUFNLENBQUUsTUFBTTtJQUNyQixTQUFTLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFBO0lBRXhCLE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUE7QUFDNUIsQ0FBQztBQUVELE1BQU0sQ0FBQyxPQUFPLEdBQUc7SUFDZixLQUFLLEVBQUUsS0FBSztJQUNaLE1BQU0sRUFBRSxNQUFNO0lBQ2QsTUFBTSxFQUFFLE1BQU07Q0FDZixDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiLy8gT1BfRFVQIE9QX0hBU0gxNjAge3B1YktleUhhc2h9IE9QX0VRVUFMVkVSSUZZIE9QX0NIRUNLU0lHXG5cbnZhciBic2NyaXB0ID0gcmVxdWlyZSgnLi4vLi4vc2NyaXB0JylcbnZhciB0eXBlcyA9IHJlcXVpcmUoJy4uLy4uL3R5cGVzJylcbnZhciB0eXBlZm9yY2UgPSByZXF1aXJlKCd0eXBlZm9yY2UnKVxudmFyIE9QUyA9IHJlcXVpcmUoJ2JpdGNvaW4tb3BzJylcblxuZnVuY3Rpb24gY2hlY2sgKHNjcmlwdCkge1xuICB2YXIgYnVmZmVyID0gYnNjcmlwdC5jb21waWxlKHNjcmlwdClcblxuICByZXR1cm4gYnVmZmVyLmxlbmd0aCA9PT0gMjUgJiZcbiAgICBidWZmZXJbMF0gPT09IE9QUy5PUF9EVVAgJiZcbiAgICBidWZmZXJbMV0gPT09IE9QUy5PUF9IQVNIMTYwICYmXG4gICAgYnVmZmVyWzJdID09PSAweDE0ICYmXG4gICAgYnVmZmVyWzIzXSA9PT0gT1BTLk9QX0VRVUFMVkVSSUZZICYmXG4gICAgYnVmZmVyWzI0XSA9PT0gT1BTLk9QX0NIRUNLU0lHXG59XG5jaGVjay50b0pTT04gPSBmdW5jdGlvbiAoKSB7IHJldHVybiAncHViS2V5SGFzaCBvdXRwdXQnIH1cblxuZnVuY3Rpb24gZW5jb2RlIChwdWJLZXlIYXNoKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy5IYXNoMTYwYml0LCBwdWJLZXlIYXNoKVxuXG4gIHJldHVybiBic2NyaXB0LmNvbXBpbGUoW1xuICAgIE9QUy5PUF9EVVAsXG4gICAgT1BTLk9QX0hBU0gxNjAsXG4gICAgcHViS2V5SGFzaCxcbiAgICBPUFMuT1BfRVFVQUxWRVJJRlksXG4gICAgT1BTLk9QX0NIRUNLU0lHXG4gIF0pXG59XG5cbmZ1bmN0aW9uIGRlY29kZSAoYnVmZmVyKSB7XG4gIHR5cGVmb3JjZShjaGVjaywgYnVmZmVyKVxuXG4gIHJldHVybiBidWZmZXIuc2xpY2UoMywgMjMpXG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBjaGVjazogY2hlY2ssXG4gIGRlY29kZTogZGVjb2RlLFxuICBlbmNvZGU6IGVuY29kZVxufVxuIl19
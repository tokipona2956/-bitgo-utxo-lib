"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.supportsSegwit = exports.supportsTaproot = exports.isTestnet = exports.isMainnet = exports.getTestnet = exports.getMainnet = exports.getNetworkName = exports.isValidNetwork = exports.getNetworkList = exports.networks = exports.addressFormat = exports.address = exports.bitgo = void 0;
__exportStar(require("bitcoinjs-lib"), exports);
exports.bitgo = require("./bitgo");
exports.address = require("./address");
exports.addressFormat = require("./addressFormat");
var networks_1 = require("./networks");
Object.defineProperty(exports, "networks", { enumerable: true, get: function () { return networks_1.networks; } });
Object.defineProperty(exports, "getNetworkList", { enumerable: true, get: function () { return networks_1.getNetworkList; } });
Object.defineProperty(exports, "isValidNetwork", { enumerable: true, get: function () { return networks_1.isValidNetwork; } });
Object.defineProperty(exports, "getNetworkName", { enumerable: true, get: function () { return networks_1.getNetworkName; } });
Object.defineProperty(exports, "getMainnet", { enumerable: true, get: function () { return networks_1.getMainnet; } });
Object.defineProperty(exports, "getTestnet", { enumerable: true, get: function () { return networks_1.getTestnet; } });
Object.defineProperty(exports, "isMainnet", { enumerable: true, get: function () { return networks_1.isMainnet; } });
Object.defineProperty(exports, "isTestnet", { enumerable: true, get: function () { return networks_1.isTestnet; } });
Object.defineProperty(exports, "supportsTaproot", { enumerable: true, get: function () { return networks_1.supportsTaproot; } });
Object.defineProperty(exports, "supportsSegwit", { enumerable: true, get: function () { return networks_1.supportsSegwit; } });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7OztBQUFBLGdEQUE4QjtBQUU5QixtQ0FBaUM7QUFFakMsdUNBQXFDO0FBRXJDLG1EQUFpRDtBQUVqRCx1Q0Fhb0I7QUFabEIsb0dBQUEsUUFBUSxPQUFBO0FBR1IsMEdBQUEsY0FBYyxPQUFBO0FBQ2QsMEdBQUEsY0FBYyxPQUFBO0FBQ2QsMEdBQUEsY0FBYyxPQUFBO0FBQ2Qsc0dBQUEsVUFBVSxPQUFBO0FBQ1Ysc0dBQUEsVUFBVSxPQUFBO0FBQ1YscUdBQUEsU0FBUyxPQUFBO0FBQ1QscUdBQUEsU0FBUyxPQUFBO0FBQ1QsMkdBQUEsZUFBZSxPQUFBO0FBQ2YsMEdBQUEsY0FBYyxPQUFBIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0ICogZnJvbSAnYml0Y29pbmpzLWxpYic7XG5cbmV4cG9ydCAqIGFzIGJpdGdvIGZyb20gJy4vYml0Z28nO1xuXG5leHBvcnQgKiBhcyBhZGRyZXNzIGZyb20gJy4vYWRkcmVzcyc7XG5cbmV4cG9ydCAqIGFzIGFkZHJlc3NGb3JtYXQgZnJvbSAnLi9hZGRyZXNzRm9ybWF0JztcblxuZXhwb3J0IHtcbiAgbmV0d29ya3MsXG4gIE5ldHdvcmssXG4gIE5ldHdvcmtOYW1lLFxuICBnZXROZXR3b3JrTGlzdCxcbiAgaXNWYWxpZE5ldHdvcmssXG4gIGdldE5ldHdvcmtOYW1lLFxuICBnZXRNYWlubmV0LFxuICBnZXRUZXN0bmV0LFxuICBpc01haW5uZXQsXG4gIGlzVGVzdG5ldCxcbiAgc3VwcG9ydHNUYXByb290LFxuICBzdXBwb3J0c1NlZ3dpdCxcbn0gZnJvbSAnLi9uZXR3b3Jrcyc7XG5cbmV4cG9ydCB7IE5ldHdvcmsgYXMgQml0Y29pbkpTTmV0d29yayB9IGZyb20gJ2JpdGNvaW5qcy1saWInO1xuIl19
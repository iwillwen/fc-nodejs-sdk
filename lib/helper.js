"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.composeStringToSign = void 0;
const url = __importStar(require("url"));
function buildCanonicalHeaders(headers, prefix) {
    let list = [];
    const keys = Object.keys(headers);
    const fcHeaders = {};
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const lowerKey = key.toLowerCase().trim();
        if (lowerKey.startsWith(prefix)) {
            list.push(lowerKey);
            fcHeaders[lowerKey] = headers[key];
        }
    }
    list = list.sort();
    let canonical = '';
    for (let i = 0; i < list.length; i++) {
        const key = list[i];
        canonical += `${key}:${fcHeaders[key]}\n`;
    }
    return canonical;
}
function composeStringToSign(method, path, headers, queries) {
    const contentMD5 = headers['content-md5'] || '';
    const contentType = headers['content-type'] || '';
    const date = headers['date'];
    const signHeaders = buildCanonicalHeaders(headers, 'x-fc-');
    const u = url.parse(path);
    const pathUnescaped = decodeURIComponent(u.pathname || '/');
    let str = `${method}\n${contentMD5}\n${contentType}\n${date}\n${signHeaders}${pathUnescaped}`;
    if (queries) {
        let params = [];
        Object.keys(queries).forEach(key => {
            const values = queries[key];
            const type = typeof values;
            if (type === 'string') {
                params.push(`${key}=${values}`);
                return;
            }
            if (Array.isArray(values)) {
                values.forEach(value => params.push(`${key}=${value}`));
            }
        });
        params = params.sort();
        str += '\n' + params.join('\n');
    }
    return str;
}
exports.composeStringToSign = composeStringToSign;
//# sourceMappingURL=helper.js.map
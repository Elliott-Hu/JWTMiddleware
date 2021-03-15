"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJWTMiddleware = void 0;
const tslib_1 = require("tslib");
const rtc = tslib_1.__importStar(require("routing-controllers"));
const koaJWT = tslib_1.__importStar(require("koa-jwt"));
const jsonwebtoken_1 = require("jsonwebtoken");
const const_1 = require("./const");
const UnauthorizedError = rtc.UnauthorizedError;
/**
 * 创建一个JWT校验中间件
 *
 * @export
 * @template T
 * @param {Options<T>} options
 * @return {Middleware}
 */
function createJWTMiddleware(options) {
    var _a;
    const { passthrough = false, secret, token: tokenOption, ctxState: { tokenKey = const_1.DEFAULT_STATE_TOKEN_KEY, payloadKey = const_1.DEFAULT_STATE_PAYLOAD_KEY, } = {}, 
    // cookie,
    expiresIn = const_1.DEFAULT_TOKEN_EXPIRED, handleInsertPayload, handleValidatePayload, } = options;
    /**
     * 签发token
     *
     * @param {payload} payload
     *
     * 如果是顾问身份登录登录态的有效期为24小时，否则有效期为两小时
     * @return {string}
     */
    const signToken = (payload) => jsonwebtoken_1.sign(payload, secret, { expiresIn });
    /**
     * 校验JWT携带的 Payload 完整性
     *
     * @param {Payload} payload
     * @return {Payload}
     */
    const validatePayload = (payload) => {
        if (handleValidatePayload && !handleValidatePayload(payload)) {
            throw new UnauthorizedError(`token payload 数据不完整：${JSON.stringify(payload || {})}`);
        }
        return Object.assign({}, payload);
    };
    /**
     * 将生成的令牌填充到 http response
     *
     * @param {Context} ctx
     * @param {string} token
     * @param {Payload} payload
     */
    const injectTokenToResponse = (ctx, token, payload) => {
        if (tokenOption.type === "cookie") {
            ctx.cookies.set(tokenOption.key, token, { httpOnly: true });
            return;
        }
        ctx.set("Set-Authorization", `Bearer ${token}`);
    };
    /**
     * token 重签处理
     *
     * @param {Context} ctx
     * @param {string} token
     * @return {Promise<contextState>}
     */
    const resignToken = async (ctx, token) => {
        const decodeInfomation = jsonwebtoken_1.decode(token, { complete: true, json: true });
        if (!!decodeInfomation) {
            let { payload } = decodeInfomation;
            const now = Date.now() / 1000;
            const exp = payload.exp;
            if (now > exp && now < exp + 86400 * 7) {
                // 清理冗余信息后再签发token
                payload = validatePayload(payload);
                const token = signToken(payload);
                injectTokenToResponse(ctx, token, payload);
                const contextState = {
                    [tokenKey]: token,
                    [payloadKey]: payload,
                };
                return contextState;
            }
            throw new UnauthorizedError("token已过期，请重新登陆");
        }
        throw new UnauthorizedError("token解析失败，请重新登陆");
    };
    /**
     * 从header中解析token
     *
     * @param {Context} ctx
     * @param {koaJWT.Options} options
     * @return {string}
     */
    const getToken = (ctx, options) => {
        if (!ctx.request ||
            !ctx.request.header ||
            !ctx.request.header["authorization"]) {
            return ctx.cookies.get(tokenKey) || "";
        }
        const authorization = ctx.request.header["authorization"];
        const parts = authorization.split(" ");
        if (parts.length === 2) {
            const scheme = parts[0];
            const token = parts[1];
            if (/^Bearer$/i.test(scheme)) {
                return token;
            }
        }
        if (!options.passthrough) {
            throw new UnauthorizedError("错误的token格式，请重新登陆");
        }
        return "";
    };
    const tokenValidateHandler = koaJWT.default({
        secret,
        cookie: tokenOption.type === "cookie" ? tokenOption.key : undefined,
        tokenKey: "token",
        key: "payload",
        passthrough: true,
        getToken,
        isRevoked: async () => false,
    });
    return _a = class JWTMiddleware {
            /**
             *
             *
             * @param {Context} ctx
             * @param {*} _next
             */
            async use(ctx, _next) {
                const next = async (err) => {
                    const payload = ctx.state[payloadKey];
                    const token = ctx.state[tokenKey];
                    if (ctx.state.token) {
                        if (token && handleInsertPayload) {
                            ctx.state[payloadKey] = handleInsertPayload(payload);
                        }
                    }
                    return _next(err);
                };
                await tokenValidateHandler(ctx, () => Promise.resolve());
                if (!ctx.state.token) {
                    if (passthrough) {
                        return next();
                    }
                    // 如果没有获取到ctx.state.token的情况下，有可能是token失效了，需要重签
                    const token = getToken(ctx, {
                        passthrough: true,
                        secret,
                    });
                    const state = await resignToken(ctx, token);
                    if (state) {
                        ctx.state = state;
                        return next();
                    }
                }
                if (!(ctx.state.token || passthrough)) {
                    throw new UnauthorizedError("请重新登录");
                }
                return next();
            }
        },
        _a.injectToken = (ctx, payload) => {
            const _payload = validatePayload(payload);
            const token = signToken(_payload);
            injectTokenToResponse(ctx, token, payload);
        },
        _a.currentUserChecker = async (action) => {
            const payload = action.context.state.payload;
            // 修复前版本缩写难以理解的问题
            // 与后端字段名统一
            return payload;
        },
        _a;
}
exports.createJWTMiddleware = createJWTMiddleware;
//# sourceMappingURL=factory.js.map
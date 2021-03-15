import * as rtc from "routing-controllers";
import * as koa from "koa";
import * as ct from "class-transformer";
declare type ClassConstructor<T> = ct.ClassConstructor<T>;
declare type KoaMiddlewareInterface = rtc.KoaMiddlewareInterface;
declare type KoaContext = koa.Context;
export interface JWTPayload {
    iat?: number;
    exp?: number;
}
export interface DecodeInfomation {
    header?: object;
    payload: JWTPayload;
}
export interface TokenCookie {
    type: "cookie";
    key: string;
    domain?: string;
    httpOnly?: boolean;
    path?: string;
}
export interface TokenHeader {
    type: "header";
}
interface Options<T = any> {
    token: TokenCookie | TokenHeader;
    ctxState: {
        tokenKey?: string;
        payloadKey?: string;
    };
    passthrough?: boolean;
    secret: string;
    expiresIn?: string;
    handleInsertPayload?: <A extends T>(payload: T) => A;
    handleValidatePayload?: (payload: T) => boolean;
}
/**
 * 创建一个JWT校验中间件
 *
 * @export
 * @template T
 * @param {Options<T>} options
 * @return {Middleware}
 */
export declare function createJWTMiddleware<T = any>(options: Options<T>): ClassConstructor<KoaMiddlewareInterface> & {
    injectToken: (ctx: KoaContext, payload: T) => void;
    currentUserChecker: (action: rtc.Action) => Promise<T>;
};
export {};

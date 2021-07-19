import * as rtc from "routing-controllers";
import * as koa from "koa";
import * as koaJWT from "koa-jwt";
import { sign, decode } from "jsonwebtoken";
import {
  DEFAULT_STATE_PAYLOAD_KEY,
  DEFAULT_STATE_TOKEN_KEY,
  DEFAULT_TOKEN_EXPIRED,
  DEFAULT_TOKEN_EXPIRED_AUTO_REFRESH,
} from "./const";
import type * as ct from "class-transformer";
import { timeSpan } from "./util";

export type ClassConstructor<T> = ct.ClassConstructor<T>;

type KoaMiddlewareInterface = rtc.KoaMiddlewareInterface;
type KoaContext = koa.Context;

interface Payload {
  [propname: string]: any;
}

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
  // key?: string;
  // resKey?: string;
}

interface Options<T = any> {
  token: TokenCookie | TokenHeader;
  ctxState: {
    tokenKey?: string;
    payloadKey?: string;
  };
  passthrough?: boolean;
  secret: string;
  /**
   * 单个 token 的有效期
   *
   * @type {(string | number)}
   * @memberof Options
   */
  expiresIn?: string | number;
  /**
   * token 自动重签的有效期
   *
   * @type {(string | number)}
   * @memberof Options
   */
  expiresInAutoRefresh?: string | number;
  handleInsertPayload?: <A extends T>(payload: T) => A;
  handleValidatePayload?: (payload: T) => boolean;
}

const UnauthorizedError = rtc.UnauthorizedError;

/**
 * 创建一个JWT校验中间件
 *
 * @export
 * @template T
 * @param {Options<T>} options
 * @return {Middleware}
 */
export function createJWTMiddleware<T = any>(
  options: Options<T> | (() => Options<T>)
): ClassConstructor<KoaMiddlewareInterface> & {
  injectToken: (ctx: KoaContext, payload: T) => void;
  currentUserChecker: (action: rtc.Action) => Promise<T>;
  resignToken: (ctx: KoaContext, token: string) => Promise<any>;
} {
  const getOptions = (): Options<T> => {
    const {
      passthrough = false,
      secret,
      token: tokenOption,
      ctxState: {
        tokenKey = DEFAULT_STATE_TOKEN_KEY,
        payloadKey = DEFAULT_STATE_PAYLOAD_KEY,
      } = {},
      // cookie,
      expiresIn = DEFAULT_TOKEN_EXPIRED,
      expiresInAutoRefresh = DEFAULT_TOKEN_EXPIRED_AUTO_REFRESH,
      handleInsertPayload,
      handleValidatePayload,
    } = typeof options === "function" ? options() : options;

    return {
      passthrough,
      secret,
      token: tokenOption,
      ctxState: { tokenKey, payloadKey },
      expiresIn,
      expiresInAutoRefresh,
      handleInsertPayload,
      handleValidatePayload,
    };
  };

  /**
   * 签发token
   *
   * @param {payload} payload
   * @param {Options<T>} options
   * @return {string}
   */
  const signToken = (payload: T, options: Options<T>) => {
    const { secret, expiresIn } = options;

    const { ..._payload } = payload as any;
    delete _payload.exp;
    delete _payload.iat;

    return sign(_payload as any, secret, { expiresIn });
  };

  /**
   * 校验JWT携带的 Payload 完整性
   *
   * @param {T} payload
   * @param {Options<T>} options
   * @return {T}
   */
  const validatePayload = (payload: T, options: Options<T>) => {
    const { handleValidatePayload } = options;

    if (handleValidatePayload && !handleValidatePayload(payload)) {
      throw new UnauthorizedError(
        `token payload 数据不完整：${JSON.stringify(payload || {})}`
      );
    }
    return { ...payload };
  };

  /**
   * 将生成的令牌填充到 http response
   *
   * @param {KoaContext} ctx
   * @param {string} token
   * @param {Payload} payload
   * @param {Options<T>} options
   */
  const injectTokenToResponse = (
    ctx: KoaContext,
    token: string,
    payload: Payload,
    options: Options<T>
  ) => {
    const { token: tokenOption } = options;

    if (tokenOption.type === "cookie") {
      ctx.cookies.set(tokenOption.key, token, { httpOnly: true });
      return;
    }
    ctx.set("Set-Authorization", `Bearer ${token}`);
  };

  /**
   * token 重签处理
   *
   * @param {KoaContext} ctx
   * @param {string} token
   * @param {Options<T>} options
   * @return {Promise<contextState>}
   */
  const resignToken = async (
    ctx: KoaContext,
    token: string,
    options?: Options<T>
  ): Promise<any> => {
    const {
      expiresInAutoRefresh,
      ctxState: { tokenKey, payloadKey },
    } = options || getOptions();

    const decodeInfomation = <
      {
        header?: object;
        payload: { iat?: number; exp?: number } & T;
      } | null
    >decode(token, { complete: true, json: true });

    if (!!decodeInfomation) {
      let { payload } = decodeInfomation;

      const now = Date.now() / 1000;
      const exp = <number>payload.exp;
      if (now > exp && now < timeSpan(expiresInAutoRefresh, exp)) {
        // 清理冗余信息后再签发token
        payload = validatePayload(payload, options);
        const token = signToken(payload, options);
        injectTokenToResponse(ctx, token, payload, options);
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
   * @param {Options<T>} options
   * @param {KoaContext} ctx
   * @param {koaJWT.Options} jwtOptions
   * @return {string}
   */
  const getToken = (
    options: Options<T>,
    ctx: KoaContext,
    jwtOptions: koaJWT.Options
  ): string => {
    const {
      ctxState: { tokenKey },
    } = options;

    if (
      !ctx.request ||
      !ctx.request.header ||
      !ctx.request.header["authorization"]
    ) {
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

    return "";
  };

  const getTokenValidateHandler = (options: Options<T>) => {
    const { token: tokenOption, secret } = options;
    return koaJWT.default({
      secret,
      cookie: tokenOption.type === "cookie" ? tokenOption.key : undefined,
      tokenKey: "token",
      key: "payload",
      passthrough: true,
      getToken: getToken.bind(null, options),
      isRevoked: async () => false,
    });
  };

  return class JWTMiddleware {
    private getOptions = getOptions;

    static resignToken = resignToken;
    static injectToken = (ctx: KoaContext, payload: T) => {
      const options = getOptions();
      const _payload = validatePayload(payload, options);
      const token = signToken(_payload, options);
      injectTokenToResponse(ctx, token, payload, options);
    };

    static currentUserChecker = async (action: rtc.Action): Promise<T> => {
      const options = getOptions();
      const payload = <T>action.context.state[options.ctxState.payloadKey];
      // 修复前版本缩写难以理解的问题
      // 与后端字段名统一
      return payload;
    };

    /**
     *
     *
     * @param {Context} ctx
     * @param {*} _next
     */
    async use(
      ctx: KoaContext,
      _next: (err?: any) => Promise<any>
    ): Promise<any> {
      const options = this.getOptions();
      const {
        secret,
        ctxState: { payloadKey, tokenKey },
        handleInsertPayload,
        passthrough,
      } = options;

      const next = async (err?: any): Promise<any> => {
        const payload = ctx.state[payloadKey];
        const token = ctx.state[tokenKey];
        if (ctx.state.token) {
          if (token && handleInsertPayload) {
            ctx.state[payloadKey] = handleInsertPayload(payload);
          }
        }
        return _next(err);
      };

      await getTokenValidateHandler(options)(ctx, () => Promise.resolve());

      if (!ctx.state.token) {
        if (passthrough) {
          return next();
        }
        // 如果没有获取到ctx.state.token的情况下，有可能是token失效了，需要重签
        const token = getToken(options, ctx, {
          passthrough: true,
          secret,
        });
        const state = await resignToken(ctx, token, options);
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
  };
}

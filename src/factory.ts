import * as rtc from "routing-controllers";
import * as koa from "koa";
import * as koaJWT from "koa-jwt";
import { sign, decode } from "jsonwebtoken";
import {
  DEFAULT_STATE_PAYLOAD_KEY,
  DEFAULT_STATE_TOKEN_KEY,
  DEFAULT_TOKEN_EXPIRED,
} from "./const";
import * as ct from "class-transformer";

type ClassConstructor<T> = ct.ClassConstructor<T>;
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
  expiresIn?: string;
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
  options: Options<T>
): ClassConstructor<KoaMiddlewareInterface> & {
  injectToken: (ctx: KoaContext, payload: T) => void;
  currentUserChecker: (action: rtc.Action) => Promise<T>;
} {
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
    handleInsertPayload,
    handleValidatePayload,
  } = options;

  /**
   * 签发token
   *
   * @param {payload} payload
   *
   * 如果是顾问身份登录登录态的有效期为24小时，否则有效期为两小时
   * @return {string}
   */
  const signToken = (payload: T) => {
    const { ..._payload } = payload as any;
    delete _payload.exp;

    return sign(_payload as any, secret, { expiresIn });
  };

  /**
   * 校验JWT携带的 Payload 完整性
   *
   * @param {Payload} payload
   * @return {Payload}
   */
  const validatePayload = (payload: T) => {
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
   * @param {Context} ctx
   * @param {string} token
   * @param {Payload} payload
   */
  const injectTokenToResponse = (
    ctx: KoaContext,
    token: string,
    payload: Payload
  ) => {
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
  const resignToken = async (ctx: KoaContext, token: string): Promise<any> => {
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
  const getToken = (ctx: KoaContext, options: koaJWT.Options): string => {
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

  return class JWTMiddleware implements KoaMiddlewareInterface {
    static injectToken = (ctx: KoaContext, payload: T) => {
      const _payload = validatePayload(payload);
      const token = signToken(_payload);
      injectTokenToResponse(ctx, token, payload);
    };

    static currentUserChecker = async (action: rtc.Action): Promise<T> => {
      const payload = <T>action.context.state.payload;
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
  };
}

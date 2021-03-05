import { KoaMiddlewareInterface, UnauthorizedError } from "routing-controllers";
import { Context } from "koa";
import * as koaJWT from "koa-jwt";
import { sign, decode } from "jsonwebtoken";
import {
  DEFAULT_STATE_PAYLOAD_KEY,
  DEFAULT_STATE_TOKEN_KEY,
  DEFAULT_TOKEN_EXPIRED,
} from "./const";

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

interface Options<T = any> {
  passthrough?: boolean;
  secret: string;
  cookie?: string;
  expiresIn?: string;
  tokenKey?: string;
  payloadKey?: string;
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
export function createJWTMiddleware<T = any>(options: Options<T>) {
  const {
    passthrough = false,
    secret,
    cookie,
    expiresIn = DEFAULT_TOKEN_EXPIRED,
    tokenKey = DEFAULT_STATE_TOKEN_KEY,
    payloadKey = DEFAULT_STATE_PAYLOAD_KEY,
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
  const signToken = (payload: T) => sign(payload as any, secret, { expiresIn });

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
    ctx: Context,
    token: string,
    payload: Payload
  ) => {
    if (cookie) {
      ctx.cookies.set(cookie, token, { httpOnly: true });
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
  const resignToken = async (ctx: Context, token: string): Promise<any> => {
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
  const getToken = (ctx: Context, options: koaJWT.Options): string => {
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
    cookie,
    tokenKey: "token",
    key: "payload",
    passthrough: true,
    getToken,
    isRevoked: async () => false,
  });

  return class JWTMiddleware implements KoaMiddlewareInterface {
    /**
     *
     *
     * @param {Context} ctx
     * @param {*} _next
     */
    async use(ctx: Context, _next: (err?: any) => Promise<any>): Promise<any> {
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

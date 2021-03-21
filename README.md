# jwt-rt-middleware

适用于`routing-controllers`的JWT中间件

## Installation
```
npm install --save jwt-rt-middleware
// or
yarn add jwt-rt-middleware
```



## Quick Start

```typescript

import { createJWTMiddleware } from 'jwt-rt-middleware'
// 指定JWT中携带的信息类型
interface CurrentUser {
  uuid: string;
  user_name: string;
}

// 创建一个服务器专属的JWT中间件
export const JWTMiddleware = createJWTMiddleware<CurrentUser>({
  secret: 'YOUR_JWT_SECRET',
  expiresIn: '2h',
  token: { type: 'header' }
})
```

现在你可以在任意层级的使用它进行JWT校验

```typescript
import { JsonController, UseBefore, Get } from "routing-controllers";
import { JWTMiddleware } from "../middleware"

@JsonController('/auth')
export default class UserController {
  @Get('/test')
  @UseBefore(JWTMiddleware)
  async test() {
    // ...
  }
}
```

调用 `${prefix}/auth/test` 接口测试接入状况

### token 签发
```typescript
import { JsonController, UseBefore, Post, Ctx } from "routing-controllers";
import { Context } from "koa";
import { JWTMiddleware } from "../middleware"

@JsonController('/auth')
export default class UserController {
  @Post('/login')
  async login(
    @BodyParam('account', { required: true }) account: string,
    @BodyParam('password', { required: true }) password: string,
    @Ctx() ctx: Context
  ) {
    // 验证密码并查询用户信息
    const { data: user } = await postSomeLoginMethod({ account, password })

    // 调用静态方法自动签发并将 token 注入 ctx.response
    JWTMiddleware.injectToken(ctx, user)

    return { code: 0 }
  }
}

```

## Configuration
### createJWTMiddleware 参数
|name|required|type|default|example|description|
|:-|:-|:-|:-|:-|:-|
|token|true|TokenOptions|--|`{ type: "header" }`|设置token的注入方式，设置type 为 header 则表示使用规范的`JWT Authorization`|
|ctxState|false|ctxStateOptions|`{ tokenKey: "token", payloadKey: "payload" }`|见下表|设置JWT在接口上下文的存储方式，当前设置可以通过`ctx.state.token` 获取`token`，通过`ctx.state.payload` 获取token中携带的信息|
|passthrough|false|boolean|false|true|设置接口是否允许跳过检查|
|secret|true|string|--|"some secret"|JWT 签发密钥|
|expiresIn|false|string|"2h"|"2h"|签发的JWT的过期时间|
|handleInsertPayload|false|`<A extends T>(payload: T) => A`|--|--|在`token`签发后添加一些增量信息到`payload`里，方便接口获取|
|handleValidatePayload|false|(payload: T) => boolean|--|--|设置校验`payload`合法的函数|

### tokenOptions
```typescript
// 当 type 为 cookie 时，中间件将会把token设置到cookie中
export interface TokenCookie {
  type: "cookie";
  /** 将要设置的 cookie key */ 
  key: string;
  /** 指定cookie的域名 */
  domain?: string;
  /** 指定cookie是否能被客户端代码中获取 */
  httpOnly?: boolean;
  /** 指定cookie生效的页面路径 */
  path?: string;
}

// 当 type 为 header 时，中间件将会按标准形式设置到 Authorization 头部
export interface TokenHeader {
  type: "header";
}

```

### ctxStateOptions
|name|required|type|default|description|
|:-|:-|:-|:-|:-|
|tokenKey|false|string|"token"|指定签发的`token`存放于请求上下文的位置`ctx.state[tokenKey]`|
|payloadKey|false|string|"payload"|指定`token`中的信息存放于请求上下文的位置`ctx.state[payloadKey]`

### 目前支持
- `koa` 类型的中间件
- JWT 的简单校验与签发
- 通过`cookie`的方式获取与签发`Token`

### 计划支持
- 提供`express`的中间件
- 更加详细的签发参数

### warning
- 当前为开发初期，可能会有用法上的微调，将在1.0的版本中提供稳定的API。

**欢迎在使用的过程中提交issue反馈，感谢支持**
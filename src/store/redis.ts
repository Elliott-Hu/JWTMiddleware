import { SecretBuffer, Store } from "../types";
import * as Redis from "redis";
import { ClassConstructor } from "class-transformer";
import { uniqBy } from "../util";

interface RedisOptions {
  host: string;
  port: number;
  password: string;
  key: string;
}

export const createStoreRedis = (
  opts: RedisOptions
): ClassConstructor<Store> => {
  /**
   * 缓存 -- redis
   *
   * @export
   * @class StoreRedis
   * @extends {Store}
   */
  return class StoreRedis extends Store {
    private count: number = 1;
    private store: SecretBuffer[] = [];
    private redis: Redis.RedisClient;
    /**
     * Creates an instance of StoreMemory.
     *
     * @param {*} options
     * @memberof StoreMemory
     */
    constructor(options: any) {
      super();
      this.count = options.count;
      this.redis = Redis.createClient({
        host: opts.host,
        port: opts.port,
        password: opts.password,
      });

      this.getStorageAsync();
    }

    /**
     * 异步获取 redis 里的缓存
     *
     * @return {Promise<SecretBuffer>}
     */
    getStorageAsync(): Promise<SecretBuffer[]> {
      return new Promise((r) => {
        this.redis.get(opts.key, (error, value) => {
          console.log("redis key", value);
          this.store = (() => {
            try {
              return JSON.parse(value) || [];
            } catch (error) {
              console.log("redis error", error);
              return [];
            }
          })();
        });
        r(this.store);
      });
    }

    /**
     * 获取缓存
     *
     * @return {SecretBuffer[]}
     */
    getStorage(): SecretBuffer[] {
      return this.store;
    }

    /**
     * 新secret缓存入列
     *
     * @param {SecretBuffer[]} secretBuffer
     */
    enqueue(secretBuffer: SecretBuffer[]) {
      this.getStorageAsync().then((buffers) => {
        const store = uniqBy([...secretBuffer, ...buffers], "secret").slice(
          0,
          this.count
        );
        this.redis.set(opts.key, JSON.stringify(store));
        this.store = store;
      });
    }
  };
};

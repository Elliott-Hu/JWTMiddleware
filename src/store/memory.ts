import { timeSpan } from "../util";
import { SecretBuffer, Store } from "../types";

/**
 * 缓存 -- memory
 *
 * @export
 * @class StoreMemory
 * @extends {Store}
 */
export class StoreMemory extends Store {
  private count: number = 1;
  private store: SecretBuffer[] = [];
  private expiresIn: number | string;

  /**
   * Creates an instance of StoreMemory.
   *
   * @param {*} options
   * @memberof StoreMemory
   */
  constructor(options: any) {
    super();
    this.expiresIn = options.expiresIn;
    this.count = options.count;
    this.store = options.store || [];
  }
  /**
   * 获取缓存
   *
   * @return {SecretBuffer[]}
   * @memberof StoreMemory
   */
  getStorage(): SecretBuffer[] {
    return this.store;
  }
  /**
   * 新secret缓存入列
   *
   * @param {SecretBuffer[]} secretBuffer
   * @memberof StoreMemory
   */
  enqueue(secretBuffer: SecretBuffer[]) {
    // 刷新上一个 secret 的超时时间
    const timeout = timeSpan(this.expiresIn, Date.now() / 1000);
    const buffers = this.store.map((item, index) =>
      !!index ? item : { ...item, timeout }
    );

    this.store = [...secretBuffer, ...buffers].slice(this.count);
  }
}

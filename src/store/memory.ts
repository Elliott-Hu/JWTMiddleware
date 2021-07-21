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
  /**
   * Creates an instance of StoreMemory.
   *
   * @param {*} options
   * @memberof StoreMemory
   */
  constructor(options: any) {
    super();
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
    this.store.unshift(...secretBuffer);
    this.store = this.store.slice(this.count);
  }
}

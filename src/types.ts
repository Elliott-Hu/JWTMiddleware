export type SecretBuffer = {
  secret: string;
  timeout?: number;
};

/**
 * 缓存抽象类
 *
 * @abstract
 * @class Store
 */
export abstract class Store {
  abstract getStorage(): SecretBuffer[];
  abstract enqueue(secretBuffer: SecretBuffer[]): void;
}

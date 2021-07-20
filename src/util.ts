import ms from "ms";

/**
 * 通过有效期与指定时间点输出过期时间点
 *
 * @export
 * @param {(string | number)} time
 * @param {number} iat
 * @return {string | undefined}
 */
export function timeSpan(time: string | number, iat?: number) {
  const timestamp = iat || Math.floor(Date.now() / 1000);

  if (typeof time === "string") {
    const milliseconds = ms(time);
    if (typeof milliseconds === "undefined") {
      return;
    }
    return Math.floor(timestamp + milliseconds / 1000);
  } else if (typeof time === "number") {
    return timestamp + time;
  } else {
    return;
  }
}

/**
 * 简单数组去重
 *
 * @export
 * @param {(Array<any>)} arr
 * @return {(Array<any>)}
 */
export function uniq(arr: any[]): any[] {
  return Array.from(new Set(arr));
}

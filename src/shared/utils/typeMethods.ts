/** Recursively strip function properties from a type */
export type DataOnly<T> =
  // arrays: recurse into element type
  T extends (infer U)[]
    ? DataOnly<U>[]
    : T extends object
      ? {
          [K in keyof T as T[K] extends (...args: any[]) => any ? never : K]:
            DataOnly<T[K]>;
        }
      : T;
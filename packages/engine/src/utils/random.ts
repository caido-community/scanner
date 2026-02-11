const ALPHA_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

export const createRandomToken = (
  random: () => number = Math.random,
): string => {
  return random().toString(36).substring(2, 15);
};

export const createPrefixedRandomId = (
  prefix: string,
  random: () => number = Math.random,
): string => {
  return `${prefix}${createRandomToken(random)}`;
};

export function generateRandomString(length: number): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    result += ALPHA_CHARS.charAt(
      Math.floor(Math.random() * ALPHA_CHARS.length),
    );
  }
  return result;
}

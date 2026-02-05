const ALPHA_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

export function generateRandomString(length: number): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    result += ALPHA_CHARS.charAt(
      Math.floor(Math.random() * ALPHA_CHARS.length),
    );
  }
  return result;
}

export function generateCanary(): string {
  const chars = "0123456789abcdef";
  let result = "";
  for (let i = 0; i < 8; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

export function containsCanary(text: string, canary: string): boolean {
  return text.includes(canary);
}

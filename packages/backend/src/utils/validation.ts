import { Result } from "engine";
import type { Result as ResultType } from "shared";
import { ZodError, type ZodType } from "zod";

export function validateInput<T>(
  schema: ZodType<T>,
  input: unknown,
): ResultType<T> {
  try {
    const result = schema.parse(input);
    return Result.ok(result);
  } catch (err) {
    if (err instanceof ZodError) {
      const errorMessages = err.issues.map((e) => {
        const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
        return `${path}${e.message}`;
      });
      return Result.err(`Validation failed: ${errorMessages.join(", ")}`);
    }
    return Result.err("Invalid input");
  }
}

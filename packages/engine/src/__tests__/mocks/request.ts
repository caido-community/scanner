import {
  type Body,
  type Request,
  type RequestRaw,
  type RequestSpec,
  type RequestSpecRaw,
} from "caido:utils";

import { createMockRequestSpec } from "./request-spec";
import { type MockRequestData } from "./types";

export class MockBody implements Body {
  private data: string;

  constructor(data: string | Array<number> | Uint8Array) {
    if (typeof data === "string") {
      this.data = data;
    } else if (Array.isArray(data)) {
      this.data = new TextDecoder().decode(new Uint8Array(data));
    } else {
      this.data = new TextDecoder().decode(data);
    }
  }

  get length(): number {
    return new TextEncoder().encode(this.data).length;
  }

  toText(): string {
    return this.data;
  }

  toJson(): unknown {
    return JSON.parse(this.data);
  }

  toRaw(): Uint8Array {
    return new TextEncoder().encode(this.data);
  }
}

export class MockRequestRaw implements RequestRaw {
  private data: string;

  constructor(data: string) {
    this.data = data;
  }

  toText(): string {
    return this.data;
  }

  toBytes(): Uint8Array {
    return new TextEncoder().encode(this.data);
  }
}

export class MockRequest implements Request {
  private mockData: Required<MockRequestData>;

  buildURL(data: MockRequestData): string {
    const protocol = (data.tls ?? true) ? "https" : "http";
    const port = data.port ?? ((data.tls ?? true) ? 443 : 80);
    const path = data.path ?? "/";
    const query = data.query ?? "";
    return `${protocol}://${data.host}:${port}${path}${query !== "" ? `?${query}` : ""}`;
  }

  constructor(data: MockRequestData) {
    this.mockData = {
      id: data.id,
      host: data.host,
      port: data.port ?? ((data.tls ?? true) ? 443 : 80),
      tls: data.tls ?? true,
      method: data.method ?? "GET",
      path: data.path ?? "/",
      query: data.query ?? "",
      url: data.url ?? this.buildURL(data),
      headers: data.headers ?? {},
      body: data.body ?? "",
      createdAt: data.createdAt ?? new Date(),
    };
  }

  getId(): string {
    return this.mockData.id;
  }

  getHost(): string {
    return this.mockData.host;
  }

  getPort(): number {
    return this.mockData.port;
  }

  getTls(): boolean {
    return this.mockData.tls;
  }

  getMethod(): string {
    return this.mockData.method;
  }

  getPath(): string {
    return this.mockData.path;
  }

  getQuery(): string {
    return this.mockData.query;
  }

  getUrl(): string {
    return this.mockData.url;
  }

  getHeaders(): Record<string, Array<string>> {
    return this.mockData.headers;
  }

  getHeader(name: string): Array<string> | undefined {
    const lowerName = name.toLowerCase();
    const headers = this.mockData.headers;

    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === lowerName) {
        return value;
      }
    }
    return undefined;
  }

  getBody(): Body | undefined {
    return this.mockData.body ? new MockBody(this.mockData.body) : undefined;
  }

  getRaw(): RequestRaw {
    const requestLine = `${this.mockData.method} ${this.mockData.path}${this.mockData.query ? `?${this.mockData.query}` : ""} HTTP/1.1`;
    const headerLines = Object.entries(this.mockData.headers).flatMap(
      ([name, values]) => values.map((value) => `${name}: ${value}`),
    );
    const start = [requestLine, ...headerLines].join("\r\n");
    const raw =
      this.mockData.body !== ""
        ? `${start}\r\n\r\n${this.mockData.body}`
        : `${start}\r\n\r\n`;
    return new MockRequestRaw(raw);
  }

  getCreatedAt(): Date {
    return this.mockData.createdAt;
  }

  toSpec(): RequestSpec {
    const headers = Object.fromEntries(
      Object.entries(this.mockData.headers).map(([name, values]) => [
        name,
        [...values],
      ]),
    );

    return createMockRequestSpec({
      host: this.mockData.host,
      port: this.mockData.port,
      tls: this.mockData.tls,
      method: this.mockData.method,
      path: this.mockData.path,
      query: this.mockData.query,
      headers,
      body: this.mockData.body,
    });
  }

  toSpecRaw(): RequestSpecRaw {
    throw new Error("toSpecRaw not implemented in mock");
  }
}

export const createMockRequest = (data: MockRequestData): Request => {
  return new MockRequest(data);
};

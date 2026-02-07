import {
  type Body,
  type ConnectionInfo,
  type RequestSpec,
  type RequestSpecRaw,
} from "caido:utils";

import { MockBody } from "./request";

export type MockRequestSpecData = {
  host: string;
  port?: number;
  tls?: boolean;
  method?: string;
  path?: string;
  query?: string;
  headers?: Record<string, string[]>;
  body?: string;
};

export class MockRequestSpec implements RequestSpec {
  private host: string;
  private port: number;
  private tls: boolean;
  private method: string;
  private path: string;
  private query: string;
  private headers: Record<string, string[]>;
  private body?: string;
  private id: number = Math.random() * 1000000;

  constructor(urlOrData: string | MockRequestSpecData) {
    if (typeof urlOrData === "string") {
      const url = new URL(urlOrData);
      this.host = url.hostname;
      this.port = url.port
        ? parseInt(url.port)
        : url.protocol === "https:"
          ? 443
          : 80;
      this.tls = url.protocol === "https:";
      this.method = "GET";
      this.path = url.pathname || "/";
      this.query = url.search.slice(1);
      this.headers = { Host: [this.host] };
      this.body = undefined;
    } else {
      this.host = urlOrData.host;
      this.port = urlOrData.port ?? ((urlOrData.tls ?? true) ? 443 : 80);
      this.tls = urlOrData.tls ?? true;
      this.method = urlOrData.method ?? "GET";
      this.path = urlOrData.path ?? "/";
      this.query = urlOrData.query ?? "";
      this.headers = urlOrData.headers ?? { Host: [this.host] };
      this.body = urlOrData.body;
    }
  }

  static parse(bytes: never): RequestSpec {
    throw new Error("RequestSpec.parse not implemented in mock");
  }

  getHost(): string {
    return this.host;
  }

  setHost(host: string): void {
    this.host = host;
    this.headers["Host"] = [host];
  }

  getPort(): number {
    return this.port;
  }

  setPort(port: number): void {
    this.port = port;
  }

  getTls(): boolean {
    return this.tls;
  }

  setTls(tls: boolean): void {
    this.tls = tls;
  }

  getId(): string {
    return this.id.toString();
  }

  getUrl(): string;
  getUrl(options: { raw: true }): Uint8Array;
  getUrl(options?: { raw?: boolean }): string | Uint8Array {
    const protocol = this.tls ? "https" : "http";
    const isDefaultPort =
      (this.tls && this.port === 443) || (!this.tls && this.port === 80);
    const port = isDefaultPort ? "" : `:${this.port}`;
    const query = this.query.length > 0 ? `?${this.query}` : "";
    const url = `${protocol}://${this.host}${port}${this.path}${query}`;

    if (options?.raw === true) {
      return new TextEncoder().encode(url);
    }

    return url;
  }

  getInfo(): ConnectionInfo {
    return {
      host: this.host,
      port: this.port,
      tls: this.tls,
      sni: this.host,
    };
  }

  getMethod(): string;
  getMethod(options: { raw: true }): Uint8Array;
  getMethod(options?: { raw?: boolean }): string | Uint8Array {
    if (options?.raw === true) {
      return new TextEncoder().encode(this.method);
    }
    return this.method;
  }

  setMethod(method: string | Uint8Array): void {
    if (typeof method === "string") {
      this.method = method;
    } else {
      this.method = new TextDecoder().decode(method);
    }
  }

  getPath(): string;
  getPath(options: { raw: true }): Uint8Array;
  getPath(options?: { raw?: boolean }): string | Uint8Array {
    if (options?.raw === true) {
      return new TextEncoder().encode(this.path);
    }
    return this.path;
  }

  setPath(path: string | Uint8Array): void {
    if (typeof path === "string") {
      this.path = path;
    } else {
      this.path = new TextDecoder().decode(path);
    }
  }

  getQuery(): string;
  getQuery(options: { raw: true }): Uint8Array;
  getQuery(options?: { raw?: boolean }): string | Uint8Array {
    if (options?.raw === true) {
      return new TextEncoder().encode(this.query);
    }
    return this.query;
  }

  setQuery(query: string | Uint8Array): void {
    if (typeof query === "string") {
      this.query = query;
    } else {
      this.query = new TextDecoder().decode(query);
    }
  }

  getHeaders(): Record<string, Array<string>> {
    return this.headers;
  }

  getHeader(name: string): Array<string> | undefined {
    const lowerName = name.toLowerCase();

    for (const [key, value] of Object.entries(this.headers)) {
      if (key.toLowerCase() === lowerName) {
        return value;
      }
    }
    return undefined;
  }

  setHeader(name: string, value: string): void {
    this.headers[name] = [value];
  }

  removeHeader(name: string): void {
    delete this.headers[name];
  }

  getBody(): Body | undefined {
    return this.body !== undefined ? new MockBody(this.body) : undefined;
  }

  setBody(
    body: Body | string | Array<number> | Uint8Array,
    options?: { updateContentLength: boolean },
  ): void {
    if (body instanceof MockBody) {
      this.body = body.toText();
    } else if (typeof body === "string") {
      this.body = body;
    } else if (Array.isArray(body)) {
      this.body = new TextDecoder().decode(new Uint8Array(body));
    } else if (body instanceof Uint8Array) {
      this.body = new TextDecoder().decode(body);
    } else {
      this.body = body.toText();
    }
  }

  setRaw(raw: never): RequestSpecRaw {
    throw new Error("setRaw not implemented in mock");
  }

  getRaw(): RequestSpecRaw {
    throw new Error("getRaw not implemented in mock");
  }
}

export const createMockRequestSpec = (
  data: MockRequestSpecData,
): RequestSpec => {
  return new MockRequestSpec(data);
};

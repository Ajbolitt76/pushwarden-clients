/** A relay frame delivered to this device (PROTOCOL.md §3). */
export interface RelayMessage {
  from: string;
  fromPk: string;
  body: string;
}

const PING_INTERVAL_MS = 20_000;
const AUTH_TIMEOUT_MS = 10_000;

/** `https://relay.example` → `wss://relay.example/v1/ws`. Plain http only for localhost. */
export function relayBaseUrl(input: string): URL {
  const url = new URL(input);
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error("relay URL must use https");
  }
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url;
}

/**
 * One authenticated WebSocket to the relay. Opened for the duration of a pairing or fill and
 * closed afterwards; the phone only ever answers, so nothing needs a standing connection.
 */
export class L2RelayConnection {
  private ws?: WebSocket;
  private pinger?: ReturnType<typeof setInterval>;
  private handlers = new Set<(m: RelayMessage) => void>();

  constructor(
    private readonly relayUrl: string,
    private readonly token: string,
  ) {}

  async open(): Promise<void> {
    const url = relayBaseUrl(this.relayUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = "/v1/ws";
    const ws = new WebSocket(url.toString());
    this.ws = ws;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("relay auth timeout")), AUTH_TIMEOUT_MS);
      ws.onopen = () => ws.send(JSON.stringify({ t: "auth", token: this.token }));
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error("relay connection failed"));
      };
      ws.onclose = () => {
        clearTimeout(timer);
        reject(new Error("relay closed the connection"));
      };
      ws.onmessage = (e) => {
        const f = parseFrame(e.data);
        if (f?.t === "ready") {
          clearTimeout(timer);
          resolve();
        } else if (f?.t === "error") {
          clearTimeout(timer);
          reject(new Error(`relay: ${String(f.code)}`));
        }
      };
    });
    ws.onmessage = (e) => {
      const f = parseFrame(e.data);
      if (
        f?.t === "msg" &&
        typeof f.from === "string" &&
        typeof f.fromPk === "string" &&
        typeof f.body === "string"
      ) {
        for (const h of this.handlers) {
          h({ from: f.from, fromPk: f.fromPk, body: f.body });
        }
      }
    };
    ws.onclose = () => this.stopPing();
    // Message traffic keeps an MV3 service worker alive; protocol-level pings don't.
    this.pinger = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ t: "ping" }));
      }
    }, PING_INTERVAL_MS);
  }

  onMessage(handler: (m: RelayMessage) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  send(to: string, body: string): void {
    this.sendFrame({ t: "send", to, body });
  }

  close(): void {
    this.stopPing();
    this.handlers.clear();
    this.ws?.close();
    this.ws = undefined;
  }

  private sendFrame(frame: object) {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      throw new Error("relay connection is not open");
    }
    this.ws.send(JSON.stringify(frame));
  }

  private stopPing() {
    if (this.pinger) {
      clearInterval(this.pinger);
      this.pinger = undefined;
    }
  }
}

function parseFrame(data: unknown): Record<string, unknown> | null {
  if (typeof data !== "string") {
    return null;
  }
  try {
    const f = JSON.parse(data);
    return f && typeof f === "object" ? f : null;
  } catch {
    return null;
  }
}

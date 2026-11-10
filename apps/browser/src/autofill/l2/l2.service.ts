import { firstValueFrom } from "rxjs";

import {
  StateDefinition,
  StateProvider,
  UserKeyDefinition,
} from "@bitwarden/common/platform/state";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";

import { isL2Value } from "./l2-cipher";
import { L2RelayConnection, relayBaseUrl } from "./l2-relay.connection";
import {
  checkQrProof,
  commitment,
  decryptField,
  fingerprintPhrase,
  getSodium,
  KEY_FIELD_NAME,
  Message,
  open,
  originAllowed,
  randomNonce,
  seal,
  unwrapKey,
  WrongPasswordError,
} from "./protocol";

/** How the user unlocks one L2 fill. The password is used once and never stored. */
export type L2Unlock = { mode: "password"; password: string } | { mode: "phone" };

export const L2ErrorCode = Object.freeze({
  NotPaired: "notPaired",
  WrongPassword: "wrongPassword",
  NoKeyItem: "noKeyItem",
  MultipleKeyItems: "multipleKeyItems",
  HostNotAllowed: "hostNotAllowed",
  PhoneDenied: "phoneDenied",
  PhoneRejected: "phoneRejected",
  Timeout: "timeout",
  Relay: "relayError",
  Pairing: "pairingFailed",
  Undecryptable: "undecryptable",
} as const);
export type L2ErrorCode = (typeof L2ErrorCode)[keyof typeof L2ErrorCode];

export class L2Error extends Error {
  constructor(readonly code: L2ErrorCode) {
    super(code);
  }
}

interface L2Device {
  relayUrl: string;
  id: string;
  token: string;
  publicKey: string;
  secretKey: string;
}

interface L2State {
  device?: L2Device;
  phone?: { id: string; publicKey: string };
}

// shortcut: state definition lives here instead of libs/state to keep the fork's diff local.
const L2_DISK = new StateDefinition("l2Autofill", "disk");
export const L2_STATE = new UserKeyDefinition<L2State>(L2_DISK, "l2State", {
  deserializer: (s) => s,
  clearOn: ["logout"],
});

const FILL_TIMEOUT_MS = 60_000;
const PAIR_TIMEOUT_MS = 120_000;
const PC_NAME_MAX = 64;

interface PendingPairing {
  conn: L2RelayConnection;
  device: L2Device;
  phone: { id: string; publicKey: string };
  accepted: Promise<void>;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Background side of L2 fills (PROTOCOL.md §6): turns an L2 cipher into a plaintext
 * copy, either with the L2 password or with an approval from the paired phone, and pairs the
 * extension with a phone.
 */
export class L2Service {
  private pairing?: PendingPairing;
  private qrPairing?: {
    conn: L2RelayConnection;
    device: L2Device;
    paired: Promise<{ id: string; publicKey: string }>;
    timer: ReturnType<typeof setTimeout>;
  };

  constructor(
    private readonly cipherService: CipherService,
    private readonly stateProvider: StateProvider,
  ) {}

  async status(userId: UserId): Promise<{ paired: boolean; phoneId?: string; relayUrl?: string }> {
    const s = await this.getState(userId);
    return { paired: !!s.phone, phoneId: s.phone?.id, relayUrl: s.device?.relayUrl };
  }

  /**
   * Returns a copy of `cipher` with plaintext password (and TOTP seed in password mode). In
   * phone mode the TOTP seed never leaves the phone; the current code comes back as `totpCode`.
   */
  async decryptForFill(
    userId: UserId,
    cipher: CipherView,
    tabUrl: string,
    unlock: L2Unlock,
  ): Promise<{ cipher: CipherView; totpCode?: string }> {
    const origin = new URL(tabUrl).origin;
    const copy = CipherView.fromJSON(JSON.parse(JSON.stringify(cipher)));
    if (copy == null) {
      throw new L2Error(L2ErrorCode.Undecryptable);
    }

    if (unlock.mode === "password") {
      const key = await this.unlockKey(userId, unlock.password);
      try {
        for (const field of ["password", "totp"] as const) {
          const value = copy.login[field];
          if (value == null || !isL2Value(value)) {
            continue;
          }
          const plain = await decryptField(key, field, cipher.id, value).catch(() => {
            throw new L2Error(L2ErrorCode.Undecryptable);
          });
          if (!originAllowed(origin, plain.hosts)) {
            throw new L2Error(L2ErrorCode.HostNotAllowed);
          }
          copy.login[field] = plain.secret;
        }
      } finally {
        (await getSodium()).memzero(key);
      }
      return { cipher: copy };
    }

    const result = await this.requestFromPhone(userId, cipher.id, origin);
    copy.login.password = result.password;
    // An L1 TOTP seed stays usable on the PC; an L2 seed is replaced by the phone's code.
    let totpCode: string | undefined;
    if (isL2Value(copy.login.totp)) {
      copy.login.totp = undefined;
      totpCode = result.totp;
    }
    return { cipher: copy, totpCode };
  }

  private async unlockKey(userId: UserId, password: string): Promise<Uint8Array> {
    const all = await this.cipherService.getAllDecrypted(userId);
    const fields = all
      .filter((c) => c.type === CipherType.SecureNote && !c.isDeleted)
      .flatMap((c) => c.fields ?? [])
      .filter((f) => f.name === KEY_FIELD_NAME);
    if (fields.length === 0) {
      throw new L2Error(L2ErrorCode.NoKeyItem);
    }
    if (fields.length > 1) {
      throw new L2Error(L2ErrorCode.MultipleKeyItems);
    }
    try {
      return await unwrapKey(fields[0].value ?? "", password);
    } catch (e) {
      throw new L2Error(
        e instanceof WrongPasswordError ? L2ErrorCode.WrongPassword : L2ErrorCode.NoKeyItem,
      );
    }
  }

  private async requestFromPhone(
    userId: UserId,
    itemId: string,
    origin: string,
  ): Promise<{ password: string; totp?: string }> {
    const s = await this.getState(userId);
    if (!s.device || !s.phone) {
      throw new L2Error(L2ErrorCode.NotPaired);
    }
    const sodium = await getSodium();
    const keys = this.keys(s.device);
    const phonePk = sodium.from_base64(s.phone.publicKey, sodium.base64_variants.ORIGINAL);
    const requestId = sodium.to_base64(sodium.randombytes_buf(16), sodium.base64_variants.ORIGINAL);
    const phone = s.phone;

    const conn = new L2RelayConnection(s.device.relayUrl, s.device.token);
    try {
      await conn.open().catch(() => {
        throw new L2Error(L2ErrorCode.Relay);
      });
      const reply = new Promise<Message & { type: "fillResult" }>((resolve, reject) => {
        const timer = setTimeout(() => reject(new L2Error(L2ErrorCode.Timeout)), FILL_TIMEOUT_MS);
        conn.onMessage(async (m) => {
          // Only the paired phone, under its paired key, may answer.
          if (m.from !== phone.id || m.fromPk !== phone.publicKey) {
            return;
          }
          const msg = await open(m.body, phonePk, keys.secretKey).catch((): null => null);
          if (msg?.type === "fillResult" && msg.requestId === requestId) {
            clearTimeout(timer);
            resolve(msg);
          }
        });
      });
      const body = await seal(
        { v: 1, type: "fillRequest", requestId, itemId, origin, time: Date.now() },
        phonePk,
        keys.secretKey,
      );
      conn.send(phone.id, body);
      const result = await reply;
      if (result.status !== "approved" || result.password == null) {
        throw new L2Error(
          result.status === "rejected" ? L2ErrorCode.PhoneRejected : L2ErrorCode.PhoneDenied,
        );
      }
      return { password: result.password, totp: result.totp };
    } finally {
      conn.close();
    }
  }

  /**
   * Steps 2–6 of PROTOCOL.md §5. Resolves with the phrase to show once the phone has answered
   * the commitment; the phone's approval is awaited by {@link pairConfirm}.
   */
  async pairStart(userId: UserId, relayUrl: string, phoneId: string, pcName: string) {
    this.pairCancel();
    const sodium = await getSodium();
    const b64 = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
    const unb64 = (t: string) => sodium.from_base64(t, sodium.base64_variants.ORIGINAL);
    const base = relayBaseUrl(relayUrl).toString();
    const device = await this.ensureDevice(userId, base);
    const keys = this.keys(device);

    const res = await fetch(new URL(`/v1/devices/${encodeURIComponent(phoneId)}`, base));
    const info = res.ok ? await res.json() : null;
    if (info?.kind !== "phone" || typeof info.publicKey !== "string") {
      throw new L2Error(L2ErrorCode.Pairing);
    }
    const phone = { id: phoneId, publicKey: info.publicKey as string };
    const phonePk = unb64(phone.publicKey);
    if (phonePk.length !== 32) {
      throw new L2Error(L2ErrorCode.Pairing);
    }

    const conn = new L2RelayConnection(base, device.token);
    await conn.open().catch(() => {
      throw new L2Error(L2ErrorCode.Relay);
    });

    const nExt = await randomNonce();
    const challenged = deferred<Uint8Array>();
    const accepted = deferred<void>();
    accepted.promise.catch(() => {}); // observed later by pairConfirm
    const fail = (e: L2Error) => {
      challenged.reject(e);
      accepted.reject(e);
    };
    let stage: "challenge" | "accept" = "challenge";

    conn.onMessage(async (m) => {
      if (m.from !== phone.id || m.fromPk !== phone.publicKey) {
        return;
      }
      const msg = await open(m.body, phonePk, keys.secretKey).catch((): null => null);
      if (msg?.type === "pairChallenge" && stage === "challenge") {
        stage = "accept";
        challenged.resolve(unb64(msg.nonce));
      } else if (msg?.type === "pairAccept" && stage === "accept" && msg.nonce === b64(nExt)) {
        accepted.resolve(); // the echoed nExt ties the accept to this attempt
      } else if (msg != null) {
        fail(new L2Error(L2ErrorCode.Pairing)); // pairReject, or out of order: abandon (§5)
      }
    });

    const timer = setTimeout(() => {
      fail(new L2Error(L2ErrorCode.Timeout));
      this.pairCancel();
    }, PAIR_TIMEOUT_MS);
    this.pairing = { conn, device, phone, accepted: accepted.promise, timer };

    const name = pcName.trim().slice(0, PC_NAME_MAX) || "PC";
    const commit = b64(await commitment(keys.publicKey, nExt));
    conn.send(
      phone.id,
      await seal({ v: 1, type: "pairRequest", name, commit }, phonePk, keys.secretKey),
    );
    try {
      const nPhone = await challenged.promise;
      conn.send(
        phone.id,
        await seal({ v: 1, type: "pairReveal", nonce: b64(nExt) }, phonePk, keys.secretKey),
      );
      return { phrase: await fingerprintPhrase(phonePk, keys.publicKey, nExt, nPhone) };
    } catch (e) {
      this.pairCancel();
      throw e;
    }
  }

  /** Call after the user confirmed the phrase matches. Stores the pairing once the phone approved. */
  async pairConfirm(userId: UserId): Promise<void> {
    const p = this.pairing;
    if (!p) {
      throw new L2Error(L2ErrorCode.Pairing);
    }
    try {
      await p.accepted;
      await this.updateState(userId, (s) => ({ ...s, device: p.device, phone: p.phone }));
    } finally {
      this.pairCancel();
    }
  }

  /**
   * Starts QR pairing (PROTOCOL.md §5b): registers with the relay if needed and returns the
   * `pushwarden://pair` URI to show. {@link qrWait} then waits for the phone's proof.
   */
  async qrStart(userId: UserId, relayUrl: string, pcName: string): Promise<{ uri: string }> {
    this.pairCancel();
    const sodium = await getSodium();
    const b64url = (b: Uint8Array) =>
      sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);
    const unb64 = (t: string) => sodium.from_base64(t, sodium.base64_variants.ORIGINAL);
    const base = relayBaseUrl(relayUrl).toString();
    const device = await this.ensureDevice(userId, base);
    const keys = this.keys(device);
    const conn = new L2RelayConnection(base, device.token);
    await conn.open().catch(() => {
      throw new L2Error(L2ErrorCode.Relay);
    });

    const secret = sodium.randombytes_buf(32);
    const paired = deferred<{ id: string; publicKey: string }>();
    paired.promise.catch(() => {}); // observed by qrWait
    conn.onMessage(async (m) => {
      const msg = await open(m.body, unb64(m.fromPk), keys.secretKey).catch((): null => null);
      // fromPk comes from the relay; the proof binds it, and only the QR code carried `secret`.
      if (
        msg?.type === "qrPair" &&
        (await checkQrProof(unb64(msg.proof), secret, unb64(m.fromPk), keys.publicKey))
      ) {
        paired.resolve({ id: m.from, publicKey: m.fromPk });
      }
    });
    const timer = setTimeout(() => {
      paired.reject(new L2Error(L2ErrorCode.Timeout));
      this.pairCancel();
    }, PAIR_TIMEOUT_MS);
    this.qrPairing = { conn, device, paired: paired.promise, timer };

    const name = pcName.trim().slice(0, PC_NAME_MAX) || "PC";
    const uri =
      `pushwarden://pair?v=1&r=${encodeURIComponent(base)}&e=${device.id}` +
      `&k=${b64url(keys.publicKey)}&s=${b64url(secret)}&n=${encodeURIComponent(name)}`;
    return { uri };
  }

  /** Resolves once a phone scanned the QR code and proved it; stores the pairing. */
  async qrWait(userId: UserId): Promise<{ phoneId: string }> {
    const p = this.qrPairing;
    if (!p) {
      throw new L2Error(L2ErrorCode.Pairing);
    }
    try {
      const phone = await p.paired;
      await this.updateState(userId, (s) => ({ ...s, device: p.device, phone }));
      return { phoneId: phone.id };
    } finally {
      this.pairCancel();
    }
  }

  pairCancel(): void {
    if (this.qrPairing) {
      clearTimeout(this.qrPairing.timer);
      this.qrPairing.conn.close();
      this.qrPairing = undefined;
    }
    if (this.pairing) {
      clearTimeout(this.pairing.timer);
      this.pairing.conn.close();
      this.pairing = undefined;
    }
  }

  async unpair(userId: UserId): Promise<void> {
    const s = await this.getState(userId);
    if (s.device && s.phone) {
      const conn = new L2RelayConnection(s.device.relayUrl, s.device.token);
      try {
        const sodium = await getSodium();
        await conn.open();
        const phonePk = sodium.from_base64(s.phone.publicKey, sodium.base64_variants.ORIGINAL);
        conn.send(
          s.phone.id,
          await seal({ v: 1, type: "unpair" }, phonePk, this.keys(s.device).secretKey),
        );
      } catch {
        // Best effort: the local pairing is removed regardless.
      } finally {
        conn.close();
      }
    }
    await this.updateState(userId, (st) => ({ ...st, phone: undefined }));
  }

  /** Registers this extension with the relay once per relay URL. */
  private async ensureDevice(userId: UserId, relayUrl: string): Promise<L2Device> {
    const s = await this.getState(userId);
    if (s.device?.relayUrl === relayUrl) {
      return s.device;
    }
    const sodium = await getSodium();
    const kp = sodium.crypto_box_keypair();
    const publicKey = sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL);
    const res = await fetch(new URL("/v1/devices", relayUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ publicKey, kind: "ext" }),
    });
    if (res.status !== 201) {
      throw new L2Error(L2ErrorCode.Relay);
    }
    const { id, token } = await res.json();
    const device: L2Device = {
      relayUrl,
      id,
      token,
      publicKey,
      secretKey: sodium.to_base64(kp.privateKey, sodium.base64_variants.ORIGINAL),
    };
    // A new device identity invalidates any pairing made with the old one.
    await this.updateState(userId, () => ({ device }));
    return device;
  }

  private keys(d: L2Device) {
    const b = (t: string) => new Uint8Array(atobBytes(t));
    return { publicKey: b(d.publicKey), secretKey: b(d.secretKey) };
  }

  private async getState(userId: UserId): Promise<L2State> {
    return (await firstValueFrom(this.stateProvider.getUser(userId, L2_STATE).state$)) ?? {};
  }

  private async updateState(userId: UserId, f: (s: L2State) => L2State) {
    await this.stateProvider.getUser(userId, L2_STATE).update((s) => f(s ?? {}));
  }
}

function atobBytes(b64: string): number[] {
  return Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

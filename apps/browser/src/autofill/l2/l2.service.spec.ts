import { mock } from "jest-mock-extended";
import { take } from "rxjs";

import { FakeStateProvider, mockAccountServiceWith } from "@bitwarden/common/spec";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { CipherType, FieldType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { LoginView } from "@bitwarden/common/vault/models/view/login.view";

import { isL2Cipher } from "./l2-cipher";
import { L2_STATE, L2ErrorCode, L2Service } from "./l2.service";
import { encryptField, getSodium, open, qrProof, seal, wrapKey } from "./protocol";

const userId = "user-1" as UserId;
const PASSWORD = "correct horse battery staple";
const FAST = { ops: 3, memMiB: 64 };

function login(id: string, password: string, totp?: string): CipherView {
  const c = new CipherView();
  c.id = id;
  c.type = CipherType.Login;
  c.login = new LoginView();
  c.login.username = "alice";
  c.login.password = password;
  c.login.totp = totp;
  return c;
}

function keyNote(value: string): CipherView {
  const c = new CipherView();
  c.id = `key-${Math.random()}`;
  c.type = CipherType.SecureNote;
  const f = new FieldView();
  f.name = "l2key";
  f.type = FieldType.Hidden;
  f.value = value;
  c.fields = [f];
  return c;
}

describe("isL2Cipher", () => {
  it("detects L2 password or TOTP, including unknown versions", () => {
    expect(isL2Cipher(login("a", "hunter2"))).toBe(false);
    expect(isL2Cipher(login("a", "l2:v1:x"))).toBe(true);
    expect(isL2Cipher(login("a", "hunter2", "l2:v1:x"))).toBe(true);
    expect(isL2Cipher(login("a", "l2:v7:x"))).toBe(true);
  });
});

describe("L2Service", () => {
  let key: Uint8Array;
  let keyItem: string;
  let cipherService: ReturnType<typeof mock<CipherService>>;
  let stateProvider: FakeStateProvider;
  let service: L2Service;

  beforeAll(async () => {
    const s = await getSodium();
    key = s.randombytes_buf(32);
    keyItem = await wrapKey(key, PASSWORD, FAST);
  });

  beforeEach(() => {
    cipherService = mock<CipherService>();
    stateProvider = new FakeStateProvider(mockAccountServiceWith(userId));
    service = new L2Service(cipherService, stateProvider);
  });

  describe("password mode", () => {
    it("decrypts password and TOTP for an allowed host", async () => {
      const item = login(
        "i1",
        await encryptField(
          key,
          "password",
          { itemId: "i1", username: "alice", hosts: ["github.com"] },
          "hunter2",
        ),
        await encryptField(
          key,
          "totp",
          { itemId: "i1", username: "alice", hosts: ["github.com"] },
          "JBSWY3DPEHPK3PXP",
        ),
      );
      cipherService.getAllDecrypted.mockResolvedValue([keyNote(keyItem), item]);

      const out = await service.decryptForFill(userId, item, "https://gist.github.com/x", {
        mode: "password",
        password: PASSWORD,
      });

      expect(out.cipher.login.password).toBe("hunter2");
      expect(out.cipher.login.totp).toBe("JBSWY3DPEHPK3PXP");
      expect(isL2Cipher(out.cipher)).toBe(false);
      // The original stays encrypted.
      expect(item.login.password?.startsWith("l2:v1:")).toBe(true);
    });

    it.each([
      ["https://evil.com", L2ErrorCode.HostNotAllowed, PASSWORD],
      ["http://github.com", L2ErrorCode.HostNotAllowed, PASSWORD],
      ["https://github.com", L2ErrorCode.WrongPassword, "wrong"],
    ])("rejects %s with %s", async (url, code, password) => {
      const item = login(
        "i1",
        await encryptField(
          key,
          "password",
          { itemId: "i1", username: "alice", hosts: ["github.com"] },
          "hunter2",
        ),
      );
      cipherService.getAllDecrypted.mockResolvedValue([keyNote(keyItem), item]);

      await expect(
        service.decryptForFill(userId, item, url, { mode: "password", password }),
      ).rejects.toMatchObject({ code });
    });

    it("refuses when the vault has zero or two key items", async () => {
      const item = login(
        "i1",
        await encryptField(
          key,
          "password",
          { itemId: "i1", username: "alice", hosts: ["a.com"] },
          "x",
        ),
      );
      const unlock = { mode: "password", password: PASSWORD } as const;

      cipherService.getAllDecrypted.mockResolvedValue([item]);
      await expect(
        service.decryptForFill(userId, item, "https://a.com", unlock),
      ).rejects.toMatchObject({
        code: L2ErrorCode.NoKeyItem,
      });

      cipherService.getAllDecrypted.mockResolvedValue([keyNote(keyItem), keyNote(keyItem), item]);
      await expect(
        service.decryptForFill(userId, item, "https://a.com", unlock),
      ).rejects.toMatchObject({
        code: L2ErrorCode.MultipleKeyItems,
      });
    });

    it("rejects a ciphertext copied from another item", async () => {
      const stolen = await encryptField(
        key,
        "password",
        { itemId: "bank-item", username: "alice", hosts: ["evil.com"] },
        "bank-pw",
      );
      const item = login("i1", stolen);
      cipherService.getAllDecrypted.mockResolvedValue([keyNote(keyItem), item]);

      await expect(
        service.decryptForFill(userId, item, "https://evil.com", {
          mode: "password",
          password: PASSWORD,
        }),
      ).rejects.toMatchObject({ code: L2ErrorCode.Undecryptable });
    });

    it("rejects a TOTP ciphertext pasted into the password field", async () => {
      const item = login(
        "i1",
        await encryptField(
          key,
          "totp",
          { itemId: "i1", username: "alice", hosts: ["a.com"] },
          "seed",
        ),
      );
      cipherService.getAllDecrypted.mockResolvedValue([keyNote(keyItem), item]);

      await expect(
        service.decryptForFill(userId, item, "https://a.com", {
          mode: "password",
          password: PASSWORD,
        }),
      ).rejects.toMatchObject({ code: L2ErrorCode.Undecryptable });
    });
  });

  describe("phone mode", () => {
    const realWebSocket = global.WebSocket;
    let sockets: FakeSocket[];

    class FakeSocket {
      static OPEN = 1;
      readyState = 0;
      sent: any[] = [];
      onopen?: () => void;
      onmessage?: (e: { data: string }) => void;
      onerror?: () => void;
      onclose?: () => void;
      constructor(readonly url: string) {
        sockets.push(this);
        setTimeout(() => {
          this.readyState = 1;
          this.onopen?.();
        });
      }
      send(data: string) {
        const f = JSON.parse(data);
        this.sent.push(f);
        if (f.t === "auth") {
          this.deliver({ t: "ready", id: "ext1-0000" });
        }
      }
      deliver(frame: object) {
        this.onmessage?.({ data: JSON.stringify(frame) });
      }
      close() {
        this.readyState = 3;
      }
    }

    beforeEach(() => {
      sockets = [];
      (global as any).WebSocket = FakeSocket;
    });
    afterAll(() => {
      (global as any).WebSocket = realWebSocket;
    });

    async function pairedSetup() {
      const s = await getSodium();
      const b64 = (b: Uint8Array) => s.to_base64(b, s.base64_variants.ORIGINAL);
      const ext = s.crypto_box_keypair();
      const phone = s.crypto_box_keypair();
      await stateProvider.setUserState(
        L2_STATE,
        {
          device: {
            relayUrl: "https://relay.test/",
            id: "ext1-0000",
            token: "tok",
            publicKey: b64(ext.publicKey),
            secretKey: b64(ext.privateKey),
          },
          phone: { id: "phon-0001", publicKey: b64(phone.publicKey) },
        },
        userId,
      );
      return { s, b64, ext, phone };
    }

    /** Waits for the extension's fillRequest, then answers it as `from`/`fromPk` would. */
    async function answer(
      setup: Awaited<ReturnType<typeof pairedSetup>>,
      reply: (req: any) => object,
      as?: { from: string; key: { publicKey: Uint8Array; privateKey: Uint8Array } },
    ) {
      const { b64, ext, phone } = setup;
      const sender = as ?? { from: "phon-0001", key: phone };
      for (let i = 0; i < 50 && !sockets[0]?.sent.some((f) => f.t === "send"); i++) {
        await new Promise((r) => setTimeout(r, 5));
      }
      const sendFrame = sockets[0].sent.find((f) => f.t === "send");
      expect(sendFrame.to).toBe("phon-0001");
      const req = await open(sendFrame.body, ext.publicKey, phone.privateKey);
      expect(req).toMatchObject({
        type: "fillRequest",
        itemId: "i1",
        origin: "https://github.com",
      });
      sockets[0].deliver({
        t: "msg",
        from: sender.from,
        fromPk: b64(sender.key.publicKey),
        body: await seal(reply(req) as any, ext.publicKey, sender.key.privateKey),
      });
    }

    it("fills with the phone's password and replaces an L2 TOTP seed with the code", async () => {
      const setup = await pairedSetup();
      const item = login("i1", "l2:v1:AAAA", "l2:v1:BBBB");
      const pending = service.decryptForFill(userId, item, "https://github.com/login", {
        mode: "phone",
      });
      await answer(setup, (req) => ({
        v: 1,
        type: "fillResult",
        requestId: req.requestId,
        status: "approved",
        password: "hunter2",
        totp: "123456",
      }));

      const out = await pending;
      expect(out.cipher.login.password).toBe("hunter2");
      expect(out.cipher.login.totp).toBeUndefined();
      expect(out.totpCode).toBe("123456");
      expect(sockets[0].url).toBe("wss://relay.test/v1/ws");
    });

    it("reports a denial", async () => {
      const setup = await pairedSetup();
      const pending = service.decryptForFill(
        userId,
        login("i1", "l2:v1:AAAA"),
        "https://github.com",
        {
          mode: "phone",
        },
      );
      await answer(setup, (req) => ({
        v: 1,
        type: "fillResult",
        requestId: req.requestId,
        status: "denied",
      }));
      await expect(pending).rejects.toMatchObject({ code: L2ErrorCode.PhoneDenied });
    });

    it("ignores answers from a key other than the paired phone", async () => {
      jest.useFakeTimers({ doNotFake: ["setImmediate", "nextTick"] });
      try {
        const setup = await pairedSetup();
        const intruder = setup.s.crypto_box_keypair();
        const pending = service.decryptForFill(
          userId,
          login("i1", "l2:v1:AAAA"),
          "https://github.com",
          {
            mode: "phone",
          },
        );
        pending.catch(() => {});
        // Let the fake socket open and the request go out.
        for (let i = 0; i < 20; i++) {
          await jest.advanceTimersByTimeAsync(5);
        }
        await answer(
          setup,
          (req) => ({
            v: 1,
            type: "fillResult",
            requestId: req.requestId,
            status: "approved",
            password: "evil",
          }),
          { from: "phon-0001", key: intruder },
        );
        await jest.advanceTimersByTimeAsync(61_000);
        await expect(pending).rejects.toMatchObject({ code: L2ErrorCode.Timeout });
      } finally {
        jest.useRealTimers();
      }
    });

    it("needs a pairing", async () => {
      await expect(
        service.decryptForFill(userId, login("i1", "l2:v1:AAAA"), "https://github.com", {
          mode: "phone",
        }),
      ).rejects.toMatchObject({ code: L2ErrorCode.NotPaired });
    });

    it("aborts pairing on a pairAccept that doesn't echo this attempt's nonce", async () => {
      const s = await getSodium();
      const b64 = (b: Uint8Array) => s.to_base64(b, s.base64_variants.ORIGINAL);
      const phone = s.crypto_box_keypair();
      const realFetch = global.fetch;
      global.fetch = jest.fn(async (url: any, init?: any) => {
        if (init?.method === "POST") {
          return { status: 201, json: async () => ({ id: "ext1-0000", token: "tok" }) } as any;
        }
        expect(String(url)).toBe("https://relay.test/v1/devices/phon-0001");
        return {
          ok: true,
          json: async () => ({ kind: "phone", publicKey: b64(phone.publicKey) }),
        } as any;
      }) as any;
      try {
        const started = service.pairStart(userId, "https://relay.test", "phon-0001", "Home PC");
        for (let i = 0; i < 50 && !sockets[0]?.sent.some((f) => f.t === "send"); i++) {
          await new Promise((r) => setTimeout(r, 5));
        }
        const extPk = s.from_base64(
          (await stateProvider.getUser(userId, L2_STATE).state$.pipe(firstState()).toPromise())!
            .device!.publicKey,
          s.base64_variants.ORIGINAL,
        );
        const reply = async (msg: object) =>
          sockets[0].deliver({
            t: "msg",
            from: "phon-0001",
            fromPk: b64(phone.publicKey),
            body: await seal(msg as any, extPk, phone.privateKey),
          });
        const nPhone = s.randombytes_buf(32);
        await reply({ v: 1, type: "pairChallenge", nonce: b64(nPhone) });
        const { phrase } = await started;
        expect(phrase.split("-")).toHaveLength(5);

        const revealFrame = sockets[0].sent.filter((f) => f.t === "send")[1];
        const reveal = await open(revealFrame.body, extPk, phone.privateKey);
        expect(reveal?.type).toBe("pairReveal");
        const nExt = (reveal as any).nonce as string;

        // A replayed accept from an earlier attempt aborts this one instead of completing it.
        const confirmed = service.pairConfirm(userId);
        await reply({ v: 1, type: "pairAccept", nonce: b64(s.randombytes_buf(32)) });
        await expect(confirmed).rejects.toMatchObject({ code: L2ErrorCode.Pairing });
        expect(await service.status(userId)).toMatchObject({ paired: false });
        expect(nExt).toHaveLength(44);
      } finally {
        global.fetch = realFetch;
      }
    });

    it.each([
      ["a valid proof pairs", true],
      ["a proof for a swapped key is ignored", false],
    ])("QR pairing: %s", async (_, honest) => {
      const s = await getSodium();
      const b64 = (b: Uint8Array) => s.to_base64(b, s.base64_variants.ORIGINAL);
      const phone = s.crypto_box_keypair();
      const relayMitm = s.crypto_box_keypair();
      const realFetch = global.fetch;
      global.fetch = jest.fn(async () => ({
        status: 201,
        json: async () => ({ id: "ext1-0000", token: "tok" }),
      })) as any;
      try {
        const { uri } = await service.qrStart(userId, "https://relay.test", "Home PC");
        const q = new URL(uri).searchParams;
        expect(uri.startsWith("pushwarden://pair?v=1&")).toBe(true);
        expect(q.get("r")).toBe("https://relay.test/");
        expect(q.get("e")).toBe("ext1-0000");
        expect(q.get("n")).toBe("Home PC");
        const urlsafe = s.base64_variants.URLSAFE_NO_PADDING;
        const extPk = s.from_base64(q.get("k")!, urlsafe);
        const secret = s.from_base64(q.get("s")!, urlsafe);

        const waited = service.qrWait(userId);
        // An honest phone proves its own key; a relay swapping in its key can't, without `secret`.
        const sender = honest ? phone : relayMitm;
        const proof = await qrProof(secret, phone.publicKey, extPk);
        sockets[0].deliver({
          t: "msg",
          from: "phon-0001",
          fromPk: b64(sender.publicKey),
          body: await seal(
            { v: 1, type: "qrPair", proof: b64(proof), name: "S24" },
            extPk,
            sender.privateKey,
          ),
        });
        if (honest) {
          await expect(waited).resolves.toEqual({ phoneId: "phon-0001" });
          expect(await service.status(userId)).toMatchObject({
            paired: true,
            phoneId: "phon-0001",
          });
        } else {
          waited.catch(() => {});
          await new Promise((r) => setTimeout(r, 30));
          expect(await service.status(userId)).toMatchObject({ paired: false });
          service.pairCancel();
        }
      } finally {
        global.fetch = realFetch;
      }
    });

    it("completes pairing on a pairAccept echoing this attempt's nonce", async () => {
      const s = await getSodium();
      const b64 = (b: Uint8Array) => s.to_base64(b, s.base64_variants.ORIGINAL);
      const phone = s.crypto_box_keypair();
      const realFetch = global.fetch;
      global.fetch = jest.fn(async (url: any, init?: any) => {
        if (init?.method === "POST") {
          return { status: 201, json: async () => ({ id: "ext1-0000", token: "tok" }) } as any;
        }
        expect(String(url)).toBe("https://relay.test/v1/devices/phon-0001");
        return {
          ok: true,
          json: async () => ({ kind: "phone", publicKey: b64(phone.publicKey) }),
        } as any;
      }) as any;
      try {
        const started = service.pairStart(userId, "https://relay.test", "phon-0001", "Home PC");
        for (let i = 0; i < 50 && !sockets[0]?.sent.some((f) => f.t === "send"); i++) {
          await new Promise((r) => setTimeout(r, 5));
        }
        const extPk = s.from_base64(
          (await stateProvider.getUser(userId, L2_STATE).state$.pipe(firstState()).toPromise())!
            .device!.publicKey,
          s.base64_variants.ORIGINAL,
        );
        const reply = async (msg: object) =>
          sockets[0].deliver({
            t: "msg",
            from: "phon-0001",
            fromPk: b64(phone.publicKey),
            body: await seal(msg as any, extPk, phone.privateKey),
          });
        const nPhone = s.randombytes_buf(32);
        await reply({ v: 1, type: "pairChallenge", nonce: b64(nPhone) });
        const { phrase } = await started;
        expect(phrase.split("-")).toHaveLength(5);

        const revealFrame = sockets[0].sent.filter((f) => f.t === "send")[1];
        const reveal = await open(revealFrame.body, extPk, phone.privateKey);
        expect(reveal?.type).toBe("pairReveal");
        const nExt = (reveal as any).nonce as string;

        const confirmed = service.pairConfirm(userId);
        await reply({ v: 1, type: "pairAccept", nonce: nExt });
        await confirmed;
        expect(await service.status(userId)).toMatchObject({ paired: true, phoneId: "phon-0001" });
      } finally {
        global.fetch = realFetch;
      }
    });
  });
});

function firstState<T>() {
  return (src: import("rxjs").Observable<T>) => src.pipe(take(1));
}

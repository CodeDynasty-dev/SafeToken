export class SafeToken<
  TimeWindow extends Record<string, number> = { "access": number, "refresh": number }
> {
  readonly #timeWindow: TimeWindow;
  readonly #secret: string;
  readonly #enc: TextEncoder;
  readonly #keyPromise: Promise<CryptoKey> | CryptoKey;

  constructor(init: { timeWindows?: TimeWindow; secret: string }) {
    if (!init || !init.secret || init.secret.length < 12 || (Object.keys(init.timeWindows || {}).length && Object.values(init.timeWindows!)
      .some((w) => (typeof w !== 'number' || w <= 0 || w === undefined || w === null || !Number.isFinite(w) || Number.isNaN(w))))) {
      throw new Error("Please provide safetoken  secret and time window");
    }
    this.#secret = init.secret;
    this.#timeWindow = init.timeWindows || { "access": 3600000, "refresh": 2592000000 } as unknown as TimeWindow
    this.#enc = new TextEncoder();
    this.#keyPromise = crypto.subtle.importKey(
      "raw",
      this.#enc.encode(this.#secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }

  async create(data: Record<string, string | number | boolean> = {}) {
    const key = await this.#keyPromise;
    return await createHmacSha256Signature(data, key, this.#enc, timestamp());
  }

  async verify(token: string, timeWindowKey: keyof TimeWindow = "access") {
    if (typeof token === "string") {
      const key = await this.#keyPromise;
      if (!this.#timeWindow[timeWindowKey]) throw new Error("Invalid time window");
      return await verifyToken(
        token,
        key,
        this.#enc,
        this.#timeWindow[timeWindowKey]
      );
    }
    console.log({ token });
    throw new Error("Invalid token");
  }

  decode(token: string): Record<string, string | number | boolean> {
    if (typeof token === "string") {
      const data = token.split(".")[2];
      if (!data) {
        console.log({ token });
        throw new Error("Invalid token");
      }
      try {
        const decodedData = base64UrlDecode(data);
        return JSON.parse(decodedData);
      } catch (error) {
        console.log({ token });
        throw new Error("Invalid token");
      }
    }
    console.log({ token });
    throw new Error("Invalid token");
  }
}

async function createHmacSha256Signature(
  payload: Record<string, string | number | boolean>,
  key: CryptoKey,
  enc: TextEncoder,
  time: string
) {


  const tbuf = base64UrlEncode(time);
  const dataToSign = base64UrlEncode(JSON.stringify(payload));
  const data = dataToSign;
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(dataToSign + tbuf)
  );
  const signature = base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signatureBuffer))
  );
  return `${time}.${signature}.${data}`;
}

async function verifyToken(token: string, key: CryptoKey, enc: TextEncoder, timeWindow: number) {
  const [time, signature, data] = token.split(".");
  if (!time || !signature || !data || !/^[0-9a-fA-F]{8}$/.test(time)) {
    console.log({ token });
    throw new Error("Invalid token");
  }
  if (!isInTime(timeWindow, time)) {
    throw new Error("Token expired");
  }

  const timeBase64 = base64UrlEncode(time);
  const dataToSign = data + timeBase64;
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(dataToSign)
  );
  const expectedSignature = base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signatureBuffer))
  );

  if (timingSafeEqual(signature, expectedSignature)) {
    const decodedData = base64UrlDecode(data);
    return JSON.parse(decodedData) as Record<string, string | number | boolean>;
  }
  console.log({ token });
  throw new Error("Invalid token");
}

const isInTime = (timeWindow: number, timeCreated: string): boolean => {
  // if (timeWindow === undefined || timeWindow === null || timeWindow <= 0) {
  //   throw new Error("Invalid time window");
  // } // handled by constructor so won't happen
  const timeCreatedParsed = parseInt(timeCreated, 16);
  if (typeof timeCreatedParsed !== "number" || !Number.isFinite(timeCreatedParsed) || timeCreatedParsed <= 0) {
    return false;
  }
  const nowMs = Date.now();
  const tokenMs = timeCreatedParsed * 1000;
  const diff = nowMs - tokenMs;

  // Protect against future-dated token timestamp exploit (allow up to 5s clock skew)
  if (diff < -5000) {
    return false;
  }

  return timeWindow >= diff;
};

const timestamp = (): string => {
  return (Math.floor(Date.now() / 1000) >>> 0).toString(16).padStart(8, "0");
};

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function base64UrlEncode(str: string) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) {
    str += "=";
  }
  return atob(str);
}

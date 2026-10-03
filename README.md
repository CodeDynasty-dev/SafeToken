# SafeToken Generator/validator

SafeToken is a simplest Auth for generating secure tokens suitable for authentication purposes.

We use it to create access tokens and refresh tokens that is verifirable and store signed data.

SafeToken is easy for everyone.

## Features

- **Secure Tokens:** Utilizes cryptographic signature.
- **Modern api** Built using modern nodejs crypto APIs.
- **Most fastest** Blazingly fast .create .verify methods.
- **Fully Typed** SafeToken is written in typescript and fully typed.
- **Super light-weight** 2KB~ size minified and fast token creation and verification logic.

## How It Works

The `SafeToken` class provides methods for generating tokens. Tokens are generated using crypto to enhance security. Token expiration is managed, and new tokens can be generated based on configured time intervals.

## Why SafeToken over JWT?

This is a niche, lightweight library rather than an industry standard, so the case for it comes straight from the code itself. For specific internal Node.js/TypeScript projects it can be a simpler and safer alternative to JWT:

### 1. Safer by design — no algorithm confusion

Standard JWTs include a header (`{"alg": "HS256", ...}`) that tells the server how to verify the signature. Attackers have exploited this by switching the header to `"alg": "none"` or swapping RSA public keys for HMAC secrets.

SafeToken hardcodes HMAC-SHA256 and never reads an algorithm from the token. This eliminates an entire class of critical vulnerabilities (CVE-2015-9235, etc.) that have repeatedly hit JWT implementations.

### 2. Tiny and auditable

A full JWT implementation (like `jsonwebtoken` or `jose`) can be thousands of lines supporting RSA, ECDSA, PSS, and more. SafeToken is roughly 150 lines of code — you can read and verify the whole execution path in about 15 minutes. Less code means fewer places for bugs to hide.

### 3. Fast and lean

- **Native crypto:** it uses the Web Crypto API (`crypto.subtle`) directly — a native Node.js standard that runs closer to the metal than older JS crypto libraries.
- **Smaller tokens:** it skips the verbose JWT header (`eyJhbGciOiJIUzI...`). A SafeToken is just `[HexTimestamp].[Signature].[Base64Data]`, saving bytes on every request.

## Comparison with JWT

| Feature | SafeToken | Standard JWT | Verdict |
|---|---|---|---|
| Attack Surface | Minimal (150 lines, 1 alg) | High (Complex spec, many algs) | SafeToken wins for simplicity. |
| Algorithm Confusion | Impossible (Hardcoded) | Possible (Depends on library config) | SafeToken wins for security. |
| Interoperability | None (Only your app works) | Universal (Parsable by anything) | JWT wins for public APIs. |
| Ecosystem | Non-existent (No tutorials/docs) | Massive (Standard everywhere) | JWT wins for maintainability. |

## When to use (and not use) SafeToken

Use it when:

- You control both the server and the client (a specific internal app).
- You want to eliminate "alg" header vulnerabilities by design.
- You value a dependency-free, lightweight codebase.

Avoid it when:

- You need features like `audience` (`aud`) or `issuer` (`iss`) checks out of the box (you'd have to build these yourself).

## next Considerations

SafeToken was intentionally kept minimal and lightweight (~150 lines). currently there are few limitations for using SafeToken

- Payloads currently rely on standard string base64 encoding. Storing emojis (e.g. `🚀`), CJK, Arabic, or multi-byte Unicode characters in payloads can trigger encoding errors. Stick to standard ASCII/Latin-1 alphanumeric data (user IDs, emails, roles).
- Changing your secret invalidates all active tokens at once, no version tag.
- `decode()` intentionally bypasses cryptographic verification for lightweight inspection; never use it for authorization decisions.

## Usage

```js
// in auth.js
const Auth = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
});
```

## Creating a token

```js
let token = await Auth.create({ email: "johndoe@gmail.com" });
console.log({
  token,
});
```

## Verifying a Token

Validates the cryptographic HMAC-SHA256 signature and verifies that the token has not expired:

```js
console.log({
  decodedToken: await Auth.verify(token),
});
```

## Decoding a Token (Unverified)

//? only decode doesn't verify
console.log({
  decodedToken: Auth.decode(token),
});
```

**ALWAYS** use `await Auth.verify(token)` for security-sensitive flows.

## Custom Token Lifetimes Example

The default timeout is 3600000 miniseconds = 1 hour.

You can customize token expiration times during class instantiation. by provide timewindows according to your application's requirements.

### creating custom time windows

```js
// Example of customizing token lifetimes
const Auth2 = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
  // your custom time windows
  timeWindows: {
    // ? all provided in miliseconds
    access: 3600000 /*1 hour*/,
    refresh: 2592000000 /*1 month*/,
  },
});
```

### Usaging custom time windows

```js
let accessToken = await Auth2.create({ email: "fridaycandours@gmail.com" });
let refreshToken = await Auth2.create({ email: "fridaycandours@gmail.com" });
console.log({
  accessToken,
  refreshToken,
});
console.log({
  decodedAccessToken: await Auth2.verify(accessToken, "access"),
  decodedRefreshToken: await Auth2.verify(refreshToken, "refresh"),
});
```

1. **Installation:**

```bash
npm i safetoken
```

## Contributing

This library provides a simple and secure way to manage authetication tokens with built-in cryptographic encryption for added security.

If you find any issues or have suggestions for improvements, feel free to contribute by opening an issue or submitting a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Feel free to adjust the information based on your project's specific considerations and security requirements.

## Pizza Area

Support me via cryptos -

- BTC: `bc1q228fnx44ha9y5lvtku70pjgaeh2jj3f867nwye`
- ETH: `0xd067560fDed3B1f3244d460d5E3011BC42C4E5d7`
- LTC: `ltc1quvc04rpmsurvss6ll54fvdgyh95p5kf74wppa6`
- TRX: `THag6WuG4EoiB911ce9ELgN3p7DibtS6vP`

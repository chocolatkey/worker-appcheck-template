const fetchJwks = require("./fetch_jwks");
const keyimport = require("jose/dist/browser/key/import");
const errors = require("jose/dist/browser/util/errors");
const isObject = require("jose/dist/browser/lib/is_object");

/**
 * 
 * @param {unknown} alg 
 * @returns {string}
 */
function getKtyFromAlg(alg) {
    switch (typeof alg === "string" && alg.substr(0, 2)) {
    case "RS":
    case "PS":
        return "RSA";
    case "ES":
        return "EC";
    case "Ed":
        return "OKP";
    default:
        throw new errors.JOSENotSupported("Unsupported \"alg\" value for a JSON Web Key Set");
    }
}

function isJWKLike(key) {
    return isObject.default(key);
}

class RemoteJWKSet {
    constructor(url, options) {
        this._cached = new WeakMap();
        if (!(url instanceof URL)) {
            throw new TypeError("url must be an instance of URL");
        }
        this._url = new URL(url.href);
        this._timeoutDuration =
        (options && typeof options.timeoutDuration === "number") ? options.timeoutDuration : 5000;
        this._cooldownDuration =
        (options && typeof options.cooldownDuration === "number") ? options.cooldownDuration : 30000;
    }

    coolingDown() {
        if (!this._cooldownStarted) {
            return false;
        }

        return Date.now() < this._cooldownStarted + this._cooldownDuration;
    }

    async getKey(protectedHeader, token) {
        const joseHeader = {
            ...protectedHeader,
            ...token.header,
        };

        if (!this._jwks) {
            await this.reload();
        }

        const candidates = this._jwks.keys.filter((jwk) => {
            // filter keys based on the mapping of signature algorithms to Key Type
            let candidate = jwk.kty === getKtyFromAlg(joseHeader.alg);

            // filter keys based on the JWK Key ID in the header
            if (candidate && typeof joseHeader.kid === "string") {
                candidate = joseHeader.kid === jwk.kid;
            }

            // filter keys based on the key's declared Algorithm
            if (candidate && typeof jwk.alg === "string") {
                candidate = joseHeader.alg === jwk.alg;
            }

            // filter keys based on the key's declared Public Key Use
            if (candidate && typeof jwk.use === "string") {
                candidate = jwk.use === "sig";
            }

            // filter keys based on the key's declared Key Operations
            if (candidate && Array.isArray(jwk.key_ops)) {
                candidate = jwk.key_ops.includes("verify");
            }

            // filter out non-applicable OKP Sub Types
            if (candidate && joseHeader.alg === "EdDSA") {
                candidate = jwk.crv === "Ed25519" || jwk.crv === "Ed448";
            }

            // filter out non-applicable EC curves
            if (candidate) {
                switch (joseHeader.alg) {
                case "ES256":
                    candidate = jwk.crv === "P-256";
                    break;
                case "ES256K":
                    candidate = jwk.crv === "secp256k1";
                    break;
                case "ES384":
                    candidate = jwk.crv === "P-384";
                    break;
                case "ES512":
                    candidate = jwk.crv === "P-521";
                    break;
                default:
                }
            }

            return candidate;
        });

        const { 0: jwk, length } = candidates;

        if (length === 0) {
            if (this.coolingDown() === false) {
                await this.reload();
                return this.getKey(protectedHeader, token);
            }
            throw new errors.JWKSNoMatchingKey();
        } else if (length !== 1) {
            throw new errors.JWKSMultipleMatchingKeys();
        }

        const cached = this._cached.get(jwk) || this._cached.set(jwk, {}).get(jwk);
        if (cached[joseHeader.alg] === undefined) {
            const keyObject = await keyimport.importJWK({ ...jwk, ext: true }, joseHeader.alg);

            if (keyObject instanceof Uint8Array || keyObject.type !== "public") {
                throw new errors.JWKSInvalid("JSON Web Key Set members must be public keys");
            }

            cached[joseHeader.alg] = keyObject;
        }

        return cached[joseHeader.alg];
    }

    async reload() {
        if (!this._pendingFetch) {
            this._pendingFetch = fetchJwks(this._url, this._timeoutDuration)
                .then((json) => {
                    if (
                        typeof json !== "object" ||
            !json ||
            !Array.isArray(json.keys) ||
            !json.keys.every(isJWKLike)
                    ) {
                        throw new errors.JWKSInvalid("JSON Web Key Set malformed");
                    }

                    this._jwks = { keys: json.keys };
                    this._cooldownStarted = Date.now();
                    this._pendingFetch = undefined;
                })
                .catch((err) => {
                    this._pendingFetch = undefined;
                    throw err;
                });
        }

        await this._pendingFetch;
    }
}

/**
 * Returns a function that resolves to a key object downloaded from a
 * remote endpoint returning a JSON Web Key Set, that is, for example,
 * an OAuth 2.0 or OIDC jwks_uri. Only a single public key must match
 * the selection process.
 *
 * @param {URL} url URL to fetch the JSON Web Key Set from.
 * @param {RemoteJWKSetOptions} options Options for the remote JSON Web Key Set.
 * @returns {GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>}
 *
 * @example Usage
 * ```js
 * const JWKS = jose.createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))
 *
 * const { payload, protectedHeader } = await jose.jwtVerify(jwt, JWKS, {
 *   issuer: 'urn:example:issuer',
 *   audience: 'urn:example:audience'
 * })
 * console.log(protectedHeader)
 * console.log(payload)
 * ```
 */
module.exports = {
    createRemoteJWKSet: function(url, options) {
        return RemoteJWKSet.prototype.getKey.bind(new RemoteJWKSet(url, options));
    }
};
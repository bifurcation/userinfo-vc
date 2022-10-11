import fs from 'fs';
import * as jose from 'jose';
import { createClaimDigests } from './selective-disclosure';
import { Log, LOG_LEVEL } from './utils';

const createSdJwt = async (jwkJSON: jose.JWK, jwt: any, claimValues: any | undefined): Promise<string> => {
    try {
        let b64claimData: string = '';
        if (claimValues) {
            const result = createClaimDigests(claimValues);
            Object.defineProperty(jwt, "sd_digests", {value: result.sdDigests, enumerable: true});
            b64claimData = jose.base64url.encode(Buffer.from(JSON.stringify(result.svc)));
        }
        Object.defineProperty(jwt, "hash_alg", {value: "sha-256", enumerable:true});

        const jwtString = JSON.stringify(jwt);
        Log("JWT: " + jwtString, LOG_LEVEL.DEBUG);
        const payload = Buffer.from(jwtString);
        Log("JWS payload: " + payload.toString("hex").toUpperCase(), LOG_LEVEL.DEBUG);

        const jwk = await jose.importJWK(jwkJson, "ES256"); 
        let jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256 '})
        .sign(jwk);
        if (b64claimData) {
            jws = jws.concat('.', b64claimData);
        }
        Log
    }
}
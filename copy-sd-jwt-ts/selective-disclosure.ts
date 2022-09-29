import * as crypto from 'crypto';
import * as jose from 'jose';

export interface sdDigests {

}

export interface ClaimDigestResults {
    svc: any; //how to specify multiple keys with ClaimData values
    sdDigests: sdDigests;
}

const SALT_BYTE_SIZE = 128 / 8;

export const createClaimDigests = (claimValues:any): ClaimDigestResults => {
    let svc = {};
    let sdDigests = {};
    const names = Object.keys(claimValues);
    const values: string[] = Object.values(claimValues) //enumerates property values of claimValues
    
}
import { AzureFunction, Context, HttpRequest } from "@azure/functions";
import * as jwt from 'jsonwebtoken';
import * as rp from 'request-promise';
import { isArray } from 'util';
import * as fs from '../CreateCustomToken/firestore';
import {User} from '../CreateCustomToken/user'

export interface MSOpenIdKey {
    kty: string;
    use: string;
    kid: string;
    x5t: string;
    n: string;
    e: string;
    x5c: Array<string>;
    issuer: string;
}

/**
 * Retrieve the IDP signing keys. If this container is re-used for another function invocation, they may still be in memory.
 * If they're not in memory, keys will be retrieved from Firestore.
 * If no keys are in firestore, they will be retrieved via HTTPS call.
 *
 * If you do not want to use firestore to store the signing keys, you can perform the updateIdpKeys method on each authentication request.
 */
export async function getSignatureKeys(context: Context, tenantId: String): Promise<Array<MSOpenIdKey>> {
    let keys: Array<MSOpenIdKey> = [];
    if (keys.length !== 0) {
        return keys; // From container memory
    }
    keys = await getKeysFromDB(context);
    if (keys.length !== 0) { // Will be empty the first time.
        return keys;
    }
    return await updateIdpKeys(context, tenantId);
}

export async function getKeysFromDB(context: Context): Promise<Array<MSOpenIdKey>> {
    let result : Array<MSOpenIdKey> = [];
    const db = fs.getDB();
    const querySnapshot = await db.collection("IdpKeys").get();
    querySnapshot.forEach(function (doc) {
        result.push(doc.data() as MSOpenIdKey);
    });
    return result;
}

/**
 * Retrieve IDP signature keys.
 */
export async function updateIdpKeys(context: Context, tenantId : String): Promise<Array<MSOpenIdKey>> {
    let keysUri =  `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
    context.log.info (`keysUri: ${keysUri}`);
    const data = await rp({ uri: keysUri, json: true });
    let keys: Array<MSOpenIdKey> = [];
    if (data && data.keys && isArray(data.keys) && data.keys.length > 0) {
        const db = fs.getDB();
        data.keys.forEach(async (k: MSOpenIdKey) => {
            await db.collection('IdpKeys').doc(k.kid).set(k);
        });
        keys = data.keys; // Store in container. Will be re-used when container is re-used
        return keys;
    } else {
        context.log.error(`Received from MS openID endpoint: ${data}`);
        throw new Error("Could not read the keys from MS' openID discovery endpoint");
    }
}

export async function getOldKeys(context: Context, updatedKeys: Array<MSOpenIdKey>) {
    const db = fs.getDB();
    const querySnapshot = await db.collection("IdpKeys").get();
    const oldKeys: string[] = [];
    querySnapshot.forEach(doc => {
        if (!updatedKeys.some(k => k.kid === doc.id)) {
            oldKeys.push(doc.id);
        }
    });
    return oldKeys;
}

export async function verifyToken(context: Context, token: string, cert: string, issuerURI: string): Promise<User> {
    return new Promise((resolve, reject) => {
        context.log.info(`Selected signature key: ${cert}`);
        
        jwt.verify(token, convertCertificate(context, cert), {
            algorithms: ["RS256"], // Prevent the 'none' alg from being used
            issuer: issuerURI
        }, function (err, decoded: any) {
            if (err || !decoded) {
                context.log.error(`Could not verify token: ${err}`);
                if (!decoded) {
                    decoded = jwt.decode(token);
                }
                reject(err);
            } else {
                const userId = decoded.upn || decoded.unique_name || decoded.preferred_username;
                const displayName = decoded.name;
                if (!userId) {
                    context.log.error(`Could not find userId: ${JSON.stringify(decoded)}`);
                    reject("Could not find a userId in the response token");
                }
                let user = new User(userId, displayName)
                context.log.info(`logged-in user: ${user.uid}, ${user.displayName}`);
                resolve(user);
            }
        })
    }) as Promise<User>;
}

//Certificate must be in this specific format or else jwt's verify function won't accept it
export function convertCertificate(context: Context, originalCert: string) {
    const beginCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";
    let cert = originalCert.replace("\n", "");
    cert = cert.replace(beginCert, "");
    cert = cert.replace(endCert, "");

    let result = beginCert;
    while (cert.length > 0) {

        if (cert.length > 64) {
            result += "\n" + cert.substring(0, 64);
            cert = cert.substring(64, cert.length);
        }
        else {
            result += "\n" + cert;
            cert = "";
        }
    }
    if (result[result.length] !== "\n")
        result += "\n";
    result += endCert + "\n";
    return result;
}
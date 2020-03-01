import { AzureFunction, Context, HttpRequest } from "@azure/functions";
import * as utils from '../Shared/utils';
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as jwt from 'jsonwebtoken';
import * as rp from 'request-promise';
import { request } from "http";
import {User} from './user'

const cors = require('cors')({ origin: true });
const nonce = "42";

const tenantId = process.env["tenantId"];
const clientId = process.env["clientId"];
const clientSecret = process.env["clientSecret"];

const redirectUri = process.env["redirectUri"];

const issuerURI = `https://login.microsoftonline.com/${tenantId}/v2.0`; 

let keys: Array<utils.MSOpenIdKey> = [];

const httpTrigger: AzureFunction = async function (context: Context, req: HttpRequest): Promise<void> {
    //cors(req, res, async () => {
        if (req.query && req.query.error) {
            context.log.info('query and error:');
            context.log.error(`Authentication request error from Azure AD: ${req.query.error_description}. Full details: ${JSON.stringify(req.query)}`);
            context.res = {
                status: 400,
                body: `Oh oh, something went wrong. Please contact support with the following message: Invalid authentication request: ${req.query.error_description}`,
                isRaw: true,
            };
        } else if (req.body && req.body.code) {
            context.log.info('query and code:');
            const code = req.body.code;
            context.log.info(`code:${code}`);
            //POST here:
            var options = {
                resolveWithFullResponse: true,
                method: 'POST',
                uri: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
                form: {
                    // Like <input type="text" name="name">
                    client_id: clientId,
                    client_secret: clientSecret,
                    redirect_uri: redirectUri,
                    grant_type: 'authorization_code',
                    code: code,
                }
            };
            const response = await rp(options);
            context.log.info(`response:${response.body}`);
            const body = JSON.parse(response.body);
            const redirectUrl = response.headers['Location'];
            context.log.info(`redirectUrl:${redirectUrl}`);
            const redirectToUrl = `${redirectUri}?id_token=${body.id_token}&access_token=${body.access_token}`
            context.log.info(`redirectToUrl:${redirectToUrl}`);
            context.res = {
                status: 302,
                headers: {
                    'Location': redirectToUrl
                },
                body: 'Redirecting...'
            };
        } else if (req.query && req.query.access_token && req.query.id_token) {
            try {
                context.log.info('query, access_token and id_token:');
                const access_token = req.query.access_token;
                const id_token = req.query.id_token;
                const unverified_access_token: any = jwt.decode(access_token, { complete: true });
                const unverified_id_token: any = jwt.decode(id_token, { complete: true });
                context.log.info(`Unverified id_token decoding:`, JSON.stringify(id_token));
                context.log.info(`Unverified access_token decoding:`, JSON.stringify(access_token));
                if (!unverified_id_token || !unverified_id_token.payload || unverified_id_token.payload.iss !== issuerURI) {
                    context.log.error(`Invalid unverified token (iss): ${unverified_id_token}.`);
                    throw new Error(`Invalid issuer.  Actual: ${unverified_id_token.payload.iss} Expected: ${issuerURI}`);
                }
                if (!unverified_id_token.header || unverified_id_token.header.alg !== "RS256" || !unverified_id_token.header.kid) {
                    context.log.error(`Invalid header or algorithm on id_token.`);
                    throw new Error(`Invalid header or algorithm on id_token.`);
                }
                context.log.info('getting signature keys....');
                const k = await utils.getSignatureKeys(context, tenantId);
                context.log.info('got signature keys!');
                const signatureKey = k.find((c => {
                    return c.kid === unverified_id_token.header.kid;
                }));
                if (!signatureKey) {
                    context.log.info(`unverified_id_token.header.kid: ${unverified_id_token.header.kid}`);
                    context.log.info('-----------------------------------------------------------------');
                    context.log.info(`${JSON.stringify(k)}`);
                    context.log.info('-----------------------------------------------------------------');
                    context.log.info(`${JSON.stringify(k.map((key)=> key.kid))}`);
                    context.log.info('-----------------------------------------------------------------');
                    throw new Error(`Signature used in id_token is not in the list of recognized keys: `);
                }
                context.log.info(`signature key is: ${signatureKey.x5c[0]}`);
                const user = await utils.verifyToken(context, id_token, signatureKey.x5c[0], issuerURI);
                context.log.info(`user.uid:${user.uid}`);

                context.log.info('creating custom token...');
                const customToken = await admin.auth().createCustomToken(user.uid,);
                context.log.info(`customToken:${customToken}`);

                context.res = {
                    body: {customToken: customToken},
                };
            } catch (err) {
                context.log.error(`Failed to create custom token: ${err}`);
                context.res = {
                    status: 400,
                    body: `Oh oh, something went wrong. Please contact support with the following message: see the logs for more information.`,
                    isRaw: true,
                };
            }
        } else {
            // https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration
            // Redirect to IdP
            context.res = {
                status: 302,
                headers: {
                    'Location': `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&scope=openid&nonce=${nonce}&response_mode=form_post`
                },
                body: 'Redirecting...'
            };
        }
        context.done();
    //});
};

export default httpTrigger;

import { AzureFunction, Context } from "@azure/functions"
import * as admin from 'firebase-admin';
import * as utils from '../Shared/utils';

const timerTrigger: AzureFunction = async function (context: Context, myTimer: any): Promise<void> {
    var timeStamp = new Date().toISOString();
    
    if (myTimer.IsPastDue)
    {
        context.log('Timer function is running late!');
    }

    if (admin.apps.length == 0) {
        console.log("calling admin.initializeApp({credential: admin.credential.applicationDefault()}); ... ");
        admin.initializeApp({
            credential: admin.credential.applicationDefault()
        });
    }

    const db = admin.firestore();

    console.log("Refreshing IdP Public keys");
    const updatedKeys = await utils.updateIdpKeys(context, "991f4767-0fc0-45de-ad5c-67233b5e488d");
   
    // Remove old signing keys
    const toDelete = await utils.getOldKeys(context, updatedKeys);
    console.log(`${toDelete.length} keys to remove`);
    toDelete.forEach(async k => {
        try {
            await db.collection("IdpKeys").doc(k).delete();
            console.log(`Document ${k} deleted`);
        } catch (err) {
            console.error("Error removing document: ", err);
        }
    })

    context.log('Timer trigger function ran!', timeStamp);
};

export default timerTrigger;

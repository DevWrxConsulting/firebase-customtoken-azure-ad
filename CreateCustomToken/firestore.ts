import * as admin from 'firebase-admin'

export function getDB() {

    if (admin.apps.length == 0) {
        admin.initializeApp({
            credential: admin.credential.applicationDefault()
        });
    }

    return admin.firestore();
}

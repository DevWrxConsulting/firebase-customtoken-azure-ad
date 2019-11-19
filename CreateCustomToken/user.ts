export class User {
    uid: string;
    displayName: string;
    
    constructor(uid: string, displayName: string) {
        this.uid = uid;
        this.displayName = displayName;
    }
}
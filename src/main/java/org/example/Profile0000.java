package org.example;

public class Profile0000 {
    private byte[] profile;
    private Profile0000Data data;

    public class Profile0000Data {
        private byte[] serialNumber; // optional
        private byte[] issuer;       // optional
        private byte[] notBefore;    // optional
        private byte[] notAfter;     // optional
        private byte[] subject;      // optional
        private byte[] publicKey;    // mandatory
        private byte[] signature;    // mandatory

        public byte[] getSerialNumber() {return serialNumber;}
        public byte[] getIssuer() {return issuer;}
        public byte[] getNotBefore() {return notBefore;}
        public byte[] getNotAfter() {return notAfter;}
        public byte[] getSubject() {return subject;}
        public byte[] getPublicKey() {return publicKey;}
        public byte[] getSignature() {return signature;}
    }

    public Profile0000() {
        this.data = new Profile0000Data();
    }

    public void setProfile(byte[] set){
        this.profile = set;
    }

    public Profile0000Data getData(){
        return this.data;
    }

    public byte[] getProfile() {
        return profile;
    }

    public void setData(byte[] publicKey, byte[] signature) {
        setData(publicKey, signature, null, null, null, null, null);
    }

    public void setData(byte[] publicKey, byte[] signature, byte[] serialNumber) {
        setData(publicKey, signature, serialNumber, null, null, null, null);
    }

    public void setData(byte[] publicKey, byte[] signature,
                        byte[] serialNumber, byte[] issuer,
                        byte[] notBefore, byte[] notAfter,
                        byte[] subject) {

        if (publicKey == null || signature == null) {
            throw new IllegalArgumentException("Public key and signature are mandatory");
        }

        this.data.publicKey = publicKey;
        this.data.signature = signature;
        this.data.serialNumber = serialNumber;
        this.data.issuer = issuer;
        this.data.notBefore = notBefore;
        this.data.notAfter = notAfter;
        this.data.subject = subject;
    }

}

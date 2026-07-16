package org.example;

import com.upokecenter.cbor.CBORObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class IssuerSignedItem {
    public String digestID;
    public String random;
    public String elementIdentifier;
    public Map<Integer,Object> elementValue;

    private Map<Integer, Object> IssuerSignedItem_dict = new HashMap<>();
    private byte[] IssuerSignedItem_dict_cbor;

    public IssuerSignedItem(String digestID, String signedItemrandom, String elementID, Map<Integer,Object> elementvalue) {
        this.digestID = digestID;
        this.random = signedItemrandom;
        this.elementIdentifier = elementID;
        this.elementValue = elementvalue;
        this.IssuerSignedItem_dict.put(1,digestID);    //digestID
        this.IssuerSignedItem_dict.put(2,signedItemrandom);    //random
        this.IssuerSignedItem_dict.put(3,elementID);    //elementIdentifier
        this.IssuerSignedItem_dict.put(4,elementvalue);


        // 反序列化验证
        CBORObject IssuerSignedItemdecoded = CBORObject.DecodeFromBytes(getIssuerSignedItem_dict_cbor());
        System.out.println("IssuerSignedItem解码结果: " + IssuerSignedItemdecoded.ToJSONString());

    }

    public byte[] getIssuerSignedItem_dict_cbor() {
        // 转换为CBOR对象
        CBORObject IssuerSignedItemcborObj = CBORObject.NewMap();
        IssuerSignedItem_dict.forEach((key, value) -> IssuerSignedItemcborObj.Add(key, CBORObject.FromObject(value)));

        // 序列化为字节数组
        IssuerSignedItem_dict_cbor = IssuerSignedItemcborObj.EncodeToBytes();
        System.out.println("IssuerSignedItemCBOR字节长度: " + this.IssuerSignedItem_dict_cbor.length);
        return this.IssuerSignedItem_dict_cbor;
    }


    public Map<Integer, Object> getIssuerSignedItem_by_dict() {
        return IssuerSignedItem_dict;
    }


    public byte[] getIssuerSignedItem_by_bytes(PrivateKey sk) throws Exception {
        byte[] issuerSignedItem_bytes = TrustFramework.mapToBytes(this.IssuerSignedItem_dict);
        byte[] signed = ECC.signMessage(sk, issuerSignedItem_bytes);
        return signed;
    }

    public boolean verifyIssuerSignedItem_by_bytes(PublicKey pk, byte[] signed, byte[] issuerSignedItem_bytes) throws Exception {
        boolean verifyresult = ECC.verifySignature(issuerSignedItem_bytes, signed, pk);
        return verifyresult;
    }


}

package org.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.upokecenter.cbor.CBORObject;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Access_Document {

    //AD只向外暴露两个value：IssuerAuth和IssuerSignedItem
    public Map<Integer, Object> ADMap = new HashMap<>();

    // 创建HashMap字典，键为String，值为Integer
    private Map<Integer, Object> IssuerAuth_dict = new HashMap<>();
    private Map<Integer, Object> deviceKeyInfo = new HashMap<>();
    private Map<Integer, Object> validityInfo = new HashMap<>();

    private ArrayList<IssuerSignedItem> IssuerSignedItems = new ArrayList<>();
    private ArrayList<Map<Integer, Object>> IssuerSignedItem_list = new ArrayList<>();

    private byte[] IssuerAuth_dict_cbor;
    private byte[] IssuerSignedItem_dict_cbor ;

    private String  validFrom;
    private String  validUnitl;

    private PublicKey deviceKey;
    private byte[] signed;
    private ArrayList<byte[]> valueDigests = new ArrayList<>();
    private ArrayList<String> elementID = new ArrayList<>();
    private ArrayList<Map<Integer,Object>> elementValue = new ArrayList<>();

    public Access_Document(PublicKey deviceKey,  ArrayList<String> elementID, ArrayList<Map<Integer,Object>> elementValue) throws IOException {

        // valueDigests由document自己维护，在构造IssuerSignedItem后直接计算hash

        //初始化时构造IssuerSginedItem，等待CI签名完成完整初始化
        this.deviceKey = deviceKey;
        this.elementID = elementID;
        this.elementValue = elementValue;

        CBORFactory CBORsignedItem = new CBORFactory();
        ObjectMapper CBORsignedItemmapper = new ObjectMapper(CBORsignedItem);

        for(int i = 0; i < elementID.size(); i++){
//            String SignedItemrandom = TrustFramework.generateRandomString(10);
            String SignedItemrandom = "xoqiytcrfl";
            IssuerSignedItem signedItem = new IssuerSignedItem("123",SignedItemrandom, elementID.get(i), elementValue.get(i));

            byte[] ItemCBOR = signedItem.getIssuerSignedItem_dict_cbor();
            byte[] valueDigest = ECC.getSHA256Hex(ItemCBOR);

            valueDigests.add(valueDigest);

            IssuerSignedItems.add(signedItem);
            IssuerSignedItem_list.add(signedItem.getIssuerSignedItem_by_dict());

         }

        //直接把IssuerSignedItem_list转为一个IssuerSignedItem_dict_cbor
        CBORObject cborArray = CBORObject.NewArray();
        for (Map<Integer, Object> map : IssuerSignedItem_list) {
            CBORObject cborMap = CBORObject.NewMap();

            for (Map.Entry<Integer, Object> entry : map.entrySet()) {
                cborMap.Add(entry.getKey(), CBORObject.FromObject(entry.getValue()));
            }

            cborArray.Add(cborMap);
        }

        IssuerSignedItem_dict_cbor = cborArray.EncodeToBytes();

        this.validFrom = "20250101";
        this.validUnitl  = "20250101";

        deviceKeyInfo.put(1, deviceKey.getEncoded());   //deviceKey
        deviceKeyInfo.put(2, -7);   //keyInfo COSE ECDSA->-7

    }

    public PublicKey get_devicePubK(){
        return this.deviceKey;
    }

    //留给CI做签名用，补足AD
    public void get_IssuerSigned(byte[] signed){
        this.signed = signed;
    }

    //获取所有签名后完成validInfo构造
    private void form_validityInfo(){
        this.validityInfo.put(1, this.signed);   //signed
        this.validityInfo.put(2, this.validFrom);   //validFrom
        this.validityInfo.put(3, this.validUnitl);   //validUntil
        this.validityInfo.put(4, 1);   //expectedUpdate
        this.validityInfo.put(5, 1);   //validityIteration
    }

    public byte[] get_IssuerAuth_dict_cbor() throws JsonProcessingException {
        // 手动构建 deviceKeyInfo 的 CBOR
        CBORObject deviceKeyCbor = CBORObject.NewMap();
        deviceKeyCbor.Add(1, CBORObject.FromObject(this.deviceKey.getEncoded())); // deviceKey
        deviceKeyCbor.Add(2, CBORObject.FromObject(-7)); // keyInfo
        // 转换为CBOR对象
        CBORObject to_issuerAuthCbor = CBORObject.NewMap();
        to_issuerAuthCbor.Add(1, CBORObject.FromObject(1)); // version
        to_issuerAuthCbor.Add(2, CBORObject.FromObject(-16)); // digestAlgorithm
        to_issuerAuthCbor.Add(3, CBORObject.FromObject(this.valueDigests)); // valueDigests
        to_issuerAuthCbor.Add(4, deviceKeyCbor); // 将 deviceKeyInfo 添加到外层
        to_issuerAuthCbor.Add(6, CBORObject.FromObject(this.validityInfo));
        // 继续处理其他字段...
        to_issuerAuthCbor.Add(5, CBORObject.FromObject("Accss"));
        to_issuerAuthCbor.Add(7, CBORObject.FromObject(1));

        this.IssuerAuth_dict_cbor = to_issuerAuthCbor.EncodeToBytes();
        return this.IssuerAuth_dict_cbor;
    }

    public byte[] get_IssuerSignedItems_cbor() throws JsonProcessingException {
        return this.IssuerSignedItem_dict_cbor;
    }

    //构造完成validInfo后完成IssuerAuth构造
    public void form_IssuerAuth(){
        form_validityInfo();
        // 添加键值对
        this.IssuerAuth_dict.put(1, 1); //version
        this.IssuerAuth_dict.put(2, -16);  //digestAlgorithm   COSE SHA-256->-16
        this.IssuerAuth_dict.put(3, this.valueDigests);  //valueDigests
        this.IssuerAuth_dict.put(4, this.deviceKeyInfo);  //deviceKeyInfo
        this.IssuerAuth_dict.put(5, "Accss");  //docType --  Access -> Access Document; Revocation -> Revocation Document
        this.IssuerAuth_dict.put(6, this.validityInfo); //validityInfo
        this.IssuerAuth_dict.put(7, 1); //timeVerificationRequired
    }

    public IssuerSignedItem getIssuerSignedItem_by_ind(int ind){
        return this.IssuerSignedItems.get(ind);
    }

    public List<IssuerSignedItem> getIssuerSignedItems_list(){
        return this.IssuerSignedItems;
    }

    public byte[] getAD_CBOR() throws IOException {
        this.ADMap.put(1,IssuerAuth_dict);
        this.ADMap.put(2,IssuerSignedItem_list);

        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper mapper = new ObjectMapper(cborFactory);

        byte[] cborBytes = mapper.writeValueAsBytes(this.ADMap);
        // 输出 CBOR 的十六进制表示
        StringBuilder sb = new StringBuilder();
        for (byte b : cborBytes) {
            sb.append(String.format("%02X ", b));
        }
        System.out.println("CBOR Hex: " + sb.toString());

        return cborBytes;
    }

    public static Map<Integer, Object> get_decode(byte[] cborBytes) throws IOException {
        // 反序列化回 Map 验证
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper mapper = new ObjectMapper(cborFactory);
        JavaType type = TypeFactory.defaultInstance().constructMapType(Map.class, Integer.class, Object.class);
        Map<Integer, Object> decoded = mapper.readValue(cborBytes, type);

        System.out.println("Decoded: " + decoded);
        return decoded;
    }

    public boolean saveADtofile(String file){
        Map<String, Object> combinedMap = new HashMap<>( );
        combinedMap.put("IssuerAuth", this.IssuerAuth_dict_cbor);
        combinedMap.put("IssuerSignedItem", this.IssuerSignedItem_dict_cbor);

        ObjectMapper mapper = new ObjectMapper();

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(file), combinedMap);
            System.out.println("字典已保存到combined.json");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }


}
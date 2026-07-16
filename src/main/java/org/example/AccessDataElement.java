package org.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AccessDataElement {

    //AccessRulesCapabilitiesBits
    public static final int SECURE = 0;                        // 0b00000001
    public static final int UNSECURED = 1;                      // 0b00000010
    public static final int TOGGLE_SECURED_OR_UNSECURED = 2;    // 0b00000100
    public static final int MOMENTARY_UNSECURE = 3;            // 0b00001000
    public static final int EXTENDED_MOMENTARY_UNSECURE = 4;   // 0b00010000
    public static final int PAYMENT_PERMISSION = 5;            // 0b00100000

    // mask保留位（6-15，RFU）
    public static final int RFU_MASK = 0b0000000000000000;     // 0xFFC0

    // 必须字段（SHALL）
    private String version;

    private Map<Integer, Object> access_Data = new HashMap<>();;

    // 可选字段（MAY）
    private String id;
    Map<Integer, Object> readerRules = new HashMap<>();
    Map<Integer, Object> accessRules = new HashMap<>();
    private List<String> schedules;
    private List<String> accessExtensions;
    private List<String> nonAccessExtensions;

    // 构造方法（强制要求version）
    public AccessDataElement(String version, String ID) {
        if (version == null) {
            throw new IllegalArgumentException("Version is mandatory");
        }
        this.version = version;
        this.id = ID;
        //initiate accessRules
        this.accessRules.put(0,accessRules.get(0));   //AccessRule_Capabilities
        this.accessRules.put(1,accessRules.get(1));   //AccessRule_AllowScheduleIds
        this.accessRules.put(2,accessRules.get(2));   //AccessRule_DenyScheduleIds
    }


    // Getter & Setter
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getId() { return id; }
    public void setId(String id) {
        // 校验字节长度（注意：不是字符长度！）
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8); // 明确指定编码
        if (idBytes.length < 1 || idBytes.length > 16) {
            throw new IllegalArgumentException("ID must be 1-16 bytes long");
        }
        this.id = id;
    }

    // 其他可选字段的getter/setter...
    public Map getAccessRules() { return  this.accessRules; }
    public void setAccessRules(int AccessRule_Capabilities, int AccessRule_AllowScheduleIds, int AccessRule_DenyScheduleIds) {
        // 检查键是否在预定义列表中
        //与标准不同，本项目强制检查Rule中的每个字段
        this.accessRules.put(0, AccessRule_Capabilities);
        this.accessRules.put(1, AccessRule_AllowScheduleIds);
        this.accessRules.put(2, AccessRule_DenyScheduleIds);
    }


    //时间表字段的解析暂时不支持

    public List<String> getSchedules() { return schedules; }
    public void setSchedules(List<String> schedules) {
        if (schedules == null || schedules.isEmpty()) {
            throw new IllegalArgumentException("Schedules list cannot be empty (min 1 element)");
        }
        if (schedules.size() > 8) {
            throw new IllegalArgumentException("Schedules list cannot exceed 8 elements");
        }
        this.schedules = new ArrayList<>(schedules); // 防御性拷贝
    }

    public void setReaderRules(Map<Integer, Object>  readerRules) {
        if (readerRules == null || readerRules.isEmpty()) {
            throw new IllegalArgumentException("ReaderRules list cannot be empty (min 1 element)");
        }
        if (readerRules.size() > 8) {
            throw new IllegalArgumentException("ReaderRules list cannot exceed 8 elements");
        }
        this.readerRules = readerRules; // 防御性拷贝
    }

    public List<String> getaccessExtensions() { return accessExtensions; }
    public void setaccessExtensions(List<String> accessExtensions) {
        this.accessExtensions = accessExtensions;
    }

    public List<String> getnonAccessExtensions() { return nonAccessExtensions; }
    public void setnonAccessExtensions(List<String> nonAccessExtensions) {
        this.nonAccessExtensions = nonAccessExtensions;
    }

    public void AccessDocument_to_form() {
        this.access_Data.put(0, this.version);                  // version → 0
        this.access_Data.put(1, this.id);                       // id → 1
        this.access_Data.put(2, this.accessRules);               // accessRules → 2
        this.access_Data.put(3, this.schedules);                // schedules → 3
        this.access_Data.put(4, this.readerRules);              // readerRules → 4
        this.access_Data.put(5, this.nonAccessExtensions);      // nonAccessExtensions → 5
        this.access_Data.put(6, this.accessExtensions);        // accessExtensions → 6

    }

    //提取map
    public Map<Integer,Object> getAccessDataelement() {
        return this.access_Data;
    }

    //格式转换
    public byte[] mapToCbor() throws IOException {
        ObjectMapper mapper = new ObjectMapper(new CBORFactory());
        return mapper.writeValueAsBytes(this.access_Data); // 直接序列化为CBOR字节数组
    }

    //IssuerSignedItem 封装
    public byte[] toIssuerSignedItem(byte[] digestID, byte[] random, byte[] elementIdentifier, byte[] elementValue) throws JsonProcessingException {
        Map<Integer, Object> IssuerSignedItem = new HashMap<>();
        IssuerSignedItem.put(1, digestID);
        IssuerSignedItem.put(2, random);
        IssuerSignedItem.put(3, elementIdentifier);
        IssuerSignedItem.put(4, elementValue);

        ObjectMapper mapper = new ObjectMapper(new CBORFactory());
        return mapper.writeValueAsBytes(IssuerSignedItem); // 直接序列化为CBOR字节数组
    }


}

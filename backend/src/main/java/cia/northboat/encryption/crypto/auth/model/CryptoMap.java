package cia.northboat.encryption.crypto.auth.model;

import cia.northboat.encryption.utils.EncodeUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import lombok.Data;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@Data
public class CryptoMap {

    Map<String, String> cryptoMap;

    public CryptoMap(){
        cryptoMap = new HashMap<>();
    }

    public void put(String key, Element val){
        cryptoMap.put(key, EncodeUtil.parseElement2Base64Str(val));
    }


    public void put(String key, BigInteger val){
        cryptoMap.put(key, EncodeUtil.parseBigInteger2HexStr(val));
    }

    public void put(String ... kv){
        int n = kv.length;
        if(n % 2 != 0){
            return;
        }
        for(int i = 0; i < n; i+=2){
            cryptoMap.put(kv[i], kv[i+1]);
        }
    }

    public String get(String key){
        return cryptoMap.get(key);
    }

    public Element getE(String id, Field field){
        return EncodeUtil.parseBase64Str2Element(cryptoMap.get(id), field);
    }

    public BigInteger getI(String key){
        return EncodeUtil.parseHexStr2BigInteger(cryptoMap.get(key));
    }

    public String toString(){
        return cryptoMap.toString();
    }
}

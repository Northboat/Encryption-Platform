package cia.northboat.encryption.service;

import cia.northboat.encryption.crypto.arch.RangedSEArchetype;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class RangedSEService {

    private final RangedSEArchetype rangedSEArchetype;

    public RangedSEService(RangedSEArchetype rangedSEArchetype){
        this.rangedSEArchetype = rangedSEArchetype;
    }


    public Map<String, Object> params(){
        return rangedSEArchetype.getSystemParams();
    }

    public Map<String, Object> auth(){
        long s = System.currentTimeMillis();
        Map<String, Object> data = rangedSEArchetype.mutualAuth();
        long e = System.currentTimeMillis();
        data.put("time_cost", e-s);
        return data;
    }

    public Map<String, Object> buildMatrix(){
        long s = System.currentTimeMillis();
        Map<String, Object> data = rangedSEArchetype.buildMatrix();
        long e = System.currentTimeMillis();
        data.put("time_cost", e-s);
        return data;
    }

    public Map<String, Object> query(){
        long s = System.currentTimeMillis();
        Map<String, Object> data = rangedSEArchetype.search();
        long e = System.currentTimeMillis();
        data.put("time_cost", e-s);
        return data;
    }

}

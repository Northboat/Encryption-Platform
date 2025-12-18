package cia.northboat.encryption.service;

import cia.northboat.encryption.crypto.arch.SimpleMinerArchetype;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class BlockChainService {
    private final SimpleMinerArchetype simpleMinerArchetype;

    public BlockChainService(SimpleMinerArchetype simpleMinerArchetype){
        this.simpleMinerArchetype = simpleMinerArchetype;
    }


    public Map<String, Object> mine(int difficulty){
        return simpleMinerArchetype.mine(difficulty);
    }
}

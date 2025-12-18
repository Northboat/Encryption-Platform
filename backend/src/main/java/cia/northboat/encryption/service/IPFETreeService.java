package cia.northboat.encryption.service;

import cia.northboat.encryption.crypto.tree.EncryptedTree;
import cia.northboat.encryption.crypto.tree.model.TreeNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class IPFETreeService {

    private final EncryptedTree encryptedTree;
    @Autowired
    public IPFETreeService(EncryptedTree encryptedTree){
        this.encryptedTree = encryptedTree;
    }


    public Map<String, Object> buildTree(int count, int dimension){
        Map<String, Object> data = new HashMap<>();

        encryptedTree.clean();
        encryptedTree.init(dimension);
        long cost = encryptedTree.randomBuild(count);
        data.put("time_cost", cost);


        String htmlTreeStr = encryptedTree.getTreeStruct().replace("\n", "<br>");
        htmlTreeStr = htmlTreeStr.replace(" ", "&nbsp;");

        data.put("tree", htmlTreeStr);
        data.put("height", encryptedTree.getHeight());

        return data;
    }



    public Map<String, Object> search(List<String> data){
        Map<String, Object> res = new HashMap<>();

        if(encryptedTree.getHeight() == 0){
            res.put("Error", "Please build tree first");
            return res;
        }

        long s = System.currentTimeMillis();
        // 匹配
        TreeNode target = encryptedTree.search(data);
        long e = System.currentTimeMillis();

        res.put("time_cost", e-s);
        res.put("target_node", target == null ? "null" : target);

//        data.put("Error", "Search haven't finished yet. Nothing seems to match here. I suspect there's an issue with the search logic. I'll fix it later when I have time. Maybe the matching formula is also problematic");

        return res;
    }
}

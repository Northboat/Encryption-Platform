package cia.northboat.encryption.crypto.tree;

import cia.northboat.encryption.crypto.tree.model.Ciphertext;
import cia.northboat.encryption.crypto.tree.model.TreeNode;
import cia.northboat.encryption.utils.EncodeUtil;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Getter
@Setter
@Component
@Slf4j
public class EncryptedTree {

    TreeNode root;
    Field G1, Zr;
    int height, n, size; // 这个 n 是字段的个数 → 树的维度

    @Autowired
    public EncryptedTree(Field G1, Field Zr){
        this.G1 = G1;
        this.Zr = Zr;
        height = 0;
    }

    public void init(int dimension){
        setN(dimension);
        IPFEMachine.keygen(G1, Zr, dimension);
    }


    public void clean(){
        root = null;
        height = 0;
        size = 0;
    }


    public TreeNode insert(String[] cur){
        // 将明文哈希，将用于前缀比较和 x 生成
        Element[] curX = HashUtil.hashStrArr2ZrArr(Zr, cur);
        if(root == null){
            String[] initPrefix = new String[n];
            // 初始化一个前缀，这会浪费 n 长度的前缀
            Arrays.fill(initPrefix, "0");
            root = IPFEMachine.enc(Zr, initPrefix, curX);
            height++;
            size++;
//            return root;
        }
        return insert(root.getPrefix(), curX, root, 1);
    }


    public TreeNode insert(String[] pre, Element[] curX, TreeNode root, int h){

        int n = root.getN();
        Element[] x = root.getX();

        String z = EncodeUtil.singleDimensionDec(x, curX, n); // 增加的前缀
        String[] newPrefix = EncodeUtil.superposePrefix(pre, z, n); // 构成新的前缀

        TreeNode node = IPFEMachine.enc(Zr, newPrefix, curX); // 根据当前前缀和明文哈希生成节点

        int i = Integer.parseInt(z, 2); // 解析二进制为十进制
        TreeNode child = root.getSubtree()[i];
        h++; // 选取到了孩子，层高 +1

        // 如果这里为空，就直接插入
        if(child == null){
            root.setSubtree(node, i);
            height = Math.max(height, h);
            size++;
            return node;
        }
        // 否则继续向下找
        return insert(newPrefix, curX, child, h);
    }


    private List<List<String>> data;
    public long randomBuild(int count){
        data = generateData(count, getN());
        long cost = build(data);
        log.info("Tree has been built, Tree height is {}", this.height);
        return cost;
    }


    public long build(List<List<String>> list){
        long s = System.currentTimeMillis();
        for(List<String> l : list){
            insert(l.toArray(new String[0]));
        }
        long e = System.currentTimeMillis();
        return e - s;
    }


    public List<List<String>> generateData(int count, int dimension){
        Set<List<String>> uniqueLists = new HashSet<>();
        while (uniqueLists.size() < count) {
            List<String> innerList = new ArrayList<>();
            for (int j = 0; j < dimension; j++) {
                // 这里用 UUID 或者随机数
                innerList.add(UUID.randomUUID().toString().substring(0, 8));
                // innerList.add("val_" + random.nextInt(10000)); // 也可以用随机数
            }
            log.info("The node has been generated: {}", innerList);
            uniqueLists.add(innerList); // HashSet 会帮我们去重
        }

        return new ArrayList<>(uniqueLists);
    }



    public List<TreeNode> search(){
        List<TreeNode> result = new ArrayList<>();
        for(List<String> l : data){
            result.add(search(l));
        }
        return result;
    }


    public TreeNode search(List<String> query){
        String[] cur = query.toArray(new String[0]);
        // 将明文哈希
        Element[] y = HashUtil.hashStrArr2ZrArr(Zr, cur);

        Ciphertext ciphertext = IPFEMachine.trap(Zr, y);
        return search(root, ciphertext);
    }


    public TreeNode search(TreeNode node, Ciphertext ciphertext){
        if(node == null || ciphertext == null){
            return null;
        }
        if(match(node, ciphertext)) {
            return node;
        }

        String z = EncodeUtil.singleDimensionDec(node.getX(), ciphertext.getY(), n); // 增加的前缀
        int i = Integer.parseInt(z, 2);

        return search(node.getSubtree()[i], ciphertext);
    }


    public boolean match(TreeNode node, Ciphertext ciphertext){
        Element g = IPFEMachine.getBase();
        return IPFEMachine.match(G1, Zr, node, ciphertext, g);
    }


    public String getTreeStruct() {
        StringBuilder sb = new StringBuilder();
        getTreeStruct(root, "", false, sb);
        return sb.toString();
    }



    // DFS
    public void getTreeStruct(TreeNode node, String prefix, boolean isTail, StringBuilder sb) {
        if (node == null) return;

//        System.out.println(node);

        sb.append(prefix).append(isTail ? "└── " : "├── ");
        sb.append(formatPrefix(node)).append("\n");
        TreeNode[] children = node.getSubtree();
        int childCount = (int) Arrays.stream(children).filter(Objects::nonNull).count();

        int printed = 0;
        for (int i = 0; i < (int)Math.pow(2, n); i++) {
            TreeNode child = children[i];
            if (child != null) {
                printed++;
                boolean last = (printed == childCount);
                getTreeStruct(child, prefix + (isTail ? "    " : "│   "), last, sb);
            }
        }
    }

    public String formatPrefix(TreeNode node){
        return node.getPrefixStr() != null ? node.getPrefixStr() : "";
    }
}

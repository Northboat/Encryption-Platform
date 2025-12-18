package cia.northboat.encryption.crypto.tree.model;

import it.unisa.dia.gas.jpbc.Element;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TreeNode {

    private int n; // 长度
    private String[] prefix; // 前缀
    private TreeNode[] subtree; // 子树

    // 密文
    private Element[] x; // 这个 x 是哈希后的明文，用于比较生成前缀，同时用来加密
    private Element s_x, t_x;


    public String getPrefixStr(){
        StringBuilder sb = new StringBuilder();
        for(String s : prefix){
            sb.append(s);
        }
        return sb.toString();
    }


    public void setSubtree(TreeNode t, int i){
        this.subtree[i] = t;
    }


}

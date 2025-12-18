package cia.northboat.encryption.crypto.pairing.impl;

import cia.northboat.encryption.crypto.pairing.PairingSystem;
import cia.northboat.encryption.utils.BitUtil;
import cia.northboat.encryption.utils.HashUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class DuMSE extends PairingSystem {


    @Autowired
    public DuMSE(Field G1, Field GT, Field Zr, Pairing bp){
        super(G1, GT, Zr, bp);
    }


    private Element g, sk_o, sk_i, sk_fs, sk_ss;
    public Map<String, Element> record;
    @Override
    public void setup(){
        g = randomG();
        sk_o = randomZ();
        sk_i = randomZ();
        sk_fs = randomZ();
        sk_ss = randomZ();

        // 在 enc 中用到的用户数据
        record = new HashMap<>();
        id = this.getZr().newElement(123456).getImmutable();
        sk_id = this.getZr().newElement(123456789).getImmutable();
    }

    Element pk_o, pk_i, pk_fs, pk_ss;
    @Override
    public void keygen(){
        pk_o = g.powZn(sk_o.invert()).getImmutable();
        pk_i = g.powZn(sk_i.invert()).getImmutable();
        pk_fs = g.powZn(sk_fs).getImmutable();
        pk_ss = g.powZn(sk_ss).getImmutable();
    }


    public Element id, sk_id, C1, C2, C3, L;
    @Override
    public void enc(String str){
        Element[] w = h(str);
        Element r = randomZ();

        // log(q) 位的随机数
        L = BitUtil.random(this.getZr(), (int)Math.log(getQ()));

        // 不知道哪来的参数
        Element p = randomZ(), pr = randomZ();

        C2 = g.powZn(r).getImmutable();

        System.out.println("L: " + L);

        // 连接，这里的连接如果超出了 Zr 群的上限，将会除余，可能会影响后续的分割，即还原不了
        Element h = BitUtil.connect(this.getZr(), id, L, sk_id);

        Element s = BitUtil.split(this.getZr(), h, id, sk_id);

        // 这里涉及到一个异或操作，我直接把他处理为 BigInteger 的 xor 操作，应该没问题
        // 并且在哈希的时候限定了哈希值的长度，这个处理很有可能有问题
        if(!record.containsKey(str)){
            record.put(str, L);
            Element p1 = pairing(HashUtil.hashZrArr2G(g, w).powZn(p), pk_ss).powZn(sk_o.invert()).getImmutable();

            // 没问题
            C1 = HashUtil.hashGT2ZrWithQ(this.getZr(), p1, (int)Math.log(getQ())).getImmutable();

            Element p2 = pairing(g.powZn(pr), pk_ss).powZn(sk_o.invert()).getImmutable();
            // 这里有问题捏，只要在某一区间就行 [-6, 24]，太神奇了，Math.log(q) 也行
            Element p3 = HashUtil.hashGT2ZrWithQ(this.getZr(), p2, (int)Math.log(id.toBigInteger().bitLength() + getQ() + sk_id.toBigInteger().bitLength()));

            C3 = BitUtil.xor(this.getZr(), p3, h);

        } else {
            C1 = record.get(str);
            Element p1 = pairing(g.powZn(pr), pk_ss).powZn(sk_o.invert()).getImmutable();
            Element p2 = HashUtil.hashGT2ZrWithQ(this.getZr(), p1, (int)Math.log(id.toBigInteger().bitLength() + getQ() + sk_id.toBigInteger().bitLength()));
            C3 = BitUtil.xor(this.getZr(), p2, h);
            record.put(str, L);
        }
    }

    public Element AI_o;
    public Element T1, T2, T3, T_1, T_2;
    // 陷门计算应该没问题，不涉及一些敏感操作
    @Override
    public void trap(String str){
        AI_o = randomG();
        Element[] w = h(str);
        Element r1 = randomZ(), r2 = randomZ();
        T1 = pk_ss.powZn(r1).getImmutable();
        T2 = pk_fs.powZn(r2).getImmutable();
        T3 = HashUtil.hashZrArr2G(g, w).powZn(sk_i).mul(g.powZn(r1.add(r2))).getImmutable();

        T_1 = T1.getImmutable();
        T_2 = pairing(T3.div(T2.powZn(sk_fs.invert())), AI_o).getImmutable();
    }

    Element L1;
    @Override
    public boolean search(){
        Element p1 = pairing(T_1, AI_o).getImmutable();
        Element p2 = T_2.powZn(sk_ss).getImmutable();

        // 又用到了这个哈希
        L1 = HashUtil.hashGT2ZrWithQ(this.getZr(), p2.div(p1), (int)Math.log(getQ())).getImmutable();

        Element U1 = pairing(C2, AI_o).powZn(sk_ss).getImmutable();
        Element U2 = C3;

        Element p3 = HashUtil.hashGT2ZrWithQ(this.getZr(), U1.powZn(sk_i), (int)Math.log(getQ())).getImmutable();

        // 异或
        Element Msg = BitUtil.xor(this.getZr(), p3, U2);
        // 分割
        Element Pt = BitUtil.split(this.getZr(), Msg, id, sk_id);

        System.out.println("L': " + L1);
        return false;
    }


    @Override
    public Map<String, Object> test(String word, List<String> words, int round) {
        Map<String, Object> data = super.test(word, words, round);
        data.put("flag", false);
        data.put("L", L);
        data.put("L'", L1);
        return data;
    }

}

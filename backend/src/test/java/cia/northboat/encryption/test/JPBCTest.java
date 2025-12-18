package cia.northboat.encryption.test;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.security.SecureRandom;

public class JPBCTest {
    public static Field G1, G2, GT, Zr;
    private static final Pairing bp;
    // 加密单词长度，为 2n
    private static final int n;

    static{
        bp = PairingFactory.getPairing("a.properties");
        G1 = bp.getG1();
        G2 = bp.getG2();
        GT = bp.getGT();
        Zr = bp.getZr();
        n = 12;
    }

    public static void main(String[] args) {
//        genParams();
//        TestUtil.singleThreadTest(G1, G2, GT, Zr, bp, n);
//        TestUtil.multiThreadTest(G1, G2, GT, Zr, bp, n);
//        RangedSEArchetype rangedSEArchetype = new RangedSEArchetype(G1, GT, Zr, bp);
//        rangedSEArchetype.test();

//        HVE hve = new HVE(G1, GT, Zr, bp, n, 3);
//        hve.setup();
//        hve.keygen();
//        hve.enc("101");
//        hve.trap("1*0");
//        System.out.println(hve.search());
//
//        // ✅ 示例输入：cell 概率分布
//        Map<String, Double> cells = new HashMap<>();
//        cells.put("A", 0.85);
//        cells.put("B", 0.15);
//        cells.put("C", 0.60);
//        cells.put("D", 0.35);
//        cells.put("E", 0.95);
//
//        Map<String, String> encoded = hve.grayOptimizer(cells, 7);
//
//        // ✅ 输出分配结果
//        System.out.println("Cell → Gray 编码分配结果：");
//        for (Map.Entry<String, String> entry : encoded.entrySet()) {
//            System.out.println("Cell " + entry.getKey() + " → " + entry.getValue());
//        }
        test();
    }

    public static void test(){
        Element u = G1.newRandomElement().getImmutable();
        Element v = G2.newRandomElement().getImmutable();
        Element a = Zr.newRandomElement().getImmutable();
        Element b = Zr.newRandomElement().getImmutable();
        System.out.println(u);
        System.out.println(a);


        // 三、计算等式左半部分
        Element ua = u.powZn(a);
        Element vb = v.powZn(b);
        Element left = bp.pairing(ua,vb);

        // 四、计算等式右半部分
        Element euv = bp.pairing(u,v).getImmutable();
        Element ab = a.mul(b);
        Element right = euv.powZn(ab);

        if (left.isEqual(right)) {
            System.out.println("Yes");
        } else {
            System.out.println("No");
        }
    }

    public static void genParams(){
        // 1. 创建固定种子的 SecureRandom 实例
        SecureRandom fixedRandom = new SecureRandom();
        fixedRandom.setSeed(12345L);  // 固定随机种子
        // 初始化 type a 类型曲线
        PairingParametersGenerator pg = new TypeACurveGenerator(160, 512);
        // 生成参数
        PairingParameters params = pg.generate();
        // 打印参数
        System.out.println(params.toString());
    }
}

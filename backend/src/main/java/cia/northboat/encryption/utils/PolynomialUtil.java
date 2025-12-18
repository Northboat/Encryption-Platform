package cia.northboat.encryption.utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PolynomialUtil {
    public static List<Element> getCoefficients(Field Zr, List<Element> factors){
        int l = factors.size();

        List<Element> coefficients = new ArrayList<>(l+1);
        for (int i = 0; i <= l; i++) {
            coefficients.add(Zr.newZeroElement().getImmutable());
        }

        coefficients.set(0, Zr.newOneElement().getImmutable());
        // 动态规划计算系数
        for (Element factor: factors) {
            for (int j = l; j >= 1; j--) {
                // 更新系数：c_j = c_j + c_{j-1} * a_i
                coefficients.set(j, coefficients.get(j).add(coefficients.get(j - 1).mul(factor)).getImmutable());
            }
        }
        // 添加符号：c_k = (-1)^k * c_k
        for (int k = 1; k <= l; k++) {
            if(k % 2 == 1){
                coefficients.set(k, coefficients.get(k).negate().getImmutable());
            }
        }
        Collections.reverse(coefficients);
        return coefficients;
    }

    public static List<Integer> getCoefficients(List<Integer> a) {
        int n = a.size();
        // 初始化系数列表，长度为 n + 1，默认值为 0
        List<Integer> coefficients = new ArrayList<>(n + 1);
        for (int i = 0; i <= n; i++) {
            coefficients.add(0);
        }
        // x^n 的系数总是 1
        coefficients.set(0, 1);

        // 动态规划计算系数
        for (Integer ai : a) {
            for (int j = n; j >= 1; j--) {
                // 更新系数：c_j = c_j + c_{j-1} * a_i
                coefficients.set(j, coefficients.get(j) + coefficients.get(j - 1) * ai);
            }
        }

        // 添加符号：c_k = (-1)^k * c_k
        for (int k = 1; k <= n; k++) {
            coefficients.set(k, coefficients.get(k) * (int)Math.pow(-1, k));
        }
        Collections.reverse(coefficients);
        return coefficients;
    }

    public static void main(String[] args) {
        // 示例：计算 (x - a)(x - b)(x - c) 的系数
        List<Integer> a = List.of(1, 1, 1);
        List<Integer> coefficients = getCoefficients(a);

        // 输出结果
        System.out.println("多项式系数为: " + coefficients);
    }
}

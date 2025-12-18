package cia.northboat.encryption.test;

import java.util.Map;

public class EncodeTest {


    public static void main(String[] args) {

        int base = 100;

        for(int i = 0; i < 7; i++){
            long timeCost0 = 0, timeCost1 = 0;

            for(int j = 0; j < base; j++){
                int randomNum = (int)(Math.random()*10000000+1);
                String randomStr = Integer.toBinaryString(randomNum);
                String randomStrWithPadding = String.format("%5s", randomStr).replaceAll(" ", "0");
                Map<String, Object> encResult0 = enc0(randomStrWithPadding);
                Map<String, Object> encResult1 = enc0(randomStrWithPadding);
//                System.out.println(encResult0);
//                System.out.println(encResult1);

                timeCost0 += (long)encResult0.get("time");
                timeCost1 += (long)encResult1.get("time");
            }

            System.out.println("Count: " + base);
            System.out.println("Encode 0 Cost: " + timeCost0);
            System.out.println("Encode 1 Cost: " + timeCost1);

            base += 50;
        }
    }


    public static StringBuilder subComma(StringBuilder str){
        if (!str.isEmpty() && ',' == str.charAt(str.length() - 1)){
            return new StringBuilder(str.substring(0, str.length() - 1));
        }
        return str;
    }


    public static Map<String, Object> enc0(String num) {
        long s = System.nanoTime();
        StringBuilder result = new StringBuilder();
        for (int i = num.length() - 1; i > -1; i--) {
            if ('0' == num.charAt(i)) {
                for (int j = 0; j < i; j++)
                    result.append(num.charAt(j));
                result.append('1');
                result.append(",");
            }
        }
        result = subComma(result);
        long e = System.nanoTime();

        return Map.of("result", result.toString(), "time", e-s);
    }



    public static Map<String, Object> enc1(String num) {
        long s = System.nanoTime();
        StringBuilder result = new StringBuilder();
        for (int i = num.length() - 1; i > -1; i--) {
            if ('1' == num.charAt(i)) {
                for (int j = 0; j <= i; j++)
                    result.append(num.charAt(j));
                if(i != 0) {
                    result.append(",");
                }
            }
        }
        result = subComma(result);
        long e = System.nanoTime();

        return Map.of("result", result.toString(), "time", e-s);
    }
}

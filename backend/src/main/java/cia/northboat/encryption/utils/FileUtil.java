package cia.northboat.encryption.utils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileUtil {

    public static String readDocs(String path) {
        InputStream inputStream = FileUtil.class.getClassLoader().getResourceAsStream(path);
        String docs = null;
        // 这样写流会自动关闭（脱离了作用范围）
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            // 接收文件内容 stringBuffer线程安全
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            docs = stringBuilder.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return docs;
    }


    /**
     * 读取文件并将每行内容存储到 List<String> 中
     *
     * @param filePath 文件的相对路径
     * @return 包含文件每行内容的 List<String>
     * @throws IOException 如果文件读取失败
     */
    public static List<String> readFileToList(String filePath) {
        List<String> lines = new ArrayList<>();

        // 使用 ClassLoader 获取资源流
        try (InputStream inputStream = FileUtil.class.getClassLoader().getResourceAsStream(filePath);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            if (inputStream == null) {
                throw new IOException("文件未找到: " + filePath);
            }

            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line); // 将每行内容添加到 List 中
            }
        } catch (IOException e){
            System.err.println("读取文件失败: " + e.getMessage());
            return null;
        }

        return lines;
    }

    public static void writeCostToLog(String logMessage){
        // 将日志写入文件
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("time.log", true))) { // true 表示追加模式
            writer.write(logMessage);
        } catch (IOException e) {
            System.err.println("写入日志文件失败: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        String filePath = "data/pairing/100.txt"; // 文件的相对路径

        List<String> lines = readFileToList(filePath);
        assert lines != null;
        for (String line : lines) {
            System.out.println(line); // 打印每行内容
        }

        String path = "data/arch/1";
        System.out.println(readDocs(path));
    }
}
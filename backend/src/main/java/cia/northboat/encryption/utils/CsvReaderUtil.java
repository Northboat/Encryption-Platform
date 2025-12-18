package cia.northboat.encryption.utils;

import com.opencsv.CSVReader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Component
public class CsvReaderUtil {

    private final ResourceLoader resourceLoader;

    public CsvReaderUtil(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    /**
     * 读取CSV文件并按指定范围截取字段
     * @param filePath 资源文件路径（如classpath:data.csv）
     * @param startIndex 起始索引（包含，从0开始）
     * @param endIndex 结束索引（包含）
     * @return 处理后的List<List<String>>
     */
    public List<List<String>> readCsvWithRange(String filePath, int startIndex, int endIndex, int length) {
        List<List<String>> result = new ArrayList<>();

        try {
            // 加载资源文件
            Resource resource = resourceLoader.getResource(filePath);
            // 创建CSV读取器
            try (CSVReader reader = new CSVReader(
                    new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {

                String[] line;
                // 逐行读取
                while ((line = reader.readNext()) != null &&  result.size() < length) {
                    List<String> row = new ArrayList<>();
                    // 截取指定范围的字段
                    for (int i = startIndex; i <= endIndex && i < line.length; i++) {
                        row.add(line[i]);
                    }
                    result.add(row);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("CSV文件读取失败", e);
        }

        return result;
    }
}
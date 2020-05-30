package com.debuggor.common;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.*;

/**
 * 读写json文件
 *
 * @Author:yong.huang
 * @Date:2020-05-30 17:37
 */
public class ReadWriteJson {

    public static String readJsonFile(String fileName) {
        String jsonStr = "";
        try {
            File jsonFile = new File(fileName);
            FileReader fileReader = new FileReader(jsonFile);

            Reader reader = new InputStreamReader(new FileInputStream(jsonFile), "utf-8");
            int ch = 0;
            StringBuffer sb = new StringBuffer();
            while ((ch = reader.read()) != -1) {
                sb.append((char) ch);
            }
            fileReader.close();
            reader.close();
            jsonStr = sb.toString();
            return jsonStr;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void writeJsonFile(String filePath, String content) {
        try {
            File file = new File(filePath);
            if (file.exists()) {
                System.out.println("file exist!");
                return;
            }
            FileWriter fw = new FileWriter(filePath);
            PrintWriter out = new PrintWriter(fw);
            out.write(content);
            out.println();
            fw.close();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


    public static void main(String[] args) throws Exception {
        String path = "test/test01/pk.json";

        String s = ReadWriteJson.readJsonFile(path);
        JSONObject object = JSON.parseObject(s);
        System.out.println(object);

        String file = "test/test01/2.json";
        writeJsonFile(file, object.toJSONString());
    }
}

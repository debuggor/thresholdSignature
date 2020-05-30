package com.debuggor.common;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;


/**
 * @Author:yong.huang
 * @Date:2020-05-30 22:26
 */
public class ECPointUtils {

    /**
     * 将单个点表示成json形式
     *
     * @param ecPoint
     * @return
     */
    public static JSONObject ecPointToJson(ECPoint ecPoint) {
        ECFieldElement xCoord = ecPoint.getXCoord();
        ECFieldElement yCoord = ecPoint.getYCoord();
        JSONObject object = new JSONObject();
        JSONArray array = new JSONArray();
        array.add(0, xCoord.toBigInteger());
        array.add(1, yCoord.toBigInteger());
        object.put("Coords", array);
        return object;
    }

    /**
     * 将点数组表示成json
     *
     * @param ecPoints
     * @return
     */
    public static JSONArray ecPointsToJson(ECPoint[] ecPoints) {
        JSONArray result = new JSONArray();
        for (int i = 0; i < ecPoints.length; i++) {
            JSONObject object = ecPointToJson(ecPoints[i]);
            result.add(i, object);
        }
        return result;
    }

}

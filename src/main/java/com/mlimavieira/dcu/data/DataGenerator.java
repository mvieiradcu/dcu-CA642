package com.mlimavieira.dcu.data;

import com.jayway.jsonpath.JsonPath;
import com.mlimavieira.dcu.FEAL;
import com.mlimavieira.dcu.model.DataPair;
import com.mlimavieira.dcu.util.Utils;

import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

public class DataGenerator {

    private static byte[] generate() {
        SecureRandom random = new SecureRandom();
        byte[] output = new byte[8];
        random.nextBytes(output);
        return output;
    }

    public static List<DataPair> generateData(Long diff, int[] dummyKey, int numPlainTexts) {

        List<DataPair> list = new ArrayList<>();

        for (int i = 0; i < numPlainTexts; i++) {

            DataPair pair = new DataPair();
            String strP1 = "";
            String strP0 = "";
            while (strP0.length() < 16 || strP1.length() < 16) {

                Long l = Utils.byteArrayToLong(generate());
                strP0 = Long.toHexString(l);
                pair.setPlainText0(l);

                pair.setCipherText0(FEAL.encrypt(pair.getPlainText0(), dummyKey));

                Long p1 = pair.getPlainText0() ^ diff;

                strP1 = Long.toHexString(p1);
                pair.setPlainText1(p1);
                pair.setCipherText1(FEAL.encrypt(pair.getPlainText1(), dummyKey));
            }
            list.add(pair);
        }

        return list;
    }

    public static List<DataPair> loadFromFile(Long diff, URI dataPairLoc) {
        try {
            if (diff.equals(0x8080000080800000L)) {
                return getDataPair("round_4", dataPairLoc);
            }
            if (diff.equals(0x0000000080800000L)) {
                return getDataPair("round_3", dataPairLoc);
            }
            if (diff.equals(0x0000000002000000L)) {
                return getDataPair("round_2", dataPairLoc);
            }
            throw new RuntimeException("Illegal Differential value 0x" + Long.toHexString(diff));
        } catch (Exception e) {
            throw new RuntimeException("Error loading Data Pairs.", e);
        }
    }

    private static List<DataPair> getDataPair(String round, URI uri) throws Exception {

        String json = Files.readString(Paths.get(uri));

        String initialJsonPath = "$." + round;
        List<String> pTxt0 = JsonPath.read(json, initialJsonPath + ".plainText0");
        List<String> pTxt1 = JsonPath.read(json, initialJsonPath + ".plainText1");
        List<String> cTxt0 = JsonPath.read(json, initialJsonPath + ".cipherText0");
        List<String> cTxt1 = JsonPath.read(json, initialJsonPath + ".cipherText1");


        if (!allEqual(pTxt0.size(), pTxt1.size(), cTxt0.size(), cTxt1.size())) {
            throw new RuntimeException("Invalid DataPairs.json All plaintexts and Ciphertexts must have the same size.");
        }

        List<DataPair> listDP = new ArrayList<>();
        for (int i = 0; i < pTxt0.size(); i++) {
            DataPair dp = new DataPair();

            dp.setPlainText0(parseLong(pTxt0.get(i)));
            dp.setPlainText1(parseLong(pTxt1.get(i)));
            dp.setCipherText0(parseLong(cTxt0.get(i)));
            dp.setCipherText1(parseLong(cTxt1.get(i)));

            dp.setPlainText0Hex(pTxt0.get(i));
            dp.setPlainText1Hex(pTxt1.get(i));
            dp.setCipherText0Hex(cTxt0.get(i));
            dp.setCipherText1Hex(cTxt1.get(i));

            listDP.add(dp);
        }

        return listDP;
    }

    static Long parseLong(String hex) {
        return  new BigInteger(hex, 16).longValue();
    }

    private static boolean allEqual(Integer... args) {
        Set<Integer> set = new HashSet<>();
        set.addAll(Arrays.asList(args));

        return set.size() == 1;
    }
}

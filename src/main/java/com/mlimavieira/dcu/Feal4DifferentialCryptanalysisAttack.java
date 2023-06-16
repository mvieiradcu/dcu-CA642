package com.mlimavieira.dcu;

import com.mlimavieira.dcu.data.DataGenerator;
import com.mlimavieira.dcu.model.DataPair;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.mlimavieira.dcu.util.Utils.*;

/**
 * Differential Cryptanalysis of FEAL-4 using Chosen plaintext attack.
 * Based on Jon King's FEAL-4 code differential cryptanalysis (http://theamazingking.com/feal4full.c)
 * <p>
 * Website reference.
 * http://theamazingking.com/crypto-feal.php
 */
@SuppressWarnings("squid:S2629")
public class Feal4DifferentialCryptanalysisAttack {

    private static final Logger LOGGER = LoggerFactory.getLogger("");

    private static final boolean GENERATE_TEST_DATA = false;

    private static final int[] DUMMY_SUB_KEY = {0x4D3, 0x7D4, 0x7BB, 0x6A9, 0x7BD, 0xC28};

    private static final Long OUTPUT_DIFFERENTIAL = 0x02000000L;

    private static final int NUM_PLAINTEXTS = 12;

    private static final StopWatch STOP_WATCH = StopWatch.createStarted();
    private List<DataPair> dataPairs;

    private List<CrackedKeys> validKeys = new ArrayList<>();

    private CrackedKeys foundCrackedKeys;

    private final URI dataPairLocation;

    public Feal4DifferentialCryptanalysisAttack(URI dataPairLocation) {
        this.dataPairLocation = dataPairLocation;
    }

    private void prepareAttack() {
        for (DataPair pair : dataPairs) {
            long cipherLeft0 = getLeftHalf(pair.getCipherText0());
            long cipherRight0 = getRightHalf(pair.getCipherText0()) ^ cipherLeft0;
            long cipherLeft1 = getLeftHalf(pair.getCipherText1());
            long cipherRight1 = getRightHalf(pair.getCipherText1()) ^ cipherLeft1;

            pair.setCipherText0(getCombinedHalves(cipherLeft0, cipherRight0));
            pair.setCipherText1(getCombinedHalves(cipherLeft1, cipherRight1));
        }
    }

    private void decryptWithCrackedKey(long crackedKey) {
        for (DataPair dataPair : dataPairs) {
            long cipherLeft0 = getRightHalf(dataPair.getCipherText0());
            long cipherLeft1 = getRightHalf(dataPair.getCipherText1());

            long cipherRight0 = FEAL.f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(dataPair.getCipherText0());
            long cipherRight1 = FEAL.f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(dataPair.getCipherText1());

            dataPair.setCipherText0(getCombinedHalves(cipherLeft0, cipherRight0));
            dataPair.setCipherText1(getCombinedHalves(cipherLeft1, cipherRight1));
        }
    }


    private List<Long> crackRound(Round round) {

        List<Long> keys = new ArrayList<>();

        for (long tmpKey = 0x00000000L; tmpKey <= 0xFFFFFFFFL; tmpKey++) {
            int score = 0;


            for (DataPair pair : dataPairs) {

                long cipherRight0 = getRightHalf(pair.getCipherText0());
                long cipherLeft0 = getLeftHalf(pair.getCipherText0());
                long cipherRight1 = getRightHalf(pair.getCipherText1());
                long cipherLeft1 = getLeftHalf(pair.getCipherText1());

                long cipherLeft = cipherLeft0 ^ cipherLeft1;
                long fOutDiffActual = cipherLeft ^ OUTPUT_DIFFERENTIAL;

                long fInput0 = cipherRight0 ^ tmpKey;
                long fInput1 = cipherRight1 ^ tmpKey;
                long fOut0 = FEAL.f(fInput0);
                long fOut1 = FEAL.f(fInput1);
                long fOutDiffComputed = fOut0 ^ fOut1;

                if (fOutDiffActual == fOutDiffComputed) {
                    score++;
                } else {
                    break;
                }
            }

            if (score == NUM_PLAINTEXTS) {
                keys.add(tmpKey);
            }
        }

        StringBuilder strKeys = new StringBuilder();
        keys.forEach((k) -> strKeys.append(" 0x").append(Long.toHexString(k)));
        LOGGER.info("Found {} valid Keys on round {}. Keys: {} ", keys.size(), round.name(), strKeys);


        return keys;
    }

    private boolean crackLastRounds(Long k3, Long k2, Long k1) {

        LOGGER.info("Cracking last round with Keys: K1: 0x{} K2: 0x{} K3: 0x{}", k1, k2, k3);
        Long searchSpace = 0L;

        for (long tmpK0 = 0; tmpK0 < 0xFFFFFFFFL; tmpK0++) {
            long tmpK4 = 0;
            long tmpK5 = 0;

            searchSpace++;

            for (DataPair pair : dataPairs) {

                long plainLeft0 = getLeftHalf(pair.getPlainText0());
                long plainRight0 = getRightHalf(pair.getPlainText0());
                long cipherLeft0 = getLeftHalf(pair.getCipherText0());
                long cipherRight0 = getRightHalf(pair.getCipherText0());

                long temp = FEAL.f(cipherRight0 ^ tmpK0) ^ cipherLeft0;
                if (tmpK4 == 0) {
                    tmpK4 = temp ^ plainLeft0;
                    tmpK5 = temp ^ cipherRight0 ^ plainRight0;
                } else if (((temp ^ plainLeft0) != tmpK4) || ((temp ^ cipherRight0 ^ plainRight0) != tmpK5)) {
                    tmpK4 = 0;
                    tmpK5 = 0;
                    break;
                }
            }
            if (tmpK4 != 0) {
                CrackedKeys crackedKeys = new CrackedKeys(tmpK0, k1, k2, k3, tmpK4, tmpK5);
                validKeys.add(new CrackedKeys(tmpK0, k1, k2, k3, tmpK4, tmpK5));
                boolean success = verifySukey(dataPairs, crackedKeys);

                if (success) {

                    foundCrackedKeys = crackedKeys;
                    LOGGER.info("\n****** SUCCESS VERIFYING THE KEYS *****\n\n");
                    LOGGER.info("Search Space. {}", searchSpace);
                    LOGGER.info("VERIFIED KEYS K0: 0x{} K1: 0x{} K2: 0x{} K3: 0x{} K4: 0x{} K5: 0x{}", Long.toHexString(tmpK0), Long.toHexString(k1), Long.toHexString(k2), Long.toHexString(k3), Long.toHexString(tmpK4), Long.toHexString(tmpK5));
                    LOGGER.info("\n\n****** SUCCESS VERIFYING THE KEYS *****\n\n");
                    return true;
                }
            }
        }
        return false;
    }

    private List<DataPair> loadDataPairs(Long diff) {

        if (!GENERATE_TEST_DATA) {
            LOGGER.info("Loading Data Pairs from dataPairs.json... Differential applied:  0x{}", Long.toHexString(diff));
            return DataGenerator.loadFromFile(diff, dataPairLocation);
        }

        LOGGER.info("Generating Data Pairs ... 0x{}", Long.toHexString(diff));
        return DataGenerator.generateData(diff, DUMMY_SUB_KEY, NUM_PLAINTEXTS);
    }

    public void run() {

        LOGGER.info("Trying to crack FEAL-4 with Differential Cryptanalysis....");

        // Round 4
        LOGGER.info(" *********  Cracking Round 4 to find K3 *********");
        this.dataPairs = loadDataPairs(Round.ROUND_4.differential);

        prepareAttack();

        List<Long> k3Candidates = crackRound(Round.ROUND_4);
        STOP_WATCH.split();
        LOGGER.info("");

        for (Long k3 : k3Candidates) {

            // Round 3
            LOGGER.info(" *********  Cracking Round 3 to find K2 *********");
            this.dataPairs = loadDataPairs(Round.ROUND_3.differential);

            prepareAttack();
            decryptWithCrackedKey(k3);
            List<Long> k2Candidates = crackRound(Round.ROUND_3);
            LOGGER.info("");
            for (Long k2 : k2Candidates) {

                // Round 2
                LOGGER.info(" *********  Cracking Round 2 to find K1 *********");
                this.dataPairs = loadDataPairs(Round.ROUND_2.differential);
                prepareAttack();
                decryptWithCrackedKey(k3);
                decryptWithCrackedKey(k2);
                // Cracking Round 2....
                List<Long> k1Candidates = crackRound(Round.ROUND_2);

                LOGGER.info("Cracking remaining keys (K0, K4, and K5) ...");

                for (Long k1 : k1Candidates) {
                    decryptWithCrackedKey(k1);
                    boolean foundKey = crackLastRounds(k3, k2, k1);
                    if (foundKey) {

                        LOGGER.info("FOUND VALID KEYS");
                        LOGGER.info(" CRACKED KEY ");
                        LOGGER.info(foundCrackedKeys.toString());

                        printFooter();
                        return;
                    }
                }
            }
        }
    }

    void printFooter() {
        LOGGER.info("VALID KEYS");
        validKeys.forEach((i) -> LOGGER.info("{}", i));
        LOGGER.info("VALID KEYS");
        STOP_WATCH.split();
        LOGGER.info("Elapsed time to crack remaining keys. {}", STOP_WATCH.formatSplitTime());
    }

    private boolean verifySukey(List<DataPair> dataPairs, CrackedKeys crackedKeys) {
        LOGGER.info("VERIFIED KEYS -- {}", crackedKeys.toString());
        for (DataPair pair : dataPairs) {

            byte[] plainText0 = ByteUtils.fromHexString(pair.getPlainText0Hex());
            byte[] cipherText0 = ByteUtils.fromHexString(pair.getCipherText0Hex());

            FEAL.decrypt(cipherText0, crackedKeys.getAsIntArray());

            if (Arrays.equals(plainText0, cipherText0)) {
                LOGGER.info("SUCCESS Decrypting CipherText0: 0x{} Decrypted Value: 0x{}", Long.toHexString(pair.getCipherText0()), Long.toHexString(bytesToLong(plainText0)));
                return true;
            }
        }

        return false;
    }

    public static void main(String[] args) throws URISyntaxException {
        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%m%n")));
        org.apache.log4j.Logger.getRootLogger().setLevel(Level.INFO);

        URI dataPairLocation;
        if( args.length > 0 && StringUtils.isNotEmpty(args[0] )) {
            File file = new File(args[0]);
            dataPairLocation = file.toURI();
        } else {
            URL resource = Feal4DifferentialCryptanalysisAttack.class.getResource("/feal/dataPairs.json");

            File nf = new File(resource.toURI());

            if( !nf.exists()) {
                LOGGER.error("Data Pair File not found: {}", nf.getAbsolutePath());
                System.exit(-1);
            }

            dataPairLocation = resource.toURI();
        }

        LOGGER.info("***************************************************************************************");
        LOGGER.info("Starting FEAL-4 Differential Cryptanalysis Attack. Start time: {}", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
        LOGGER.info("***************************************************************************************");
        LOGGER.info("\n");


        new Feal4DifferentialCryptanalysisAttack(dataPairLocation).run();

        LOGGER.info("Finishing Differential Attack. End time: {}", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));

        STOP_WATCH.stop();

        LOGGER.info("Total Elapsed time. {}", STOP_WATCH.formatTime());
    }

    private enum Round {
        ROUND_4(0x8080000080800000L),
        ROUND_3(0x0000000080800000L),
        ROUND_2(0x0000000002000000L);

        Long differential;

        Round(Long diff) {
            this.differential = diff;
        }
    }

    private static class CrackedKeys {
        private long crackedKey0 = 0;
        private long crackedKey1 = 0;
        private long crackedKey2 = 0;
        private long crackedKey3 = 0;
        private long crackedKey4 = 0;
        private long crackedKey5 = 0;


        CrackedKeys(long k0, long k1, long k2, long k3, long k4, long k5) {
            this.crackedKey0 = k0;
            this.crackedKey1 = k1;
            this.crackedKey2 = k2;
            this.crackedKey3 = k3;
            this.crackedKey4 = k4;
            this.crackedKey5 = k5;
        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder("Cracked Keys. ");
            stringBuilder.append(" K0= 0x").append(Long.toHexString(crackedKey0));
            stringBuilder.append(" K1= 0x").append(Long.toHexString(crackedKey1));
            stringBuilder.append(" K2= 0x").append(Long.toHexString(crackedKey2));
            stringBuilder.append(" K3= 0x").append(Long.toHexString(crackedKey3));
            stringBuilder.append(" K4= 0x").append(Long.toHexString(crackedKey4));
            stringBuilder.append(" K5= 0x").append(Long.toHexString(crackedKey5));
            return stringBuilder.toString();
        }

        void printKeysAsHex() {
            LOGGER.info(" K0: 0x{} K1: 0x{} K2: 0x{} K3: 0x{} K4: 0x{} K5: 0x{} ",
                    Long.toHexString(crackedKey0),
                    Long.toHexString(crackedKey1),
                    Long.toHexString(crackedKey2),
                    Long.toHexString(crackedKey3),
                    Long.toHexString(crackedKey4),
                    Long.toHexString(crackedKey5));
        }

        @SuppressWarnings("squid:S2153")
        int[] getAsIntArray() {
            return new int[]{
                    Long.valueOf(crackedKey0).intValue(),
                    Long.valueOf(crackedKey1).intValue(),
                    Long.valueOf(crackedKey2).intValue(),
                    Long.valueOf(crackedKey3).intValue(),
                    Long.valueOf(crackedKey4).intValue(),
                    Long.valueOf(crackedKey5).intValue()
            };
        }
    }

    public static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip
        return buffer.getLong();
    }
}

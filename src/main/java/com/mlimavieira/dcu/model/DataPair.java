package com.mlimavieira.dcu.model;

import java.util.StringJoiner;

public class DataPair {

    private Long plainText0;
    private Long cipherText0;

    private Long plainText1;
    private Long cipherText1;

    private String plainText0Hex;
    private String cipherText0Hex;

    private String plainText1Hex;
    private String cipherText1Hex;

    public Long getPlainText0() {
        return plainText0;
    }

    public void setPlainText0(Long plainText0) {
        this.plainText0 = plainText0;
    }

    public Long getCipherText0() {
        return cipherText0;
    }

    public void setCipherText0(Long cipherText0) {
        this.cipherText0 = cipherText0;
    }

    public Long getPlainText1() {
        return plainText1;
    }

    public void setPlainText1(Long plainText1) {
        this.plainText1 = plainText1;
    }

    public Long getCipherText1() {
        return cipherText1;
    }

    public void setCipherText1(Long cipherText1) {
        this.cipherText1 = cipherText1;
    }

    public String getPlainText0Hex() {
        return plainText0Hex;
    }

    public void setPlainText0Hex(String plainText0Hex) {
        this.plainText0Hex = plainText0Hex;
    }

    public String getCipherText0Hex() {
        return cipherText0Hex;
    }

    public void setCipherText0Hex(String cipherText0Hex) {
        this.cipherText0Hex = cipherText0Hex;
    }

    public String getPlainText1Hex() {
        return plainText1Hex;
    }

    public void setPlainText1Hex(String plainText1Hex) {
        this.plainText1Hex = plainText1Hex;
    }

    public String getCipherText1Hex() {
        return cipherText1Hex;
    }

    public void setCipherText1Hex(String cipherText1Hex) {
        this.cipherText1Hex = cipherText1Hex;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", DataPair.class.getSimpleName() + "[", "]")
                .add("plainText0=" + plainText0)
                .add("cipherText0=" + cipherText0)
                .add("plainText1=" + plainText1)
                .add("cipherText1=" + cipherText1)
                .toString();
    }
}

# dcu-ca642

Requirements to run the application
* Java 12 
* Maven 3 

Maven command: `mvn clean install`

Java command: `java -cp DCU-CA642I-jar-with-dependencies.jar ${Data_Pair_Location}"
`
the variable `${Data_Pair_Location}` must be replaced by the absolute location of the `DataPairs.json` file


Data Pairs - JSON file with PlainText0, PlainText1, CipherText0 and CipherText1 for each round.  

Format
````
{
"round_4": {
"plainText0": [],
"plainText1": [],
"cipherText0": [],
"cipherText1": []
},
"round_3": {
"plainText0": [],
"plainText1": [],
"cipherText0": [],
"cipherText1": []
},
"round_2": {
"plainText0": [],
"plainText1": [],
"cipherText0": [],
"cipherText1": []
}
}
````
Sample file on `src/main/resources/feal/dataPairs.json`
```
{
  "round_4": {
    "plainText0": [
      "a46f442880cc5610",
      "5f629c2b0de19943",
      "3c473558e1e34fbc",
      "db76e679ea367106",
      "3d9aa69a4b8e1b6c",
      "114529a2e3ccb462",
      "99638d5aea0311d9",
      "66f0c87543fd02fd",
      "5912f02e63c0ce38",
      "31ffde8d2d12523b",
      "fc91b27b39b2d0b4",
      "11cf4593623081d0"
    ],
    "plainText1": [
      "24ef4428004c5610",
      "dfe29c2b8d619943",
      "bcc7355861634fbc",
      "5bf6e6796ab67106",
      "bd1aa69acb0e1b6c",
      "91c529a2634cb462",
      "19e38d5a6a8311d9",
      "e670c875c37d02fd",
      "d992f02ee340ce38",
      "b17fde8dad92523b",
      "7c11b27bb932d0b4",
      "914f4593e2b081d0"
    ],
    "cipherText0": [
      "9f9a621ac28d472c",
      "7525c8134cf469ce",
      "dd10f88f8e82f8bc",
      "228fa12b11c29bac",
      "567f8444d184ff00",
      "e6f97bd14e278fe5",
      "d25c7565e3d5491f",
      "9dac1a10519801b4",
      "288337f0353629b1",
      "161ccd9821792deb",
      "551d953215b619c5",
      "4caec050e3774683"
    ],
    "cipherText1": [
      "d39dc09e6602c529",
      "0a16e7926b3fa7ca",
      "978a78207c80998c",
      "8d4f2747d59a3d41",
      "3ebd0e2c51de55e8",
      "1be4100a2bc284bd",
      "b92a5b8f202b8671",
      "4bb67eecec0a05cb",
      "3d99511f7b946fdd",
      "7f9e55b81063d54b",
      "9bd86dad73ebc1d9",
      "27ac4a4860fdec1b"
    ]
  },
  "round_3": {
    "plainText0": [
      "edf5c70902d2b842",
      "7c8c03426daaaad4",
      "b5ac028ce9b0b356",
      "7d6681098acf5ced",
      "2ef38b8eab60dfdc",
      "e546a38b697be470",
      "e9260d02330876d9",
      "128243df7e574bc6",
      "ace291358d783e09",
      "366a4df809ffeed6",
      "4ded0de86b75c987",
      "aaa621d487885a87"
    ],
    "plainText1": [
      "edf5c7098252b842",
      "7c8c0342ed2aaad4",
      "b5ac028c6930b356",
      "7d6681090a4f5ced",
      "2ef38b8e2be0dfdc",
      "e546a38be9fbe470",
      "e9260d02b38876d9",
      "128243dffed74bc6",
      "ace291350df83e09",
      "366a4df8897feed6",
      "4ded0de8ebf5c987",
      "aaa621d407085a87"
    ],
    "cipherText0": [
      "11221c3d9a8e21a5",
      "009d03eaccec3120",
      "777353dc27925dbd",
      "0edb8ae1373b1bed",
      "97fac322d2e3e77b",
      "f34988c2ea5fb664",
      "9a20010a424dd845",
      "e1df034194b341a4",
      "e728dc1b5beec4e3",
      "b65d4d00b355871f",
      "6d4c590c01405e83",
      "dd47458f8872afeb"
    ],
    "cipherText1": [
      "b1647744fecfe94f",
      "559ebd81973723df",
      "3bcacdd6112d4ff3",
      "5ccbad3143da22aa",
      "bdd2319ba8e7fb88",
      "17ef052de3388687",
      "e654ee3249f6f542",
      "3f7a79f6c21895f6",
      "9b48e05884ce79a4",
      "d5d57dcc1a1b1870",
      "36f7a94ac1792624",
      "01843bd51699dbe7"
    ]
  },
  "round_2": {
    "plainText0": [
      "38a8d23ec4f90d99",
      "a8ff3c56742b28d5",
      "6fa3d1ce04066447",
      "4e321fb56bed5a56",
      "9233d89924807af1",
      "83a548fa44d33fd9",
      "5f481249b031d090",
      "1d85402fb89cab51",
      "80e34a187b138f79",
      "74d6b600aa57bccc",
      "43aa1d272c85d29c",
      "c90a18716471cfa9"
    ],
    "plainText1": [
      "38a8d23ec6f90d99",
      "a8ff3c56762b28d5",
      "6fa3d1ce06066447",
      "4e321fb569ed5a56",
      "9233d89926807af1",
      "83a548fa46d33fd9",
      "5f481249b231d090",
      "1d85402fba9cab51",
      "80e34a1879138f79",
      "74d6b600a857bccc",
      "43aa1d272e85d29c",
      "c90a18716671cfa9"
    ],
    "cipherText0": [
      "828bdb6b302ae6a0",
      "770d92aeb0d1e467",
      "57e2291b91596a3b",
      "93899d128e2b6ba7",
      "6b7d9c68ea690851",
      "78a8a2f9e76ebc1d",
      "765d4649b602bd1d",
      "ed314af0db85c8ef",
      "4fc03807cfab45ca",
      "4a72e3255cb40408",
      "46b5a0b748127ac7",
      "0d04d43f7a212cf7"
    ],
    "cipherText1": [
      "c8f4f1a02fba6b2f",
      "7c3647dd14cd50b0",
      "e665190ca9ed69a4",
      "0519580d1bab51e5",
      "55df0d9c47349bfc",
      "fd22cf17bc7ccedd",
      "a1685c421d3d0e69",
      "47042c0142c8e2cd",
      "5e074b66fbcd52f8",
      "733d009d76587763",
      "fa06f3572efa23ce",
      "5b8ee7bc190a58ba"
    ]
  }
}
```
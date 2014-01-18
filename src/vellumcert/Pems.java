/*
 Source https://code.google.com/p/vellum by @evanxsummers

       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements. See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership. The ASF licenses this file to
       you under the Apache License, Version 2.0 (the "License").
       You may not use this file except in compliance with the
       License. You may obtain a copy of the License at:

         http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.  
 */
package vellumcert;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author evan.summers
 */
public class Pems {

    private static final String BEGIN_PRIVATE_KEY = "BEGIN PRIVATE KEY";
    private static final String END_PRIVATE_KEY = "END PRIVATE KEY";
    private static final String BEGIN_CERT = "BEGIN CERTIFICATE";
    private static final String END_CERT = "END CERTIFICATE";
    private static final String DASHES = "-----";
    private static final int LENGTH = 64;

    public static String buildKeyPem(Key privateKey) {
        StringBuilder builder = new StringBuilder();
        builder.append(DASHES);
        builder.append(BEGIN_PRIVATE_KEY);
        builder.append(DASHES);
        builder.append('\n');
        builder.append(Base64.encodeBase64String(privateKey.getEncoded()));
        builder.append(DASHES);
        builder.append(END_PRIVATE_KEY);
        builder.append(DASHES);
        builder.append('\n');
        return builder.toString();
    }

    public static String buildCertPem(Certificate cert) throws CertificateEncodingException {
        StringBuilder builder = new StringBuilder();
        builder.append(DASHES);
        builder.append(BEGIN_CERT);
        builder.append(DASHES);
        builder.append('\n');
        String text = Base64.encodeBase64String(cert.getEncoded());
        for (int index = 0;; index += LENGTH) {
            if (index + LENGTH < text.length()) {
                builder.append(text.substring(index, index + LENGTH));
                builder.append('\n');
            } else {
                builder.append(text.substring(index));
                builder.append('\n');
                break;
            }
        }
        builder.append(DASHES);
        builder.append(END_CERT);
        builder.append(DASHES);
        builder.append('\n');
        return builder.toString();
    }

    public static byte[] decodePemDer(String pem) {
        int index = pem.lastIndexOf(DASHES);
        if (index > 0) {
            pem = pem.substring(0, index);
            index = pem.lastIndexOf(DASHES);
            pem = pem.substring(0, index);
            index = pem.lastIndexOf(DASHES);
            pem = pem.substring(index + DASHES.length());
        }
        return Base64.decodeBase64(pem);
    }

}

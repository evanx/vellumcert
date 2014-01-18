/*
 * Source https://github.com/evanx by @evanxsummers

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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Decoder;
import sun.security.pkcs.PKCS10;
import sun.security.pkcs.PKCS10Attribute;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 *
 * @author evan.summers
 */
public class CertReqs {
    private static Logger logger = LoggerFactory.getLogger(CertReqs.class);
    private static final String DASHES = "-----";
    private static final String BEGIN_NEW_CERT_REQ = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    private static final String END_NEW_CERT_REQ = "-----END NEW CERTIFICATE REQUEST-----";
        
    public static PKCS10 create(PrivateKey privateKey, X509Certificate cert) 
            throws Exception {
        String sigAlgName = "SHA256WithRSA";
        PKCS10 request = new PKCS10(cert.getPublicKey());
        if (false) {
            CertificateExtensions ext = new CertificateExtensions();
            request.getAttributes().setAttribute(X509CertInfo.EXTENSIONS,
                    new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, ext));
        }
        Signature signature = Signature.getInstance(sigAlgName);
        signature.initSign(privateKey);
        X500Name subject = new X500Name(cert.getSubjectDN().toString());
        request.encodeAndSign(subject, signature);
        return request;
    }

    public static CertReq create(String certReqPem) throws Exception {
        PKCS10 req = new PKCS10(decodePemDer(certReqPem));
        return new CertReq(req.getSubjectName().getName(), req.getSubjectPublicKeyInfo());
    }

    public static byte[] decodePemDer(String pem) throws Exception {
        int index = pem.lastIndexOf(DASHES);
        if (index > 0) {
            pem = pem.substring(0, index);
            index = pem.lastIndexOf(DASHES);
            pem = pem.substring(0, index);
            index = pem.lastIndexOf(DASHES);
            pem = pem.substring(index + DASHES.length());
        }
        return new BASE64Decoder().decodeBuffer(pem);
    }
    
    public static X509Certificate sign(CertReq certReq, PrivateKey signingKey, 
            X509Certificate signingCert, Date notBefore, int validityDays) 
            throws Exception {
        Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(validityDays));
        return sign(certReq, signingKey, signingCert, notBefore, notAfter);
    }
    
    public static X509Certificate sign(CertReq certReq, PrivateKey signingKey, 
            X509Certificate signingCert, Date notBefore, Date notAfter) 
            throws Exception {
        String sigAlgName = "SHA256WithRSA";
        CertificateValidity validity = new CertificateValidity(notBefore, notAfter);
        byte[] encoded = signingCert.getEncoded();
        X509CertImpl signerCertImpl = new X509CertImpl(encoded);
        X509CertInfo signerCertInfo = (X509CertInfo) signerCertImpl.get(
                X509CertImpl.NAME + "." + X509CertImpl.INFO);
        X500Name issuer = (X500Name) signerCertInfo.get(
                X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);
        Signature signature = Signature.getInstance(sigAlgName);
        signature.initSign(signingKey);
        X509CertImpl cert = new X509CertImpl(buildCertInfo(certReq, issuer, 
                sigAlgName, validity));
        cert.sign(signingKey, sigAlgName);
        return cert;
    }

    public static X509Certificate sign(CertReq certReq, PrivateKey signingKey, 
            X509Certificate signingCert, Date notBefore, Date notAfter, 
            long serialNumber) throws Exception {
        return sign(certReq, signingKey, signingCert, notBefore, notAfter, serialNumber,
                false, 0, KeyUsageType.DIGITAL_SIGNATURE);
    }
    
    public static X509Certificate sign(CertReq certReq, PrivateKey signingKey, X509Certificate signingCert,
            Date notBefore, Date notAfter, long serialNumber,
            boolean isCa, int pathLength, KeyUsageType keyUsage) 
            throws Exception {
        String sigAlgName = "SHA256WithRSA";
        CertificateValidity validity = new CertificateValidity(notBefore, notAfter);
        byte[] encoded = signingCert.getEncoded();
        X509CertImpl signerCertImpl = new X509CertImpl(encoded);
        X509CertInfo signerCertInfo = (X509CertInfo) signerCertImpl.get(
                X509CertImpl.NAME + "." + X509CertImpl.INFO);
        X500Name issuer = (X500Name) signerCertInfo.get(
                X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);
        Signature signature = Signature.getInstance(sigAlgName);
        signature.initSign(signingKey);
        X509CertInfo certInfo = buildCertInfo(certReq, issuer,  
                sigAlgName, validity, serialNumber, isCa, pathLength, keyUsage);
        X509CertImpl cert = new X509CertImpl(certInfo);
        cert.sign(signingKey, sigAlgName);
        return cert;
    }
    
    private static X509CertInfo buildCertInfo(CertReq certReq, X500Name issuer, 
            String sigAlgName, CertificateValidity validity) 
            throws Exception {
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, validity);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                new java.util.Random().nextInt() & 0x7fffffff));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, 
                new CertificateAlgorithmId(AlgorithmId.get(sigAlgName)));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
        info.set(X509CertInfo.KEY, new CertificateX509Key(certReq.getPublicKey()));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(new X500Name(certReq.getSubject())));
        return info;
    }
    
    private static X509CertInfo buildCertInfo(CertReq certReq, X500Name issuer, 
            String sigAlgName, CertificateValidity validity, long serialNumber,
            boolean isCa, int pathLength, KeyUsageType keyUsage) 
            throws Exception {
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, validity);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                BigInteger.valueOf(serialNumber)));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(AlgorithmId.get(sigAlgName)));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
        info.set(X509CertInfo.KEY, new CertificateX509Key(certReq.getPublicKey()));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(new X500Name(certReq.getSubject())));
        CertificateExtensions extensions = new CertificateExtensions();
        if (isCa) {
            BasicConstraintsExtension bce = new BasicConstraintsExtension(true, true, 1);
            extensions.set(BasicConstraintsExtension.NAME, bce);
        } else {
            BasicConstraintsExtension bce = new BasicConstraintsExtension(true, false, 0);
            extensions.set(BasicConstraintsExtension.NAME, bce);
            if (keyUsage != null) {
                KeyUsageExtension kue = new KeyUsageExtension(getKeyUsages(keyUsage));
                extensions.set(KeyUsageExtension.NAME, kue);
            }
        }
        info.set(X509CertInfo.EXTENSIONS, extensions);
        return info;
    }
    
    private static boolean[] getKeyUsages(KeyUsageType keyUsage) {
        boolean[] array = new boolean[9];
        array[keyUsage.ordinal()] = true;
        return array;  
    }
}
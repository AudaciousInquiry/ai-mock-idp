/*
 * Copyright (c) 2020 Audacious Inquiry, LLC
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.ainq.mockidp.service.impl;

import com.ainq.mockidp.model.SamlSpConnectionInfo;
import com.ainq.mockidp.model.SamlSpMetadata;
import com.ainq.mockidp.service.SamlSpMetadataService;
import com.ainq.mockidp.util.Base64;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.commons.io.IOUtils;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import org.opensaml.security.x509.BasicX509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

@Service("samlSpMetadataService")
@Slf4j
public class SamlSpMetadataServiceImpl implements SamlSpMetadataService {

  private static String X_509 = "X.509";

  @Autowired
  private ParserPool parserPool;

  @Autowired private UnmarshallerFactory unmarshallerFactory;

  private static javax.net.ssl.SSLSocketFactory getFactorySimple(String tlsVersion)
      throws Exception {
    SSLContext context = SSLContext.getInstance(tlsVersion);

    context.init(null, null, null);

    return context.getSocketFactory();

  }

  public void parse(SamlSpConnectionInfo info) throws Exception {

    String xml = null;

    HttpURLConnection urlConnection = null;

    if (info.getParseXml()) {
      xml = info.getMetadataXml();
    } else {
      try {

        log.debug("info.metadataUrl = " + info.getMetadataUrl());

        URL url = new URL(info.getMetadataUrl());


        if (url.getProtocol().equals("https")) {
          log.info("Secure Metadata Retrieval attempting TLSv1.2");
          urlConnection = (HttpsURLConnection)url.openConnection();
          javax.net.ssl.SSLSocketFactory sslSocketFactory =getFactorySimple("TLSv1.2");

          ((HttpsURLConnection)urlConnection).setSSLSocketFactory(sslSocketFactory);

        } else {
          log.info("Insecure Metadata Retrieval");
          urlConnection = (HttpURLConnection)url.openConnection();
        }

        urlConnection.setRequestMethod("GET");

        if (urlConnection.getResponseCode() == HttpURLConnection.HTTP_OK) {
          StringBuilder xmlResponse = new StringBuilder();
          BufferedReader input = new BufferedReader(
              new InputStreamReader(urlConnection.getInputStream()), 8192);
          String strLine = null;
          while ((strLine = input.readLine()) != null) {
            xmlResponse.append(strLine);
          }
          xml = xmlResponse.toString();
          input.close();
        }
      } catch (Exception e) {
        log.error("Unable to retrieve xml from the SP Metadata URL", e);
        throw new RuntimeException(e);
      } finally {// close connection
        if (urlConnection != null) {
          urlConnection.disconnect();
        }

      }
    }

    final EntityDescriptor descriptor = unmarshall(xml);
    final String protocol = info.getMetadataProtocol();
    final SPSSODescriptor spDescriptor = descriptor.getSPSSODescriptor(protocol);

    log.info("Parsing the Id Provider, with the entityId: " + descriptor.getEntityID());

    info.setSamlSpMetadata(new SamlSpMetadata(
        descriptor.getEntityID(),
        spDescriptor.getErrorURL(),
        getAssertionConsumerMap(spDescriptor),
        this.getSingleLogoutMap(spDescriptor),
        this.getCredentialList(descriptor.getEntityID(), spDescriptor, UsageType.SIGNING, info),
        this.getCredentialList(descriptor.getEntityID(), spDescriptor, UsageType.ENCRYPTION, info)));
  }

  protected Map<String, String> getAssertionConsumerMap(SPSSODescriptor spDescriptor) {
    final Map<String, String> assertionConsumerBindingLocationMap = new LinkedHashMap<>();

    spDescriptor
        .getAssertionConsumerServices()
        .stream()
        .forEach(
            sso -> {
              log.debug(
                  "Add AssertionConsumer binding "
                      + sso.getBinding()
                      + "("
                      + sso.getLocation()
                      + ")");
              assertionConsumerBindingLocationMap.put(sso.getBinding(), sso.getLocation());
            });

    return assertionConsumerBindingLocationMap;
  }

  protected Map<String, String> getSingleLogoutMap(SPSSODescriptor spDescriptor) {
    final Map<String, String> singleLogoutBindingLocationMap = new LinkedHashMap<>();

    spDescriptor
        .getSingleLogoutServices()
        .stream()
        .forEach(
            sso -> {
              log.debug("Add SLO binding " + sso.getBinding() + "(" + sso.getLocation() + ")");
              singleLogoutBindingLocationMap.put(sso.getBinding(), sso.getLocation());
            });

    return singleLogoutBindingLocationMap;
  }

  protected List<Credential> getCredentialList(
      final String entityId,
      final SPSSODescriptor idpDescriptor,
      UsageType usageType,
      SamlSpConnectionInfo info) {

    List<Credential> signingCreds =
        idpDescriptor
            .getKeyDescriptors()
            .stream()
            .filter(
                key ->
                    null != key.getKeyInfo()
                        && key.getKeyInfo().getX509Datas().get(0).getX509Certificates().size() > 0
                        && usageType == key.getUse()) // not signing are relevant by now.
            .map(
                key ->
                    convertToCredential(
                        entityId,
                        key.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0),
                        info))
            .collect(Collectors.toList());

    if (signingCreds.size() == 0) {
      signingCreds =
          idpDescriptor
              .getKeyDescriptors()
              .stream()
              .filter(
                  key ->
                      null != key.getKeyInfo()
                          && key.getKeyInfo().getX509Datas().get(0).getX509Certificates().size() > 0
                          && UsageType.UNSPECIFIED
                          == key.getUse()) // not signing are relevant by now.
              .map(
                  key ->
                      convertToCredential(
                          entityId,
                          key.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0),
                          info))
              .collect(Collectors.toList());
    }

    return signingCreds;
  }

  protected Credential convertToCredential(
      final String entityId,
      final org.opensaml.xmlsec.signature.X509Certificate x509Certificate,
      SamlSpConnectionInfo info) {

    final byte[] decoded;
    final CertificateFactory cf;
    final java.security.cert.X509Certificate javaX509Certificate;
    ByteArrayInputStream bais = null;
    Credential credential = null;

    try {

      decoded = Base64.decode(x509Certificate.getValue());
      cf = CertificateFactory.getInstance(X_509);
      bais = new ByteArrayInputStream(decoded);
      javaX509Certificate =
          java.security.cert.X509Certificate.class.cast(cf.generateCertificate(bais));

      try {
        javaX509Certificate.checkValidity();
      } catch (CertificateExpiredException | CertificateNotYetValidException e) {
        if (info.getIgnoreInvalidCerts() == null
            || !info.getIgnoreInvalidCerts()) { // if ignore is null or ignore is false,
          throw e;
        }
      }

      final BasicX509Credential signing = new BasicX509Credential(javaX509Certificate);
      signing.setEntityId(entityId);
      credential = signing;
    } catch (CertificateException e) {

      log.error(e.getMessage(), e);
      credential = null;

    } finally {

      IOUtils.closeQuietly(bais);
    }

    return credential;
  }

  protected EntityDescriptor unmarshall(final String xml) throws Exception {

    EntityDescriptor descriptor = null;

    try {
      // Parse metadata file
      final StringReader reader = new StringReader(xml);
      final Element metadata = this.parserPool.parse(reader).getDocumentElement();
      // Get apropriate unmarshaller
      final Unmarshaller unmarshaller = this.unmarshallerFactory.getUnmarshaller(metadata);
      // Unmarshall using the document root element, an EntitiesDescriptor in this case
      descriptor = EntityDescriptor.class.cast(unmarshaller.unmarshall(metadata));
    } catch (Exception e) {

      log.error(e.getMessage(), e);
      throw new Exception(e.getMessage(), e);
    }

    return descriptor;
  }

}

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

package com.ainq.mockidp.util;

import com.ainq.mockidp.constants.MockIdpConstants;
import com.ainq.mockidp.model.SamlSpConnectionInfo;
import com.ainq.mockidp.model.User;
import com.ainq.mockidp.model.PatientContext;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

@Slf4j
public abstract class SamlSpAssertionUtil {

  private static Credential getCredential(SamlSpConnectionInfo info, UsageType usageType) throws java.security.cert.CertificateException, IOException {

    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

    // read public key
    InputStream certStream = new ByteArrayInputStream(info.getPublicSigningCert().getBytes(Charset.forName("UTF-8")));
    BufferedReader certReader = new BufferedReader(new InputStreamReader(certStream));
    PEMParser ppCert = new PEMParser(certReader);
    X509CertificateHolder certHolder = (X509CertificateHolder) ppCert.readObject();
    X509Certificate x509Cert = (X509Certificate) new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) certHolder);
    ppCert.close();
    certReader.close();
    certStream.close();

    // TODO: read private key
    InputStream keyStream = new ByteArrayInputStream(info.getPrivateSigningPemKey().getBytes(Charset.forName("UTF-8")));

    BufferedReader keyReader = new BufferedReader(new InputStreamReader(keyStream));
    PEMParser ppKey = new PEMParser(keyReader);
    PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) ppKey.readObject();
    PrivateKey key = new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
    ppKey.close();
    keyReader.close();
    keyStream.close();

    BasicX509Credential credential = new BasicX509Credential(x509Cert);
    credential.setEntityCertificate(x509Cert);
    credential.setUsageType(usageType);

    credential.setPrivateKey(key);

    // done.
    return credential;
  }


	public static void postSamlResponse(HttpServletResponse httpServletResponse, SamlSpConnectionInfo info, Response samlResponse, String relayState, VelocityEngine velocityEngine, PatientContext patient) {

        MessageContext context = new MessageContext();

        context.setMessage(samlResponse);
        
        SAMLBindingSupport.setRelayState(context, relayState);

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getAssertionConsumerEndpoint(relayState, info));
        

        try {
          SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
          signatureSigningParameters.setSigningCredential(getCredential(info, UsageType.SIGNING));
          signatureSigningParameters
              .setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

          context.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        } catch (CertificateException | IOException e) {
          log.error("Could not load Signing key!", e);
          throw new RuntimeException("Signing Key Loading Issue", e);
        }



        
        
        PatientContextAwareHTTPPostEncoder encoder = new PatientContextAwareHTTPPostEncoder();

        if (patient != null) {
            encoder.setPatientAccountNumber(patient.getPatientAccountNumber());
            encoder.setOid(patient.getOid());
            encoder.setPatientSourceCode(patient.getPatientSourceCode());
            encoder.setExternalMrn(patient.getExternalMrn());
        }

        encoder.setDebugMode(info.getDebugMode());

        encoder.setVelocityEngine(velocityEngine);

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        log.debug("Redirecting to SP");
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }
	
	private static Endpoint getAssertionConsumerEndpoint(String relayState, SamlSpConnectionInfo info) {
        AssertionConsumerService endpoint = OpenSamlUtils.buildSAMLObject(AssertionConsumerService.class);
        endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        
        endpoint.setLocation(getSpSsoAssertionConsumerLocation(info));
        
        return endpoint;
    }
	
	private static String getSpSsoAssertionConsumerLocation(SamlSpConnectionInfo info) {

		String url = info.getSamlSpMetadata().getAssertionConsumerBindingLocationMap().get(SAMLConstants.SAML2_POST_BINDING_URI);
 
		return url;

	}
	
	
	public static Response buildResponse(User user, PatientContext patient, SamlSpConnectionInfo info) {

        Response response = OpenSamlUtils.buildSAMLObject(Response.class);
        response.setDestination(getSpSsoAssertionConsumerLocation(info));
        response.setIssueInstant(new DateTime());
        response.setID(OpenSamlUtils.generateSecureRandomId());
        Issuer issuer2 = OpenSamlUtils.buildSAMLObject(Issuer.class);
        issuer2.setValue(MockIdpConstants.LOCAL_IDP_ENTITY_ID);

        response.setIssuer(issuer2);

        Status status2 = OpenSamlUtils.buildSAMLObject(Status.class);
        StatusCode statusCode2 = OpenSamlUtils.buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion(user, patient, info);

        if (info.getSignAssertion()) {
          signSignable(assertion, info);
        }

        if (info.getEncryptAssertion()) {
          EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, info);

          response.getEncryptedAssertions().add(encryptedAssertion);
        } else {
          response.getAssertions().add(assertion);
        }

        if (info.getSignResponse()) {
          signSignable(response, info);
        }
        return response;
    }

    private static EncryptedAssertion encryptAssertion(Assertion assertion, SamlSpConnectionInfo info) {
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(info.getSamlSpMetadata().getCredentialEncryptionList().get(0));
        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

        try {
            EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
            return encryptedAssertion;
        } catch (EncryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private static void signSignable(SignableSAMLObject signable, SamlSpConnectionInfo info) {
      Signature signature = OpenSamlUtils.buildSAMLObject(Signature.class);
      try {
        signature.setSigningCredential(getCredential(info, UsageType.SIGNING));
      } catch (CertificateException | IOException e) {
        throw new RuntimeException(e);
      }

      signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
      signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

      signable.setSignature(signature);

      try {
          XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable).marshall(signable);
      } catch (MarshallingException e) {
          throw new RuntimeException(e);
      }

      try {
          Signer.signObject(signature);
      } catch (SignatureException e) {
          throw new RuntimeException(e);
      }
    }

    private static Assertion buildAssertion(User user, PatientContext patient, SamlSpConnectionInfo info) {

        Assertion assertion = OpenSamlUtils.buildSAMLObject(Assertion.class);

        Issuer issuer = OpenSamlUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(MockIdpConstants.LOCAL_IDP_ENTITY_ID);
        assertion.setIssuer(issuer);
        assertion.setIssueInstant(new DateTime());

        assertion.setID(OpenSamlUtils.generateSecureRandomId());

        Subject subject = OpenSamlUtils.buildSAMLObject(Subject.class);
        assertion.setSubject(subject);

        NameID nameID = OpenSamlUtils.buildSAMLObject(NameID.class);
        
        nameID.setFormat(NameIDType.EMAIL);
        	nameID.setValue(user.getEmail());
        
        nameID.setSPNameQualifier(info.getSamlSpMetadata().getEntityId());
        nameID.setNameQualifier(MockIdpConstants.LOCAL_IDP_ENTITY_ID);

        subject.setNameID(nameID);

        subject.getSubjectConfirmations().add(buildSubjectConfirmation(info));

        assertion.setConditions(buildConditions(info));

        assertion.getAttributeStatements().add(buildAttributeStatement(user, patient, info));

        assertion.getAuthnStatements().add(buildAuthnStatement());

        return assertion;
    }

    private static SubjectConfirmation buildSubjectConfirmation(SamlSpConnectionInfo info) {
        SubjectConfirmation subjectConfirmation = OpenSamlUtils.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData subjectConfirmationData = OpenSamlUtils.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setInResponseTo("Made up ID");
        if (info.getSubjectConfirmationValidity().equalsIgnoreCase("valid")) {
          subjectConfirmationData.setNotBefore(new DateTime().minusDays(1));
          subjectConfirmationData.setNotOnOrAfter(new DateTime().plusDays(1));
        } else if (info.getSubjectConfirmationValidity().equalsIgnoreCase("expired")) {
          subjectConfirmationData.setNotBefore(new DateTime().minusDays(2));
          subjectConfirmationData.setNotOnOrAfter(new DateTime().minusDays(1));
        } else if (info.getSubjectConfirmationValidity().equalsIgnoreCase("future")) {
          subjectConfirmationData.setNotBefore(new DateTime().plusDays(1));
          subjectConfirmationData.setNotOnOrAfter(new DateTime().plusDays(2));
        } else if (info.getSubjectConfirmationValidity().equalsIgnoreCase("reversed")) {
          subjectConfirmationData.setNotBefore(new DateTime().plusDays(1));
          subjectConfirmationData.setNotOnOrAfter(new DateTime().minusDays(1));
        }
        subjectConfirmationData.setRecipient(getSpSsoAssertionConsumerLocation(info));

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        return subjectConfirmation;
    }

    private static AuthnStatement buildAuthnStatement() {
        AuthnStatement authnStatement = OpenSamlUtils.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = OpenSamlUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = OpenSamlUtils.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.SMARTCARD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);

        authnStatement.setAuthnInstant(new DateTime());



        return authnStatement;
    }

    private static Conditions buildConditions(SamlSpConnectionInfo info) {
        Conditions conditions = OpenSamlUtils.buildSAMLObject(Conditions.class);
      if (info.getSamlConditionsValidity().equalsIgnoreCase("valid")) {
        conditions.setNotBefore(new DateTime().minusDays(1));
        conditions.setNotOnOrAfter(new DateTime().plusDays(1));
      } else if (info.getSamlConditionsValidity().equalsIgnoreCase("expired")) {
        conditions.setNotBefore(new DateTime().minusDays(2));
        conditions.setNotOnOrAfter(new DateTime().minusDays(1));
      } else if (info.getSamlConditionsValidity().equalsIgnoreCase("future")) {
        conditions.setNotBefore(new DateTime().plusDays(1));
        conditions.setNotOnOrAfter(new DateTime().plusDays(2));
      } else if (info.getSamlConditionsValidity().equalsIgnoreCase("reversed")) {
        conditions.setNotBefore(new DateTime().plusDays(1));
        conditions.setNotOnOrAfter(new DateTime().minusDays(1));
      }
        
        
        AudienceRestriction audienceRestriction = OpenSamlUtils.buildSAMLObject(AudienceRestriction.class);
        Audience audience = OpenSamlUtils.buildSAMLObject(Audience.class);
        audience.setAudienceURI(info.getSamlSpMetadata().getEntityId());
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);


        return conditions;
    }
    
    public static Properties parsePropertiesString(String s) throws IOException {
        // grr at load() returning void rather than the Properties object
        // so this takes 3 lines instead of "return new Properties().load(...);"
        final Properties p = new Properties();
        p.load(new StringReader(s));
        return p;
    }

    private static AttributeStatement buildAttributeStatement(User user, PatientContext patient, SamlSpConnectionInfo info) {
        AttributeStatement attributeStatement = OpenSamlUtils.buildSAMLObject(AttributeStatement.class);
        Properties prop = null;


        Attribute attributeUserName = OpenSamlUtils.buildSAMLObject(Attribute.class);

        XSStringBuilder stringBuilder = (XSStringBuilder)XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        userNameValue.setValue(user.getUserName());

        attributeUserName.getAttributeValues().add(userNameValue);
        attributeUserName.setName("userName");
        attributeStatement.getAttributes().add(attributeUserName);
        
        
        Attribute attributeEmail = OpenSamlUtils.buildSAMLObject(Attribute.class);
        XSString emailValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        emailValue.setValue(user.getEmail());
        
        attributeEmail.getAttributeValues().add(emailValue);
        attributeEmail.setName("email");
        attributeStatement.getAttributes().add(attributeEmail);

        Attribute attributeFirstName = OpenSamlUtils.buildSAMLObject(Attribute.class);
        XSString firstNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        firstNameValue.setValue(user.getFirstName());
        
        attributeFirstName.getAttributeValues().add(firstNameValue);
        attributeFirstName.setName("firstName");
        attributeStatement.getAttributes().add(attributeFirstName);
        
        Attribute attributeLastName = OpenSamlUtils.buildSAMLObject(Attribute.class);
        XSString lastNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        lastNameValue.setValue(user.getLastName());
        
        attributeLastName.getAttributeValues().add(lastNameValue);
        attributeLastName.setName("lastName");
        attributeStatement.getAttributes().add(attributeLastName);

        if (patient != null) {
          if (info.getPatientContextInRequest() == null
              || info.getPatientContextInRequest() == false) {

            if (patient.getPatientSourceCode() != null) {
              Attribute attributeSourceCode = OpenSamlUtils.buildSAMLObject(Attribute.class);
              XSString sourceCodeValue = stringBuilder
                  .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
              sourceCodeValue.setValue(patient.getPatientSourceCode());

              attributeSourceCode.getAttributeValues().add(sourceCodeValue);
              attributeSourceCode.setName("patientSourceCode");
              attributeStatement.getAttributes().add(attributeSourceCode);
            }

            if (patient.getOid() != null) {
              Attribute attributeOid = OpenSamlUtils.buildSAMLObject(Attribute.class);
              XSString oidValue = stringBuilder
                  .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
              oidValue.setValue(patient.getOid());

              attributeOid.getAttributeValues().add(oidValue);
              attributeOid.setName("patientOid");
              attributeStatement.getAttributes().add(attributeOid);
            }

            if (patient.getPatientAccountNumber() != null) {
              Attribute attributePatientAccountNumber = OpenSamlUtils
                  .buildSAMLObject(Attribute.class);
              XSString patientAccountNumberValue = stringBuilder
                  .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
              patientAccountNumberValue.setValue(patient.getPatientAccountNumber());

              attributePatientAccountNumber.getAttributeValues().add(patientAccountNumberValue);
              attributePatientAccountNumber.setName("patientAccountNumber");
              attributeStatement.getAttributes().add(attributePatientAccountNumber);
            }

            if (patient.getExternalMrn() != null) {
              Attribute attributeExternalMrn = OpenSamlUtils.buildSAMLObject(Attribute.class);
              XSString externalMrnValue = stringBuilder
                  .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
              externalMrnValue.setValue(patient.getExternalMrn());

              attributeExternalMrn.getAttributeValues().add(externalMrnValue);
              attributeExternalMrn.setName("externalMrn");
              attributeStatement.getAttributes().add(attributeExternalMrn);
            }
          }
        }

        // for now pass roles as comma separated string
        if ( user.getRoles() != null && !user.getRoles().isEmpty()) {
            Attribute attrRoles = OpenSamlUtils.buildSAMLObject(Attribute.class);
            XSString rolesValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,  XSString.TYPE_NAME);
            rolesValue.setValue(StringUtils.join(user.getRoles(), ","));
            attrRoles.getAttributeValues().add(rolesValue);
            attrRoles.setName("Roles");
            attributeStatement.getAttributes().add(attrRoles);
        }
        // if info.crazyshit == true, do crazy shit
        
        return attributeStatement;

    }
    
	
}

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

import java.io.Serializable;
import java.io.StringWriter;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SignableSAMLObject;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

@Slf4j
public class OpenSamlUtils {
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static {
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    }
    
    public static String toString(Element doc) {
 	    try {
 	        StringWriter sw = new StringWriter();
 	        TransformerFactory tf = TransformerFactory.newInstance();
 	        Transformer transformer = tf.newTransformer();
 	        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
 	        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
 	        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
 	        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

 	        transformer.transform(new DOMSource(doc), new StreamResult(sw));
 	        return sw.toString();
 	    } catch (Exception ex) {
 	        throw new RuntimeException("Error converting to String", ex);
 	    }
 	}

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static void logSAMLObject(final XMLObject object) {
        Element element = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                log.error(e.getMessage(), e);
            }
        }

        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(element);

            transformer.transform(source, result);
            String xmlString = result.getWriter().toString();

            log.info(xmlString);
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }
    
    

public static Serializable getXMLObjectValue(XMLObject xmlObject) {
	if (xmlObject instanceof XSAny) {
		XSAny xsAny = (XSAny)xmlObject;

		return xsAny.getTextContent();
	}
	else if (xmlObject instanceof XSBoolean) {
		XSBoolean xsBoolean = (XSBoolean)xmlObject;

		XSBooleanValue xsBooleanValue = xsBoolean.getValue();

		return xsBooleanValue.getValue();
	}
	else if (xmlObject instanceof XSDateTime) {
		XSDateTime xsDateTime = (XSDateTime)xmlObject;

		return String.valueOf(xsDateTime.getValue());
	}
	else if (xmlObject instanceof XSInteger) {
		XSInteger xsInteger = (XSInteger)xmlObject;

		return xsInteger.getValue();
	}
	else if (xmlObject instanceof XSString) {
		XSString xsString = (XSString)xmlObject;

		return xsString.getValue();
	}

	return null;
}
}

# The Audacious Inquiry Mock Identity Provider

This is a simple identity provider to facilitate testing of single sign-on based on standard federated identity authentication standards.

## Setup the Mock Identity Provider

Modify the list of Authenticated Users

The mock identity provider utilizes simulated users to generated federated authentication messages via SAML.   Users are defined via individual YAML (*.yml) files in the data directory of the project.

The format of the YAML file is as follows:

````
userName: tmctestface
email: testy@ainq.com
firstName: Testy
lastName: McTestFace
patients:
  - oid: 1.11.111.1.111111.1.111.11
    patientAccountNumber: 1234123412
    externalMrn: 1234
    patientSourceCode: TEST_SRC
  - oid: 1.11.111.1.111111.1.111.11
    patientAccountNumber: 1234123412
    externalMrn: 1234
    patientSourceCode: TEST_SRC    
roles:
  - Clinician
  - Admin
````

## Run the Mock Identity Provider

The Ai Mock Identity Provider can be executed as either a Spring Boot Application or a Docker container.

### Spring Boot Execution

To execute as a Spring boot application, you must have Open JDK version 8.  From a command prompt or terminal, execute the following from the root directory of the project

`````
./gradlew bootRun
`````

### Docker Execution

To execute using Docker, the Docker service agent must first be running on your machine.  From a command prompt or terminal, navigate to the root directory of the project and execute the following command to build the docker image:

`````
docker build --no-cache --build-arg data_directory=/data -t ainq/mock-idp .
`````

Once the container image has been built, run the container with the following command:
`````
docker run -p 8081:8081 ainq/mock-idp
`````

## Using the Mock Identity Provider

Open a web browser, such as Chrome and navigate to the following URL:

http://localhost:8081

The following screen should be rendered to the browser:

![Mock IDP Screen](images/mockIdp.png)

### SAML Service Provider Metadata
The Ai Mock Identity Provider requires a valid SAML Service Provider Metadata to integrate with the downstream service provider.  If a valid metadata file is not available, it can be mocked up using the valid public certificate values for encryption and signing as well as the valid AssertionConsumerService urls for the HTTP POST SAML Binding.

The below sample can be used as a starting point to mock up the metadata:

````
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/sp/mockIdp/defaultTenant">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:assertion urn:oasis:names:tc:SAML:2.0:protocol">
  <md:KeyDescriptor use="signing">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>
  MIIGfjCCBGagAwIBAgIC... PUBLIC CERTIFICATE CONTENTS ...TiQ/1WuGZRhNQoIZdQ==
  </ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:KeyDescriptor>
  <md:KeyDescriptor use="encryption">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>
  MIIGfjCCBGagAwIBAgIC... PUBLIC CERTIFICATE CONTENTS ...TiQ/1WuGZRhNQoIZdQ==
  </ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
  </md:KeyDescriptor>
  <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://ui.pulsedev-ainq.com:9709/v1/sp/mockIdp/slo"/>
  <md:NameIDFormat>
  urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
  </md:NameIDFormat>
  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/sp/mockIdp/consumer/POST/defaultTenant" index="0"/>
  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://example.com/sp/mockIdp/consumer" index="1"/>
  </md:SPSSODescriptor>
  </md:EntityDescriptor>
````

If a Metadata Url is published to the internet for the correponding service provider, then the URL can be used instead of the XML.

### Private Key for XML Signing

If the downstream service provider requires the signing of assertions or SAML responses, then the private key that corresponds to the public certificate that was shared with the Service Provider should be utilized to verify the authenticity of the authentication.

The key should be an RSA private key in PEM format (e.g. starts with -----BEGIN PRIVATE KEY----- and ends with -----END PRIVATE KEY-----)

### Public Certificate for XML Signing

If the downstream service provider requires the signing of assertions or SAML responses, then the public certificate that has been shared with the downstream service provider and has been generated from the private key should be utilized to verify the authenticity of the authentication.

The certificate should be an x.509 certificate in PEM format (e.g. starts with -----BEGIN CERTIFICATE----- and ends with -----END CERTIFICATE-----)

### Additional Options

The Audacious Inquiry Mock Identity Provider allows for modification of the federated login to facilitate positive and negative test scenarios for the SAML authentication flows.  The following options can be toggled:
* Encrypting or Not Encrypting the SAML Assertion
* Signing or Not Signing the SAML Assertion
* Signing or Not Signing the SAML Response

There is also the capability to tweak the validity time periods for SAML Subject Confirmation Validity and SAML Conditions Validity.  The options are as follows:
* Valid
* Not valid as the time period has expired
* Not valid as the time period is in the future
* Not valid as the time period has been reversed (NotBefore is after NotOnOrAfter)

Additionally, if the downstream SP system supports the tranmission of Patient Context, additional Patient information can be sent via either Request Parameters or as part of the SAML Assertion.

Finally, the mock IdP offers a debug mode, to allow easy debugging for the SAML Response and Assertion that is generated.
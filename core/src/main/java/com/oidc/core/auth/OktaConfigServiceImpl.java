package com.oidc.core.auth;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = OktaConfigService.class, immediate = true)
@Designate(ocd = OktaConfigServiceImpl.Config.class)
public class OktaConfigServiceImpl implements OktaConfigService {

  private final Logger log = LoggerFactory.getLogger(OktaConfigServiceImpl.class);
  private String oktaIssuer;
  private String oktaClientId;
  private String clientSecret;
  private String[] scopes;
  private String authCallback;

  @ObjectClassDefinition(
      name = "Okta OIDC Config",
      description = "Configuration to authenticate against Okta for OIDC")
  @interface Config {
    @AttributeDefinition(name = "Okta Issuer", type = AttributeType.STRING)
    String getIssuer();
    @AttributeDefinition(name = "Okta ClientId", type = AttributeType.STRING)
    String getClientId();
    @AttributeDefinition(name = "Encrypted Okta ClientSecret", type = AttributeType.STRING)
    String getClientSecret();
    @AttributeDefinition(name = "Okta Scopes", type = AttributeType.STRING)
    String[] getScopes();
    @AttributeDefinition(name = "Redirect URI", type = AttributeType.STRING)
    String getAuthCallback();
  }

  @Activate
  void activate(Config config) {
    log.info("Activating Okta Config Service");
    this.oktaIssuer = config.getIssuer();
    this.oktaClientId = config.getClientId();
    this.clientSecret = config.getClientSecret();
    this.scopes = config.getScopes();
    this.authCallback = config.getAuthCallback();
  }

  @Override
  public String getIssuer() {
    return this.oktaIssuer;
  }

  @Override
  public String getClientId() {
    return this.oktaClientId;
  }

  @Override
  public String getClientSecret() {
    return this.clientSecret;
  }

  @Override
  public String getScopes() {
    return String.join("%20", this.scopes);
  }

  @Override
  public String getAuthCallback() {
    return this.authCallback;
  }
}

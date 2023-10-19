package com.oidc.core.auth;

/**
 * Service to provide configuration for Okta OIDC
 */
public interface OktaConfigService {

  /**
   * Get the issuer for the Okta OIDC provider
   *
   * @return the issuer
   */
  public String getIssuer();

  /**
   * Get the client id for the Okta OIDC provider
   *
   * @return the client id
   */
  public String getClientId();

  /**
   * Get the client secret for the Okta OIDC provider
   *
   * @return the client secret
   */
  public String getClientSecret();

  /**
   * Get the scopes for the Okta OIDC provider
   *
   * @return the scopes
   */
  public String getScopes();

  /**
   * Get the callback for the Okta OIDC provider
   *
   * @return the callback
   */
  public String getAuthCallback();
}

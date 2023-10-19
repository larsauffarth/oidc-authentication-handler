package com.oidc.core.auth;

import static com.oidc.core.auth.OpenIdConnectAuthHandler.SERVICE_RANKING;

import com.day.crx.security.token.TokenCookie;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OpenIdConnect Authentication Handler
 */
@Component(service = AuthenticationHandler.class, immediate = true, property = {
    "path=" + "/content",
    Constants.SERVICE_RANKING + SERVICE_RANKING,
    Constants.SERVICE_DESCRIPTION + "=OIDC Authentication Handler"
})
public class OpenIdConnectAuthHandler extends DefaultAuthenticationFeedbackHandler
    implements AuthenticationHandler {

  public static final String SERVICE_RANKING = ":Integer=" + Integer.MAX_VALUE;

  private final Logger log = LoggerFactory.getLogger(OpenIdConnectAuthHandler.class);

  private static final String TOKEN_ID = ".token";
  private static final String PATH_TO_ID_TOKEN = "/oidcTokens/id_token";
  private static final String LOGOUT_ENDPOINT = "/v1/logout";
  private static final String LOGOUT_URI = "/specific-logout-uri";
  private static final String ACCESS_TOKEN = "access_token";
  private static final String USER_ID_KEY = "preferredUsername";
  private static final Map<String, Object> AUTH_INFO = Collections.singletonMap(
      ResourceResolverFactory.SUBSERVICE, "OidcUserMgr");

  @Reference
  private ResourceResolverFactory resourceResolverFactory;
  @Reference
  private SlingRepository repository;
  @Reference
  private OpenIdConnectAuthService openIdConnectAuthService;
  @Reference
  private OktaConfigService oktaConfigService;

  /**
   * Called when a request is received Must return null if request shouldn't be handled, otherwise
   * returns AuthInfo for logged-in user
   * @return AuthenticationInfo object or null
   */
  @Override
  public AuthenticationInfo extractCredentials(HttpServletRequest request,
      HttpServletResponse response) {
    // check if the request contains an authorization code as part of the
    // authentication procedure
    String code = request.getParameter("code");
    // if the code is present and the request URI matches with the configured
    // value, we handle the request and return an AuthenticationInfo object
    if (code != null && !code.isEmpty()
        && oktaConfigService.getAuthCallback().contains(request.getRequestURI())) {
      // use the code to exchange it for OpenIDConnect tokens
      Map<String, String> tokens = openIdConnectAuthService
          .exchangeTokenForCode(code);
      // use the accessToken to get the user data
      JsonObject userData = openIdConnectAuthService.getUserData(tokens.get(ACCESS_TOKEN));
      // ... run any custom validations for your set of user data

      // use obtained user information to create an AuthenticationInfo object
      try (ResourceResolver resourceResolver = resourceResolverFactory
          .getServiceResourceResolver(AUTH_INFO)) {
        // extract data from response and transform provided attributes into
        // a map
        Map<String, String> attributes = openIdConnectAuthService.createUserAttributes(userData);
        // get the field that contains the user id (this is dependent on your
        // Okta configuration, in this case it is labelled userIdField
        String userId = attributes.get(USER_ID_KEY);
        // try to get the user with this id
        UserManager userManager = resourceResolver
            .adaptTo(UserManager.class);
        Authorizable user = userManager.getAuthorizable(userId);
        // in case no user exists, the user needs to be created
        if (user == null) {
          // here, this is handled in the createNewUser method which uses the
          // userId as password to keep this example concise.
          // You'll want to create a more sophisticated password
          user = openIdConnectAuthService.createNewUser(userManager, attributes, tokens);
        } else {
          // if the user exists, the obtained values need to be updated and any
          // subsequent processing steps need to be performed.
          // Here, the obtained tokens are synced to the user as well, so that
          // these may be used to request resources on the users behalf
          openIdConnectAuthService.updateAndSyncUser(user, attributes, tokens);
        }
        // add groups (use your own logic to determine the groups)
        Group oidcUsers = (Group) userManager.getAuthorizable("oidcUsers");
        oidcUsers.addMember(user);
        // save changes
        Session userMgrSession = resourceResolver
            .adaptTo(Session.class);
        userMgrSession.save();
        // create a new AuthenticationInfo object that makes use of the standard
        // AEM token authentication
        final AuthenticationInfo authInfo = new AuthenticationInfo("TOKEN",
            userId);
        // as the user has authenticated at this point, we use SimpleCredentials
        // to prepare the sign in of the user - as we used the userId
        // as password during user creation, we create the credentials as follows
        SimpleCredentials sc = new SimpleCredentials(userId,
            userId.toCharArray());
        // and we set a dummy token which will be updated
        sc.setAttribute(TOKEN_ID, "");

        // log in using the credentials to record the log in event
        repository.login(sc);

        // use the associated session to create TokenCredentials
        TokenCredentials tc = new TokenCredentials((String)
            sc.getAttribute(TOKEN_ID));
        // and set the token-credentials in authenticationInfo object
        authInfo.put("user.jcr.credentials", tc);

        // set or update login token cookie
        String repoId = repository.getDescriptor("crx.cluster.id");
        TokenCookie.update(request, response, repoId, tc.getToken(),
            repository.getDefaultWorkspace(), true);
        return authInfo;
      } catch (Exception e) {
        // handle exception
        log.error("Error while extracting credentials", e);
      }
    }
    // otherwise, this auth-handler can't handle the request and null is returned
    return null;
  }

  /**
   * Redirect to OpenID Connect endpoint
   * @return Always return true since for requesting credentials, we need to redirect to Okta.
   */
  @Override
  public boolean requestCredentials(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse)
      throws IOException {
    // set the OpenIdConnect Endpoint, should end with /authorize
    String oktaAuthEndpoint = oktaConfigService.getIssuer()
        + "/oauth2/default/v1/authorize?client_id=" + oktaConfigService.getClientId()
        + "&response_type=code&redirect_uri=" + oktaConfigService.getAuthCallback()
        + "&scope=" + oktaConfigService.getScopes() + "&state=" + UUID.randomUUID();
    // send redirect the user to OpenId Connect Endpoint
    httpServletResponse.sendRedirect(oktaAuthEndpoint);
    return true;
  }

  /**
   * Called when authentication succeeds
   */
  @Override
  public boolean authenticationSucceeded(final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationInfo authInfo) {
    // add custom redirecting logic here
    // check if the request URI matches the configured redirect URI identifier
    if (request.getRequestURI().contains("oidc_callback")) {
      // redirect to the page that should be shown after successful login
      String redirectUrl = "/content/oidc/us/en.html";
      // get the token from the authInfo object
      Object a = authInfo.get(TOKEN_ID);
      if (a != null && !a.toString().isEmpty()) {
        String token = a.toString();
        String repoId = repository.getDescriptor("crx.cluster.id");
        // set or update login token cookie
        TokenCookie.update(request, response, repoId, token, repository.getDefaultWorkspace(),
            true);
      }
      try {
        response.sendRedirect(redirectUrl);
      } catch (IOException e) {
        // handle error case
        log.error("Error while redirecting to {}", redirectUrl, e);
      }
      return true;
    } else {
      // if the request URI doesn't match the configured redirect URI, we pass
      // the request on to the DefaultAuthenticationFeedbackHandler
      return DefaultAuthenticationFeedbackHandler.handleRedirect(request, response);
    }
  }

  /*
   * Invoked on logout request on a resource protected by the auth handler
   * and redirects with id_token to okta logout endpoint
   */
  @Override
  public void dropCredentials(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse) throws IOException {
    // Verify that the httpServletRequest is a SlingHttpServletRequest,
    // so that the user can be identified and the id_token can be retrieved
    if (httpServletRequest instanceof SlingHttpServletRequest) {
      String idToken = "";
      try {
        SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) httpServletRequest;
        Authorizable user = slingRequest.getResourceResolver().adaptTo(Authorizable.class);
        // as mentioned earlier, we stored the tokens in the user's node
        // under "/oidcTokens/id_token"
        Value[] idTokenValue = user.getProperty(PATH_TO_ID_TOKEN);
        idToken = idTokenValue[0].getString();
      } catch (Exception e) {
        // handle error case
        log.error("Error while dropping credentials", e);
      }
      String idTokenHint = "?id_token_hint=" + idToken;
      String postLogoutURL = "&post_logout_redirect_uri=" + LOGOUT_URI;
      String logoutUri =
          oktaConfigService.getIssuer() + LOGOUT_ENDPOINT + idTokenHint + postLogoutURL;
      httpServletResponse.sendRedirect(logoutUri);
    }
  }
}

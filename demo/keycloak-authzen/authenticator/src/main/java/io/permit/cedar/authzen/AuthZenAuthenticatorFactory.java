package io.permit.cedar.authzen;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory that registers the {@link AuthZenAuthenticator} with Keycloak and
 * exposes its per-execution configuration (PDP URL, action name, resource type,
 * fail-open behaviour).
 */
public class AuthZenAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "authzen-access-evaluation";

    static final String CONFIG_PDP_URL = "pdpUrl";
    static final String CONFIG_ACTION = "action";
    static final String CONFIG_RESOURCE_TYPE = "resourceType";
    static final String CONFIG_FAIL_OPEN = "failOpen";

    // The authenticator is stateless, so a single shared instance is fine.
    private static final AuthZenAuthenticator SINGLETON = new AuthZenAuthenticator();

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getDisplayType() {
        return "AuthZEN Access Evaluation";
    }

    @Override
    public String getReferenceCategory() {
        return "authorization";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Performs an AuthZEN access evaluation against an external PDP "
                + "(authzen-sidecar) at login time and denies the login when the "
                + "decision is false.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty pdpUrl = new ProviderConfigProperty(
                CONFIG_PDP_URL,
                "PDP base URL",
                "Base URL of the AuthZEN PDP (authzen-sidecar), e.g. http://authzen-sidecar:9000",
                ProviderConfigProperty.STRING_TYPE,
                "http://authzen-sidecar:9000");

        ProviderConfigProperty action = new ProviderConfigProperty(
                CONFIG_ACTION,
                "Action name",
                "AuthZEN action name to evaluate (maps to Cedar Action::\"<name>\").",
                ProviderConfigProperty.STRING_TYPE,
                "login");

        ProviderConfigProperty resourceType = new ProviderConfigProperty(
                CONFIG_RESOURCE_TYPE,
                "Resource type",
                "Cedar entity type used for the resource. The resource id is the "
                        + "Keycloak client id of the login target.",
                ProviderConfigProperty.STRING_TYPE,
                "Client");

        ProviderConfigProperty failOpen = new ProviderConfigProperty(
                CONFIG_FAIL_OPEN,
                "Fail open",
                "If enabled, allow the login when the PDP cannot be reached. "
                        + "Not recommended for production.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                "false");

        return List.of(pdpUrl, action, resourceType, failOpen);
    }
}

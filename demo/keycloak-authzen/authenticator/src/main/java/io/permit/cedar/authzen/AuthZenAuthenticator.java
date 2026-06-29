package io.permit.cedar.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Browser-flow authenticator that asks an AuthZEN PDP (authzen-sidecar) whether
 * the authenticated user is allowed to log into the requesting client.
 *
 * <p>The AuthZEN request is built as:
 * <pre>
 *   subject  = { type: "User", id: &lt;username&gt;, properties: { user_type, department } }
 *   action   = { name: &lt;configured action, default "login"&gt; }
 *   resource = { type: &lt;configured type, default "Client"&gt;, id: &lt;clientId&gt; }
 *   context  = { ip, access_route }
 * </pre>
 * A {@code decision: false} (or an unreachable PDP when fail-open is off) denies
 * the login with {@link AuthenticationFlowError#ACCESS_DENIED}.
 */
public class AuthZenAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(AuthZenAuthenticator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final String DEFAULT_PDP_URL = "http://authzen-sidecar:9000";
    private static final String DEFAULT_ACTION = "login";
    private static final String DEFAULT_RESOURCE_TYPE = "Client";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            // No authenticated user yet; nothing to evaluate. Let the flow proceed.
            context.attempted();
            return;
        }

        Map<String, String> config = configOf(context);
        String pdpUrl = trimTrailingSlash(
                config.getOrDefault(AuthZenAuthenticatorFactory.CONFIG_PDP_URL, DEFAULT_PDP_URL));
        String action = config.getOrDefault(AuthZenAuthenticatorFactory.CONFIG_ACTION, DEFAULT_ACTION);
        String resourceType =
                config.getOrDefault(AuthZenAuthenticatorFactory.CONFIG_RESOURCE_TYPE, DEFAULT_RESOURCE_TYPE);
        boolean failOpen = Boolean.parseBoolean(
                config.getOrDefault(AuthZenAuthenticatorFactory.CONFIG_FAIL_OPEN, "false"));

        ClientModel client = context.getAuthenticationSession().getClient();
        String clientId = client != null ? client.getClientId() : "unknown";
        String ip = remoteIp(context);

        Map<String, Object> body = buildEvaluationRequest(user, action, resourceType, clientId, ip);

        boolean decision;
        try {
            decision = evaluate(pdpUrl, body);
        } catch (Exception e) {
            log.errorf(e, "AuthZEN PDP call failed (pdpUrl=%s, user=%s, client=%s)",
                    pdpUrl, user.getUsername(), clientId);
            if (failOpen) {
                log.warn("fail-open enabled: allowing login despite PDP error");
                context.success();
            } else {
                context.failure(AuthenticationFlowError.ACCESS_DENIED);
            }
            return;
        }

        log.infof("AuthZEN decision=%s user=%s client=%s ip=%s",
                decision, user.getUsername(), clientId, ip);

        if (decision) {
            context.success();
        } else {
            context.getEvent().detail("authzen_decision", "deny");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    private Map<String, Object> buildEvaluationRequest(
            UserModel user, String action, String resourceType, String clientId, String ip) {

        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", "User");
        subject.put("id", user.getUsername());

        Map<String, Object> properties = new LinkedHashMap<>();
        putIfPresent(properties, "user_type", user.getFirstAttribute("user_type"));
        putIfPresent(properties, "department", user.getFirstAttribute("department"));
        if (!properties.isEmpty()) {
            subject.put("properties", properties);
        }

        Map<String, Object> actionNode = new LinkedHashMap<>();
        actionNode.put("name", action);

        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("type", resourceType);
        resource.put("id", clientId);

        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("ip", ip == null ? "" : ip);
        ctx.put("access_route", classifyRoute(ip));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", subject);
        body.put("action", actionNode);
        body.put("resource", resource);
        body.put("context", ctx);
        return body;
    }

    private boolean evaluate(String pdpUrl, Map<String, Object> body) throws Exception {
        String json = MAPPER.writeValueAsString(body);
        // Demo aid: log the exact AuthZEN request body sent to the PDP.
        log.infof("AuthZEN request -> %s/access/v1/evaluation: %s", pdpUrl, json);
        HttpRequest request = HttpRequest.newBuilder(URI.create(pdpUrl + "/access/v1/evaluation"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "PDP returned HTTP " + response.statusCode() + ": " + response.body());
        }
        JsonNode node = MAPPER.readTree(response.body());
        return node.path("decision").asBoolean(false);
    }

    private static Map<String, String> configOf(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel == null || configModel.getConfig() == null) {
            return Collections.emptyMap();
        }
        return configModel.getConfig();
    }

    private static void putIfPresent(Map<String, Object> map, String key, String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }

    private static String trimTrailingSlash(String url) {
        return url.replaceAll("/+$", "");
    }

    /**
     * Resolve the remote IP of the login request. When an {@code X-Forwarded-For}
     * header is present (Keycloak behind a reverse proxy) its first hop is used —
     * this also lets the demo simulate an internet-facing login by setting the
     * header. Otherwise the direct connection address is used.
     */
    private static String remoteIp(AuthenticationFlowContext context) {
        try {
            String xff = context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }
        } catch (Exception ignored) {
            // fall back to the direct connection address below
        }
        return context.getConnection() != null ? context.getConnection().getRemoteAddr() : null;
    }

    /**
     * Classify the remote address as an {@code internal} or {@code internet}
     * access route. This is a demo-grade heuristic (loopback and RFC 1918 ranges
     * count as internal; everything else is treated as coming from the internet).
     */
    static String classifyRoute(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        if (ip.startsWith("127.") || ip.equals("::1") || ip.equals("0:0:0:0:0:0:0:1")) {
            return "internal";
        }
        if (ip.startsWith("10.") || ip.startsWith("192.168.")) {
            return "internal";
        }
        if (ip.startsWith("172.")) {
            String[] parts = ip.split("\\.");
            if (parts.length > 1) {
                try {
                    int second = Integer.parseInt(parts[1]);
                    if (second >= 16 && second <= 31) {
                        return "internal";
                    }
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            }
        }
        return "internet";
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // This authenticator is non-interactive; it never issues a challenge,
        // so action() is not part of the flow.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }
}

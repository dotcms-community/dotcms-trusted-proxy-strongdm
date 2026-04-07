package com.dotcms.cloud.strongdm.util;


import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.dotcms.business.WrapInTransaction;
import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.http.CircuitBreakerUrl;
import com.dotcms.rest.api.v1.DotObjectMapperProvider;
import com.dotcms.util.SecurityUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.DotStateException;
import com.dotmarketing.business.Layout;
import com.dotmarketing.business.LayoutAPI;
import com.dotmarketing.business.Role;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.UtilMethods;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.liferay.portal.model.User;
import io.vavr.control.Try;


public class StrongDmUtils {

    final String FAILURE = "FAILURE";
    final String validationUrl = "https://app.strongdm.com/validate";

    
    public void updateValidReferers(final String hostName) throws Exception {

        Logger.info(this.getClass().getName(), "Updating valid referers with: " + hostName);

        String paths = Config.getStringProperty("IGNORE_REFERER_FOR_HOSTS", "" );
        
        if(paths.contains(hostName)) {
            Logger.info(this.getClass().getName(), "skipping IGNORE_REFERER_FOR_HOSTS : " + paths);
            return;
        }
        paths = paths.length()>0 ? paths + "," + hostName : hostName;
        
        Config.setProperty("IGNORE_REFERER_FOR_HOSTS", paths);
        
        // Get field instance
        final Field field = SecurityUtils.class.getDeclaredField("IGNORE_REFERER_FOR_HOSTS");
        field.setAccessible(true); // Suppress Java language access checking

        Logger.info(this.getClass().getName(), "IGNORE_REFERER_FOR_HOSTS current value : " + field.get(null));

        // Set value
        field.set(null, null);

    }


    /**
     * Creates User if they do not exist, also ensures they are activated and have Admin and Backend Roles
     * @param userMap
     * @return
     */
    public User validateUser(Map<String, String> userMap) {

        String email = userMap.get("email");
        String firstName = userMap.get("firstName");
        String lastName = userMap.get("lastName");

        User user = Try.of(() -> APILocator.getUserAPI().loadByUserByEmail(userMap.get("email"),
                        APILocator.systemUser(), false)).getOrNull();

        if (user == null) {
            user = createUser(email, firstName, lastName);
        }

        if (!user.isActive()) {
            user.setActive(true);
            saveUser(user);
        }

        if (user.hasConsoleAccess() && user.isAdmin()) {
            return user;
        }

        grantAdminRoles(user);
        grantAllLayouts(user);

        return user;
    }

    @WrapInTransaction
    private User saveUser(User user) {

        Try.run(() -> APILocator.getUserAPI().save(user, APILocator.systemUser(), false)).onFailure(e -> {
            throw new DotRuntimeException(e);
        });
        return user;
    }


    @WrapInTransaction
    private boolean grantAdminRoles(User user) {


        if (user.isAdmin() && user.isBackendUser()) {
            return true;
        }
        Try.run(() -> {
            if (!user.isAdmin()) {
                Role role = APILocator.getRoleAPI().loadCMSAdminRole();
                APILocator.getRoleAPI().addRoleToUser(role, user);
                role = APILocator.getRoleAPI().loadBackEndUserRole();
                APILocator.getRoleAPI().addRoleToUser(role, user);

            }
        }).onFailure(e -> new DotRuntimeException(e));
        return true;
    }


    @WrapInTransaction
    private boolean grantAllLayouts(final User user) {
        LayoutAPI api = APILocator.getLayoutAPI();
        final List<Layout> allLayouts = Try.of(() -> api.findAllLayouts()).getOrElseThrow(
                        e -> new DotStateException("Unable to find user role for user:" + user.getUserId()));
        final List<Layout> myLayouts =
                        Try.of(() -> api.loadLayoutsForUser(user)).getOrElseThrow(e -> new DotRuntimeException(e));
        final Role userRole = Try.of(() -> APILocator.getRoleAPI().loadRoleByKey(user.getUserId())).getOrElseThrow(
                        e -> new DotStateException("Unable to find user role for user:" + user.getUserId()));

        Set<String> myPortlets = new HashSet<>();
        Set<String> allPortlets = new HashSet<>();
        myLayouts.forEach(l -> myPortlets.addAll(l.getPortletIds()));
        allLayouts.forEach(l -> allPortlets.addAll(l.getPortletIds()));
        if (myPortlets.size() >= allPortlets.size()) {
            return true;
        }

        allLayouts.stream().filter(l -> !myPortlets.containsAll(l.getPortletIds())).forEach(l -> {
            Try.run(() -> APILocator.getRoleAPI().addLayoutToRole(l, userRole)).onFailure(e -> {
                throw new DotRuntimeException(e);
            });
            myPortlets.addAll(l.getPortletIds());
        });


        allLayouts.stream().filter(l -> !myLayouts.contains(l)).forEach(l -> {

        });
        return true;
    }


    /**
     * Default method implementation to extract the access token from the request token json response
     * 
     * @throws IOException
     */
    public Map<String, String> validateAndParseToken(final String jwtToken) throws IOException {
        if (UtilMethods.isEmpty(jwtToken)) {
            Logger.info(this.getClass().getName(), "jwtToken empty!");
            return Map.of();
        }


       Logger.info(this.getClass().getName(), "trying " + validationUrl + " with token " + jwtToken);


        Map<String,String> data = Map.of("token", jwtToken);
        ObjectMapper mapper = DotObjectMapperProvider.getInstance().getDefaultObjectMapper();
        
        Map<String,String> headers = Map.of("Content-Type", "application/json");
        
        final String response = CircuitBreakerUrl.builder()
                        .setMethod(com.dotcms.http.CircuitBreakerUrl.Method.POST)
                        .setHeaders(headers)
                        .setUrl("https://api.strongdm.com/v1/control-panel/http/verify")
                        .setTimeout(5000)
                        .setRawData(mapper.writeValueAsString(data))
                        .build()
                        .doString();
        Logger.info(this.getClass().getName(), "got response : " + response);
        Map<String, Object> map = mapper.readValue(response, Map.class);
        

        if(!(Boolean)map.getOrDefault("valid", false)) {
            Logger.info(this.getClass().getName(), "JWT validation failed : " + map);
            return Map.of();
        }
        

        java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
        String[] parts = jwtToken.split("\\.");
        if(parts.length<2) {
            throw new DotRuntimeException("Invalid JWT passed in : " + jwtToken);
        }

        String payloadJson = new String(decoder.decode(parts[1]));

        Map<String,String> returnMap = mapper.readValue(payloadJson, new TypeReference<Map<String, String>>() {});
        Logger.info(this.getClass().getName(), "JWT parsed : " + returnMap);
        return returnMap;

    }


    public void setSystemRoles(User user, boolean frontEnd) {

        final Role roleToAdd = frontEnd ? Try.of(() -> APILocator.getRoleAPI().loadLoggedinSiteRole()).getOrNull()
                        : Try.of(() -> APILocator.getRoleAPI().loadBackEndUserRole()).getOrNull();

        if (roleToAdd != null) {
            Try.run(() -> APILocator.getRoleAPI().addRoleToUser(roleToAdd, user)).onFailure(e -> {
                Logger.warn(StrongDmUtils.class.getName(), e.getMessage(), e);
            });
        }


    }


    public User createUser(final String emailAddress, String firstName, String lastName) {

        final String userId = UUIDGenerator.generateUuid();

        try {
            final User user = APILocator.getUserAPI().createUser(userId, emailAddress);
            user.setNickName(firstName);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setActive(true);

            user.setCreateDate(new Date());

            user.setPassword(PasswordFactoryProxy
                            .generateHash(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
            user.setPasswordEncrypted(true);
            APILocator.getUserAPI().save(user, APILocator.systemUser(), false);

            return user;
        } catch (Exception e) {
            throw new DotRuntimeException(e);
        }
    } // createUser.


}

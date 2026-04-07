package com.dotcms.cloud.strongdm.interceptor;

import com.dotmarketing.filters.CMSUrlUtil;
import com.dotmarketing.util.SecurityLogger;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.dotcms.auth.providers.saml.v1.DotSamlResource;
import com.dotcms.cloud.strongdm.util.StrongDmUtils;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UtilMethods;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;
import io.vavr.Function1;
import io.vavr.control.Try;

/**
 * This interceptor is used for handle the StrongDM login check on DotCMS BE.
 * 
 */
public class StrongDMInterceptor implements WebInterceptor {


    private final StrongDmUtils strongDmUtils= new StrongDmUtils();
    public StrongDMInterceptor() {

        Logger.info(StrongDMInterceptor.class.getName(), "adding backend url");


    }

    
    @Override
    public String[] getFilters() {
        return CMSUrlUtil.BACKEND_FILTERED_COLLECTION.toArray(new String[0]);
    }




    public Result intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        // If we already have a logged in user, continue
        User user = PortalUtil.getUser(request);
        if(UtilMethods.isSet(user)) {
            return Result.NEXT;
        }



        setNoCacheHeaders(response);





        Logger.info(this.getClass().getName(), "StrongDM login request");
        
        Logger.info(this.getClass().getName(), "StrongDM: headers----");
        Enumeration<String> headers = request.getHeaderNames();
        while(headers.hasMoreElements()){
            String header = headers.nextElement();
            Logger.info(this.getClass().getName(), header + " : " + request.getHeader(header));
        }
        Logger.info(this.getClass().getName(), "/StrongDM: headers----");
        final String sDMToken = request.getHeader("x-sdm-token");

        Logger.info(this.getClass(), "Got sDMToken: " +  sDMToken);




        if (UtilMethods.isEmpty(sDMToken)) {
            Logger.info(this.getClass().getName(), "No SDM User here - redirecting");
            sendRedirectHTML(response, "/dotAdmin/");
            return Result.SKIP_NO_CHAIN;
        }
        
        
        Map<String,String> jwtMap = Try.of(()->strongDmUtils.validateAndParseToken(sDMToken))
                .onFailure(e -> {
                    SecurityLogger.logInfo(this.getClass(),"StrongDM validate failed: " + e.getMessage());
                    Logger.error(this.getClass(), "StrongDM validate failed: " + e.getMessage(),e);
                }).getOrElse(Map.of());

        
        if(jwtMap.isEmpty()) {
            Logger.info(this.getClass().getName(), "Unable to find authentication token");
            response.sendError(401);
            return Result.SKIP_NO_CHAIN;
        }


        user = strongDmUtils.validateUser(jwtMap);
        
        Logger.info(this.getClass().getName(), "Authenticating User");
        if (null != user && APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString(user.getUserId()), request, response, false)) {
            sendRedirectHTML(response, "/dotAdmin/index.html?sDMToken=" + sDMToken);
            return Result.SKIP_NO_CHAIN;
        }
        
        response.sendError(403);
        
        return Result.SKIP_NO_CHAIN;

    } // intercept.


    public void setNoCacheHeaders(HttpServletResponse response) {
        // set no cache on the login page
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

    }

    
    final static String redirectTemplate =
                    new StringWriter()
                    .append("<html>")
                    .append("<head>")
                    .append("<meta http-equiv=\"refresh\" content=\"0;URL='REDIRECT_ME'\"/>")
                    .append("<style>p {font-family: Arial;font-size: 16px;color: #666;margin: 50px;text-align:center;opacity: 1;animation: fadeIn ease 5s;animation-iteration-count: 0;-webkit-animation: fadeIn ease 5s;}@keyframes fadeIn {0% {opacity:0;}100% {opacity:1;}}@-moz-keyframes fadeIn {0% {opacity:0;}100% {opacity:1;}}@-webkit-keyframes fadeIn {0% {opacity:0;}100% {opacity:1;}}@-o-keyframes fadeIn {0% {opacity:0;}100% {opacity:1;}@-ms-keyframes fadeIn {0% {opacity:0;}100% {opacity:1;}}</style>")
                    .append("</head>")
                    .append("<body><p>If your browser does not refresh, click <a href=\"REDIRECT_ME\">Here</a>.</p></body>")
                    .append("</html>")
                    .toString();
                


    
    void sendRedirectHTML(HttpServletResponse response, final String redirectUrl) {
        
        final String finalTemplate = UtilMethods.replace(redirectTemplate,"REDIRECT_ME", redirectUrl);
        setNoCacheHeaders(response);
        response.setContentType("text/html");
        Try.run(() -> {
            response.getWriter().write(finalTemplate);
            response.getWriter().flush();
        }).onFailure(e->Logger.warn(DotSamlResource.class,"Unable to redirect to :" + redirectUrl+ " cause:"+e.getMessage()));

    }
        
    
    
    
} 

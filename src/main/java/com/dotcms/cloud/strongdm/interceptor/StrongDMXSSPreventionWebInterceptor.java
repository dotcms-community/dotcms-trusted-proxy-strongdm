package com.dotcms.cloud.strongdm.interceptor;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.dotcms.cloud.strongdm.util.StrongDmUtils;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.filters.interceptor.dotcms.XSSPreventionWebInterceptor;
import com.dotmarketing.util.Logger;

/**
 * Interceptor created to validate referers for incoming requests. This will reject any calls to
 * URIs that do not include a valid referer or Origin header and will help prevent XSS attacks
 */
public class StrongDMXSSPreventionWebInterceptor implements WebInterceptor {


    private static final long serialVersionUID = 1L;
    private final WebInterceptor xssInterceptor = new XSSPreventionWebInterceptor();
    
    
    
    
  @Override
  public Result intercept(final HttpServletRequest request, HttpServletResponse response) throws IOException {

    
    final String sDMToken = request.getParameter("sDMToken");
    if(null!= sDMToken && !new StrongDmUtils().validateAndParseToken(sDMToken).isEmpty()) {
        Logger.info(getClass(), "got token, passing");
        return Result.NEXT;
    }
    
    
    return xssInterceptor.intercept(request, response);
    
        
    
  }



}

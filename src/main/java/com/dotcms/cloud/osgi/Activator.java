package com.dotcms.cloud.osgi;


import java.util.List;

import org.osgi.framework.BundleContext;
import com.dotcms.cloud.strongdm.interceptor.StrongDMInterceptor;
import com.dotcms.cloud.strongdm.interceptor.StrongDMXSSPreventionWebInterceptor;

import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;

import com.dotmarketing.filters.LoginRequiredFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;


public class Activator extends GenericBundleActivator {

    static final String PLUGIN_NAME = "dotCMS SDM Proxy";

    final List<WebInterceptor> webInterceptors = List.of(new StrongDMInterceptor(),new StrongDMXSSPreventionWebInterceptor());

    final WebInterceptorDelegate delegate =
                    FilterWebInterceptorProvider.getInstance(Config.CONTEXT).getDelegate(LoginRequiredFilter.class);

    public void start(org.osgi.framework.BundleContext context)  {
        Logger.info(Activator.class.getName(), "");
        Logger.info(Activator.class.getName(), "Starting: " + PLUGIN_NAME);

        startStrongDMInterceptor();

        Logger.info(Activator.class.getName(), "Started: " + PLUGIN_NAME);
        Logger.info(Activator.class.getName(), "");

    }

    private void startStrongDMInterceptor() {
        // This prevents a new session from being created when a login occurs.
        Config.setProperty("PREVENT_SESSION_FIXATION_ON_LOGIN", false);

        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Adding : " + webIn.getClass().getName());
            delegate.addFirst(webIn);
        }
    }

    @Override
    public void stop(BundleContext context)  {
        Logger.info(Activator.class.getName(), "Stopping " + PLUGIN_NAME);
        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Removing the " + webIn.getClass().getName());
            delegate.remove(webIn.getName(), true);
        }




    }

}

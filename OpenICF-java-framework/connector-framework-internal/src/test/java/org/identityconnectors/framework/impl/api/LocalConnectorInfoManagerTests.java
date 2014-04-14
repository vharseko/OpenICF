/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License").  You may not use this file
 * except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://opensource.org/licenses/cddl1.php
 * See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at http://opensource.org/licenses/cddl1.php.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.identityconnectors.framework.impl.api;

import java.net.URL;
import java.util.List;

import org.identityconnectors.common.Version;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.api.ConnectorInfo;
import org.identityconnectors.framework.api.ConnectorInfoManager;
import org.identityconnectors.framework.api.ConnectorInfoManagerFactory;
import org.identityconnectors.framework.common.FrameworkUtil;
import org.identityconnectors.framework.common.FrameworkUtilTestHelpers;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.testng.Assert;
import org.testng.annotations.Test;


public class LocalConnectorInfoManagerTests extends ConnectorInfoManagerTestBase {

    /**
     * Setup logging for the {@link LocalConnectorInfoManagerTests}.
     */
    private static final Log logger = Log.getLog(LocalConnectorInfoManagerTests.class);

    /**
     * Tests that the framework refuses to load a bundle that requests a framework version newer than the one present.
     */
    @Test(priority = -1)
    public void testCheckVersion() throws Exception {
        // The test bundles require framework 1.0, so pretend the framework is older.
        FrameworkUtilTestHelpers.setFrameworkVersion(Version.parse("0.5"));
        try {
            ConnectorInfoManager manager = getConnectorInfoManager();
            try {
                //We should not get here. If we get here then display some diagnostic information.
                for (ConnectorInfo info : manager.getConnectorInfos()) {
                    logger.error("TEST FAIL: Found connector key: {0}", info.getConnectorKey());
                }
            } finally {
                Assert.fail("Require framework 1.0, so pretend the framework is 0.5 but found: " + FrameworkUtil
                        .getFrameworkVersion());
            }
        } catch (ConfigurationException e) {
            if (!e.getMessage().contains("unrecognized framework version")) {
                Assert.fail();
            }
        }
    }

    /**
     * To be overridden by subclasses to get different ConnectorInfoManagers
     *
     * @return
     * @throws Exception
     */
    @Override
    protected ConnectorInfoManager getConnectorInfoManager() throws Exception {
        List<URL> urls = getTestBundles();
        ConnectorInfoManagerFactory fact = ConnectorInfoManagerFactory.getInstance();
        ConnectorInfoManager manager = fact.getLocalManager(urls.toArray(new URL[0]));
        return manager;
    }

    @Override
    protected void shutdownConnnectorInfoManager() {
        ConnectorFacadeFactory.getInstance().dispose();
        ConnectorInfoManagerFactory.getInstance().clearLocalCache();
    }
}

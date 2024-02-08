/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for
 * the specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file
 * and include the License file at legal/CDDLv1.0.txt. If applicable, add the following
 * below the CDDL Header, with the fields enclosed by brackets [] replaced by your
 * own identifying information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2010-2016 ForgeRock AS.
 * Portions Copyrighted 2011 Viliam Repan (lazyman)
 */
package org.forgerock.openicf.csvfile;

import org.forgerock.openicf.csvfile.util.TestUtils;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class ComplexSyncOpTest {

    private CSVFileConnector connector;

    @BeforeMethod
    public void before() throws Exception {
        File file = new File("./src/test/resources/files/sync.csv.1300734815289");
        TestUtils.copyAndReplace(new File("./src/test/resources/files/sync.backup.csv.1300734815289"), file);

        CSVFileConfiguration config = new CSVFileConfiguration();
        config.setCsvFile(new File("./src/test/resources/files/sync.csv"));
        config.setHeaderUid("uid");
        config.setHeaderPassword("password");

        connector = new CSVFileConnector();
        connector.init(config);
    }

    @AfterMethod
    public void after() {
        connector.dispose();
        connector = null;
    }

    @Test
    public void syncTest() {
        final List<SyncDelta> deltas = new ArrayList<SyncDelta>();
        final AtomicReference<SyncToken> newToken = new AtomicReference<SyncToken>();
        SyncToken token = connector.getLatestSyncToken(ObjectClass.ACCOUNT);
        for (int i = 0; i < 10; i++) {
            connector.sync(ObjectClass.ACCOUNT, token, new SyncTokenResultsHandler() {
                public boolean handle(SyncDelta sd) {
                    deltas.add(sd);
                    return true;
                }

                public void handleResult(SyncToken syncToken) {
                    newToken.set(syncToken);
                }
            }, null);
            if (!deltas.isEmpty()) {
                token = deltas.get(0).getToken();
            }
            deltas.clear();
        }
    }

    private Map<String, SyncDelta> createSyncDeltaTestMap(SyncToken token) {
        Map<String, SyncDelta> map = new HashMap<String, SyncDelta>();

        SyncDeltaBuilder builder = new SyncDeltaBuilder();
        builder.setDeltaType(SyncDeltaType.DELETE);
        builder.setToken(token);
        builder.setUid(new Uid("vilo"));
        builder.setObject(null);
        map.put("vilo", builder.build());

        builder = new SyncDeltaBuilder();
        builder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
        builder.setToken(token);
        builder.setUid(new Uid("miso"));
        ConnectorObjectBuilder cBuilder = new ConnectorObjectBuilder();
        cBuilder.setName("miso");
        cBuilder.setUid("miso");
        cBuilder.setObjectClass(ObjectClass.ACCOUNT);
        cBuilder.addAttribute("firstName", "michal");
        cBuilder.addAttribute("lastName", "LastnameChange");
        cBuilder.addAttribute("__PASSWORD__", new GuardedString("Z29vZA==".toCharArray()));
        builder.setObject(cBuilder.build());
        map.put("miso", builder.build());

        builder = new SyncDeltaBuilder();
        builder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
        builder.setToken(token);
        builder.setUid(new Uid("fanfi"));
        cBuilder = new ConnectorObjectBuilder();
        cBuilder.setName("fanfi");
        cBuilder.setUid("fanfi");
        cBuilder.setObjectClass(ObjectClass.ACCOUNT);
        cBuilder.addAttribute("firstName", "igor");
        cBuilder.addAttribute("lastName", "farinicNewRecord");
        cBuilder.addAttribute("__PASSWORD__", new GuardedString("Z29vZA==".toCharArray()));
        builder.setObject(cBuilder.build());
        map.put("fanfi", builder.build());

        return map;
    }
}

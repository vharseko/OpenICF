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
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.testng.annotations.Test;

public class CSVFileConfigurationTest {

    @Test
    public void validateGoodConfiguration() throws Exception {
        CSVFileConfiguration config = new CSVFileConfiguration();
        config.setCsvFile(TestUtils.getTestFile("config.csv"));
        config.setHeaderPassword("password");
        config.setHeaderUid("uid");

        config.validate();
    }

    @Test(expectedExceptions = ConfigurationException.class)
    public void validateFilePath() {
        CSVFileConfiguration config = new CSVFileConfiguration();
        config.setHeaderPassword("password");
        config.setHeaderUid("uid");

        config.validate();
    }
}

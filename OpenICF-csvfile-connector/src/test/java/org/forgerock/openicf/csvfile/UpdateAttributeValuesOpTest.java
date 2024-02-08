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

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;

import static org.testng.Assert.*;

import org.forgerock.openicf.csvfile.util.TestUtils;

import java.util.Set;

import java.io.File;
import java.util.HashSet;

import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.testng.annotations.Test;

/**
 * @author Viliam Repan (lazyman)
 */
public class UpdateAttributeValuesOpTest {

    private CSVFileConnector connector;

    @BeforeMethod
    public void before() throws Exception {
        File file = TestUtils.getTestFile("update-attribute.csv");
        File backup = TestUtils.getTestFile("update-attribute-backup.csv");
        TestUtils.copyAndReplace(backup, file);

        CSVFileConfiguration config = new CSVFileConfiguration();
        config.setCsvFile(TestUtils.getTestFile("update-attribute.csv"));
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

    @AfterClass
    public static void afterClass() throws Exception {
        File file = TestUtils.getTestFile("update-attribute.csv");
        file.delete();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullObjectClass() {
        connector.addAttributeValues(null, new Uid("vilo"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void badObjectClass() {
        connector.addAttributeValues(ObjectClass.GROUP, new Uid("vilo"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullUid() {
        connector.addAttributeValues(ObjectClass.ACCOUNT, null, new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = UnknownUidException.class)
    public void notExistingUid() {
        connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("unknown"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullAttributeSet() {
        connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), null, null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullObjectClassRemove() {
        connector.removeAttributeValues(null, new Uid("vilo"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void badObjectClassRemove() {
        connector.removeAttributeValues(ObjectClass.GROUP, new Uid("vilo"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullUidRemove() {
        connector.removeAttributeValues(ObjectClass.ACCOUNT, null, new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = UnknownUidException.class)
    public void notExistingUidRemove() {
        connector.removeAttributeValues(ObjectClass.ACCOUNT, new Uid("unknown"), new HashSet<Attribute>(), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void nullAttributeSetRemove() {
        connector.removeAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), null, null);
    }

    @Test
    public void updateNonExistingAttributeAdd() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("nonExisting", "repan"));
        Uid uid = connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), attributes, null);
        assertNotNull(uid);
        assertEquals("vilo", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-non-existing.csv"));
        assertNotNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void updateAttributeAddAdd() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("lastName", "repantest"));
        Uid uid = connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), attributes, null);
        assertNotNull(uid);
        assertEquals("vilo", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-add.csv"));
        assertNotNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void updateNonExistingAttributeRemove() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("nonExisting", "repan"));
        Uid uid = connector.removeAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), attributes, null);
        assertNotNull(uid);
        assertEquals("vilo", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-non-existing.csv"));
        assertNotNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void updateAttributeDeleteRemove() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("lastName", "repan2"));
        Uid uid = connector.removeAttributeValues(ObjectClass.ACCOUNT, new Uid("miso"), attributes, null);
        assertNotNull(uid);
        assertEquals("miso", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-remove.csv"));
        assertNotNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void updateMultivalueAttributeAdd() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("lastName", "repan", "repan2", "repan3"));
        Uid uid = connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), attributes, null);
        assertNotNull(uid);
        assertEquals("vilo", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-add-multi.csv"));
        assertNotNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void updateMultivalueAttributeRemove() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(AttributeBuilder.build("lastName", "repan", "repan2", "repan3"));
        Uid uid = connector.removeAttributeValues(ObjectClass.ACCOUNT, new Uid("miso"), attributes, null);
        assertNotNull(uid);
        assertEquals("miso", uid.getUidValue());

        String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                TestUtils.getTestFile("update-attribute-result-remove-multi.csv"));
        assertNull(result, "File updated incorrectly: " + result);
    }

    @Test
    public void addNameWhenUniqueEqualsNamingAttribute() throws Exception {
        Set<Attribute> attributes = new HashSet<Attribute>();

        attributes.add(new Name("troll"));
        try {
            connector.addAttributeValues(ObjectClass.ACCOUNT, new Uid("vilo"), attributes, null);
        } finally {
            String result = TestUtils.compareFiles(TestUtils.getTestFile("update-attribute.csv"),
                    TestUtils.getTestFile("update-attribute-backup.csv"));
            assertNotNull(result, "File updated incorrectly: " + result);
        }
    }
}

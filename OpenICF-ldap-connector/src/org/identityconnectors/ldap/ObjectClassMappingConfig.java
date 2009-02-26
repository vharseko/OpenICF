/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2007-2008 Sun Microsystems, Inc. All rights reserved.     
 * 
 * The contents of this file are subject to the terms of the Common Development 
 * and Distribution License("CDDL") (the "License").  You may not use this file 
 * except in compliance with the License.
 * 
 * You can obtain a copy of the License at 
 * http://IdentityConnectors.dev.java.net/legal/license.txt
 * See the License for the specific language governing permissions and limitations 
 * under the License. 
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields 
 * enclosed by brackets [] replaced by your own identifying information: 
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.identityconnectors.ldap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ObjectClass;

/**
 * Describes how to map a framework object class to an LDAP object class.
 */
public class ObjectClassMappingConfig {

    private final ObjectClass objectClass;
    private final String ldapClass;

    private boolean container;

    private String uidAttribute; // Maps to UID.
    private String nameAttribute; // Maps to Name.

    private final Map<String, AttributeMappingConfig> attrName2Mapping = new HashMap<String, AttributeMappingConfig>();
    private final List<AttributeMappingConfig> attributeMappings = new ArrayList<AttributeMappingConfig>();

    private final Map<String, AttributeMappingConfig> attrName2DNMapping = new HashMap<String, AttributeMappingConfig>();
    private final List<AttributeMappingConfig> dnMappings = new ArrayList<AttributeMappingConfig>();

    private final Set<AttributeInfo> operationalAttributes = new HashSet<AttributeInfo>();

    public ObjectClassMappingConfig(ObjectClass objectClass, String ldapClass) {
        assert objectClass != null;
        assert ldapClass != null;
        this.objectClass = objectClass;
        this.ldapClass = ldapClass;
    }

    public ObjectClass getObjectClass() {
        return objectClass;
    }

    public String getLdapClass() {
        return ldapClass;
    }

    public boolean isContainer() {
        return container;
    }

    public void setContainer(boolean container) {
        this.container = container;
    }

    public String getUidAttribute() {
        return uidAttribute;
    }

    public void setUidAttribute(String uidAttribute) {
        this.uidAttribute = uidAttribute;
    }

    public String getNameAttribute() {
        return nameAttribute;
    }

    public void setNameAttribute(String nameAttribute) {
        this.nameAttribute = nameAttribute;
    }

    public List<AttributeMappingConfig> getAttributeMappings() {
        return CollectionUtil.newReadOnlyList(attributeMappings);
    }

    public AttributeMappingConfig getAttributeMapping(String attrName) {
        return attrName2Mapping.get(attrName);
    }

    public void addAttributeMapping(String attrName, String ldapAttrName) {
        assert attrName != null;
        assert ldapAttrName != null;
        if (attrName2Mapping.containsKey(attrName)) {
            throw new IllegalStateException("Attribute " + attrName + "is already mapped");
        }
        AttributeMappingConfig mapping = new AttributeMappingConfig(attrName, ldapAttrName);
        attrName2Mapping.put(attrName, mapping);
        attributeMappings.add(mapping);
    }

    public List<AttributeMappingConfig> getDNMappings() {
        return CollectionUtil.newReadOnlyList(dnMappings);
    }

    public AttributeMappingConfig getDNMapping(String dnValuedAttr) {
        return attrName2DNMapping.get(dnValuedAttr);
    }

    public void addDNMapping(String dnValuedAttr, String mapToAttr) {
        assert dnValuedAttr != null;
        assert mapToAttr != null;
        if (attrName2DNMapping.containsKey(dnValuedAttr)) {
            throw new IllegalStateException("DN value of attribute " + dnValuedAttr + "is already mapped");
        }
        AttributeMappingConfig mapping = new AttributeMappingConfig(dnValuedAttr, mapToAttr);
        attrName2DNMapping.put(dnValuedAttr, mapping);
        dnMappings.add(mapping);
    }

    public void addOperationalAttributes(AttributeInfo... attributeInfos) {
        operationalAttributes.addAll(Arrays.asList(attributeInfos));
    }

    public Set<AttributeInfo> getOperationalAttributes() {
        return CollectionUtil.newReadOnlySet(operationalAttributes);
    }

    public int hashCode() {
        return objectClass.hashCode();
    }

    public boolean equals(Object o) {
        if (o instanceof ObjectClassMappingConfig) {
            ObjectClassMappingConfig that = (ObjectClassMappingConfig)o;
            if (!objectClass.equals(that.objectClass)) {
                return false;
            }
            if ((ldapClass == null) ? (that.ldapClass != null) : !ldapClass.equals(that.ldapClass)) {
                return false;
            }
            if ((uidAttribute == null) ? (that.uidAttribute != null) : !uidAttribute.equals(that.uidAttribute)) {
                return false;
            }
            if ((nameAttribute == null) ? (that.nameAttribute != null) : !nameAttribute.equals(that.nameAttribute)) {
                return false;
            }
            if (!attributeMappings.equals(that.attributeMappings)) {
                return false;
            }
            if (!dnMappings.equals(that.dnMappings)) {
                return false;
            }
            if (!operationalAttributes.equals(that.operationalAttributes)) {
                return false;
            }
            return true;
        }
        return false;
    }
}

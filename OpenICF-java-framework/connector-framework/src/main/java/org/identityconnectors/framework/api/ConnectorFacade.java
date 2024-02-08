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
 * Portions Copyrighted 2010-2015 ForgeRock AS.
 */
package org.identityconnectors.framework.api;

import java.util.Set;

import org.identityconnectors.framework.api.operations.APIOperation;
import org.identityconnectors.framework.api.operations.AuthenticationApiOp;
import org.identityconnectors.framework.api.operations.BatchApiOp;
import org.identityconnectors.framework.api.operations.ConnectorEventSubscriptionApiOp;
import org.identityconnectors.framework.api.operations.CreateApiOp;
import org.identityconnectors.framework.api.operations.DeleteApiOp;
import org.identityconnectors.framework.api.operations.GetApiOp;
import org.identityconnectors.framework.api.operations.ResolveUsernameApiOp;
import org.identityconnectors.framework.api.operations.SchemaApiOp;
import org.identityconnectors.framework.api.operations.ScriptOnConnectorApiOp;
import org.identityconnectors.framework.api.operations.ScriptOnResourceApiOp;
import org.identityconnectors.framework.api.operations.SearchApiOp;
import org.identityconnectors.framework.api.operations.SyncApiOp;
import org.identityconnectors.framework.api.operations.SyncEventSubscriptionApiOp;
import org.identityconnectors.framework.api.operations.TestApiOp;
import org.identityconnectors.framework.api.operations.UpdateApiOp;
import org.identityconnectors.framework.api.operations.ValidateApiOp;

/**
 * Main interface through which an application invokes Connector operations.
 * Represents at the API level a specific instance of a Connector that has been
 * configured in a specific way.
 *
 * @see ConnectorFacadeFactory
 *
 * @author Will Droste
 * @since 1.0
 */
public interface ConnectorFacade extends BatchApiOp, CreateApiOp, DeleteApiOp, SearchApiOp, UpdateApiOp,
        SchemaApiOp, AuthenticationApiOp, ResolveUsernameApiOp, GetApiOp, ValidateApiOp, TestApiOp,
        ScriptOnConnectorApiOp, ScriptOnResourceApiOp, SyncApiOp, ConnectorEventSubscriptionApiOp,
        SyncEventSubscriptionApiOp {

    /**
     * Gets the unique generated identifier of this ConnectorFacade.
     *
     * It's not guarantied that the equivalent configuration will generate the
     * same configuration key. Always use the generated value and maintain it in
     * the external application.
     *
     * @return identifier of this ConnectorFacade instance.
     * @since 1.4
     */
    public String getConnectorFacadeKey();

    /**
     * Get the set of operations that this {@link ConnectorFacade} will support.
     */
    Set<Class<? extends APIOperation>> getSupportedOperations();

    /**
     * Get an instance of an operation that this facade supports.
     */
    APIOperation getOperation(Class<? extends APIOperation> clazz);

}

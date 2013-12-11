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
package org.identityconnectors.framework.spi;

import org.identityconnectors.framework.common.objects.ConnectorMessages;

/**
 * Convenient base-class for Configuration objects to extend.
 */
public abstract class AbstractConfiguration implements Configuration {

    private ConnectorMessages connectorMessages;

    @Override
    public final ConnectorMessages getConnectorMessages() {
        return connectorMessages;
    }

    @Override
    public final void setConnectorMessages(ConnectorMessages messages) {
        connectorMessages = messages;
    }

    @Override
    public abstract void validate();

}

/*
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * 
 * U.S. Government Rights - Commercial software. Government users 
 * are subject to the Sun Microsystems, Inc. standard license agreement
 * and applicable provisions of the FAR and its supplements.
 * 
 * Use is subject to license terms.
 * 
 * This distribution may include materials developed by third parties.
 * Sun, Sun Microsystems, the Sun logo, Java and Project Identity 
 * Connectors are trademarks or registered trademarks of Sun 
 * Microsystems, Inc. or its subsidiaries in the U.S. and other
 * countries.
 * 
 * UNIX is a registered trademark in the U.S. and other countries,
 * exclusively licensed through X/Open Company, Ltd. 
 * 
 * -----------
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved. 
 * 
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License(CDDL) (the License).  You may not use this file
 * except in  compliance with the License. 
 * 
 * You can obtain a copy of the License at
 * http://identityconnectors.dev.java.net/CDDLv1.0.html
 * See the License for the specific language governing permissions and 
 * limitations under the License.  
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each
 * file and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields 
 * enclosed by brackets [] replaced by your own identifying information: 
 * "Portions Copyrighted [year] [name of copyright owner]"
 * -----------
 */
package org.identityconnectors.dbcommon;


import java.util.ArrayList;
import java.util.List;

import org.identityconnectors.common.CollectionUtil;


/**
 * The update set builder create the database update statement.
 * <p>The main functionality is create set part of update statement from Attribute set</p>
 *
 * @version $Revision 1.0$
 * @since 1.0
 */
public class UpdateSetBuilder {
    private List<Object> params = new ArrayList<Object>();
    private StringBuilder set = new StringBuilder();
    
    /**
     * @return the params
     */
    public List<Object> getParams() {
        return CollectionUtil.newReadOnlyList(params);
    }
    
    /**
     * Add column name and value pair
     * The names are quoted using the {@link #columnQuote} value
     * 
     * @param name name
     * @param value value
     * @param index 
     * @return self
     */
    public UpdateSetBuilder addBind(String name, Object value) {
        return addBind(name,"?", value);
    }

    /**
     * Add column name and expression value pair
     * The names are quoted using the {@link #columnQuote} value
     * @param name of the column
     * @param expression the Comparable expression
     * @param param the value to bind
     * @return self
     */
    public UpdateSetBuilder addBind(String name, String expression, Object param) {
        if(set.length()>0) {
            set.append(" , ");
        }
        set.append(name).append(" = ").append(expression);
        params.add(param);
        return this;
    }    
    
    /**
     * Build the set SQL 
     * @return The update set clause 
     */
    public String getSQL() {
        return set.toString();
    }
}

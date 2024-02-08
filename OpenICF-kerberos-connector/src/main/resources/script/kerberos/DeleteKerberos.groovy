/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016 ForgeRock AS.
 */

package openicf.kerberos.scripts

import org.forgerock.openicf.connectors.ssh.CommandLineBuilder
import org.forgerock.openicf.connectors.kerberos.KerberosConfiguration
import org.forgerock.openicf.misc.scriptedcommon.OperationType
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.exceptions.UnknownUidException
import org.identityconnectors.framework.common.objects.ObjectClass

// SSH Connector specific bindings

//setTimeout <value> : defines global timeout (ms) on expect/send actions
//setTimeoutSec <value> : defines global timeout (sec) on expect/send actions
//send <command> : sends a String or GString of commands
//sendln <command> : sends a String or GString of commands + \r
//sudo <command>: mock the sudo command, using sudo cmd, sudo prompt and user password defined in the configuration
//sendControlC: sends a Ctrl-C interrupt sequence
//sendControlD: sends a Ctrl-D sequence
//promptReady <prompt> <retry>: force the connection to be in prompt ready mode. Returns true if success, false if failed
//expect <pattern>: expect a match pattern from the Read buffer
//expect <pattern>, <Closure>: expect a match pattern from the Read buffer and associate a simple Closure to be performed on pattern match.
//expect <List of matches>: expect a list of different match pattern
//match: defines a global match pattern and a Closure within a call to expect<List>
//regexp: defines a Perl5 style regular expression and a Closure within a call to expect<List>
//timeout: defines a local timeout and a Closure within a call to expect
// The following constants: TIMEOUT_FOREVER, TIMEOUT_NEVER, TIMEOUT_EXPIRED, EOF_FOUND

def operation = operation as OperationType
def configuration = configuration as KerberosConfiguration
def log = log as Log
def objectClass = objectClass as ObjectClass
def uid = uid.getUidValue() as String
def kadmin = configuration.getPropertyBag().get("kadmin") as ConfigObject

log.info("Entering {0} script", operation);
assert operation == OperationType.DELETE, 'Operation must be a DELETE'
assert objectClass == ObjectClass.ACCOUNT, 'ObjectClass must be __ACCOUNT__'

// The prompt is the first thing we should expect from the connection
if (!promptReady(2)) {
    throw new ConnectorException("Can't get the session prompt")
}
log.info("Prompt ready...")

// Example:
// kadmin -p openidm/admin -q 'delprinc -force test1'
// Authenticating as principal openidm/admin with password.
// Password for openidm/admin@REALM: ******
// Principal "test1@REALM" deleted.
// Make sure that you have removed this principal from all ACLs before reusing.
// user@host:~$

def command = new CommandLineBuilder(kadmin.cmd).p(kadmin.user).q("delprinc -force $uid").build()
log.info("Command is {0}", command)

if (!sudo(command)) {
    throw new ConnectorException("Failed to run sudo $command")
}
if (kadmin.cmd.endsWith("kadmin")) {
    expect "\nPassword for $kadmin.user", { sendln kadmin.password }
}
expect(
        [
                match("Principal \"$uid\" deleted.") {
                    log.info("Principal {0} deleted", uid)
                },
                match("Principal does not exist while deleting principal \"$uid\"") {
                    log.info("Principal {0} does not exist", uid)
                    throw new UnknownUidException(uid)
                },
                timeout(500) {
                    throw new ConnectorException("Delete of $uid failed")
                }
        ]
)

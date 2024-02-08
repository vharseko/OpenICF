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
import org.forgerock.openicf.connectors.ssh.SSHConnection
import org.forgerock.openicf.misc.scriptedcommon.OperationType
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions

import static org.identityconnectors.common.security.SecurityUtil.decrypt

// SSH Connector specific bindings

//setTimeout <value> : defines global timeout (ms) on expect/send actions
//setTimeoutSec <value> : defines global timeout (sec) on expect/send actions
//send <command> : sends a String or GString of commands
//sendln <command> : sends a String or GString of commands + \r
//sendControlC: sends a Ctrl-C interrupt sequence
//sendControlD: sends a Ctrl-D sequence
//sudo <command>: mock the sudo command, using sudo cmd, sudo prompt and user password defined in the configuration
//promptReady <prompt> <retry>: force the connection to be in prompt ready mode. Returns true if success, false if failed
//expect <pattern>: expect a match pattern from the Read buffer
//expect <pattern>, <Closure>: expect a match pattern from the Read buffer and associate a simple Closure to be performed on pattern match.
//expect <List of matches>: expect a list of different match pattern
//match: defines a global match pattern and a Closure within a call to expect<List>
//regexp: defines a Perl5 style regular expression and a Closure within a call to expect<List>
//timeout: defines a local timeout and a Closure within a call to expect
// The following constants: TIMEOUT_FOREVER, TIMEOUT_NEVER, TIMEOUT_EXPIRED, EOF_FOUND

def operation = operation as OperationType
def attributes = attributes as Set<Attribute>
def configuration = configuration as KerberosConfiguration
def connection = connection as SSHConnection
def id = id as String
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def attrs = new AttributesAccessor(attributes)
def kadmin = configuration.getPropertyBag().get("kadmin") as ConfigObject

log.info("Entering {0} script", operation);
assert operation == OperationType.CREATE, 'Operation must be a CREATE'
assert objectClass == ObjectClass.ACCOUNT, 'ObjectClass must be __ACCOUNT__'

// The prompt is the first thing we should expect from the connection
if (!promptReady(2)) {
    throw new ConnectorException("Can't get the session prompt")
}
log.info("Prompt ready...")

/*
Example:
kadmin -p openidm/admin -q 'addprinc -policy user -expire 2016-10-01 -maxlife 2016-10-01 -pwexpire 2016-10-01 -maxrenewlife 2016-10-01 foo@BAR'
Authenticating as principal openidm/admin with password.
Password for openidm/admin@COOPSRC:
Enter password for principal "foo@BAR":
Re-enter password for principal "foo@BAR":
Principal "foo@BAR" created.
*/

// Check if realm has been set... append the default one if not
if (!id.contains('@')) {
    id += "@" + kadmin.default_realm
}

def query = new CommandLineBuilder("addprinc")
        .expire(attrs.findString("expirationDate"))
        .maxlife(attrs.findString("maximumTicketLife"))
        .maxrenewlife(attrs.findString("maximumRenewableLife"))
        .pwexpire(attrs.findString("passwordExpiration"))
        .policy(attrs.findString("policy"))
        .append(id)
        .build()

def command = new CommandLineBuilder(kadmin.cmd).p(kadmin.user).q(query).build()
log.info("Command is {0}", command)

if (!sudo(command)) {
    throw new ConnectorException("Failed to run sudo $command")
}

if (kadmin.cmd.endsWith("kadmin")) {
    expect "\nPassword for $kadmin.user", { sendln kadmin.password }
}
expect "\nEnter password for principal \"$id\":", { sendln decrypt(attrs.getPassword()) }
expect "\nRe-enter password for principal \"$id\":", { sendln decrypt(attrs.getPassword()) }
expect(
        [
                match("Principal \"$id\" created.") {
                    log.info("Principal {0} created", id)
                },
                match("Principal or policy already exists while creating \"$id\"") {
                    log.info("Principal {0} already exists!", id)
                    throw new AlreadyExistsException(id)
                },
                timeout(500) {
                    throw new ConnectorException("Create of $id failed")
                }
        ]
)

return id
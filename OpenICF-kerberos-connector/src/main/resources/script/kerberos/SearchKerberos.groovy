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
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.Name
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.Uid
import org.identityconnectors.framework.common.objects.filter.AndFilter
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter
import org.identityconnectors.framework.common.objects.filter.Filter
import org.identityconnectors.framework.common.objects.filter.EqualsFilter
import org.identityconnectors.framework.common.objects.filter.FilterVisitor
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter
import org.identityconnectors.framework.common.objects.filter.LessThanFilter
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter
import org.identityconnectors.framework.common.objects.filter.NotFilter
import org.identityconnectors.framework.common.objects.filter.OrFilter
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter
import org.identityconnectors.framework.common.objects.filter.ContainsFilter
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter


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
def configuration = configuration as KerberosConfiguration
def connection = connection as SSHConnection
def filter = filter as Filter
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def handler = handler as Closure
def attributesToGet = options.getAttributesToGet() as String[]
def prompt = configuration.getPrompt()
def kadmin = configuration.getPropertyBag().get("kadmin") as ConfigObject

def getPrincipalDetails = { princ ->
    def command = new CommandLineBuilder(kadmin.cmd).p(kadmin.user).q("getprinc $princ").build()

    if (!sudo(command)) {
        throw new ConnectorException("Failed to run sudo $command")
    }
    expect "Authenticating as principal $kadmin.user with password."
    if (kadmin.cmd.endsWith("kadmin")) {
        expect "\nPassword for $kadmin.user", { sendln kadmin.password }
    }
    expect prompt, {
        if (it.getMatchedWhere() > 0) {
            def list = it.getBuffer().substring(0, it.getMatchedWhere()).trim().split("\r\n")
            def attrs = [:]
            list.each() { attr ->
                def name, value
                (name, value) = attr.split(":", 2)
                if (value != null && value != '') {
                    attrs[name] = value.trim()
                }
            }
            def notExist = attrs["get_principal"] as String
            if (!(notExist != null && notExist.startsWith("Principal does not exist"))) {
                handler {
                    uid attrs.Principal
                    id attrs.Principal
                    attribute "policy", attrs['Policy']
                    attribute "expirationDate", attrs['Expiration date']
                    attribute "lastPasswordChange", attrs['Last password change']
                    attribute "passwordExpiration", attrs['Password expiration date']
                    attribute "maximumTicketLife", attrs['Maximum ticket life']
                    attribute "maximumRenewableLife", attrs['Maximum renewable life']
                    attribute "lastModified", attrs['Last modified']
                    attribute "lastSuccessfulAuthentication", attrs['Last successful authentication']
                    attribute "lastFailedAuthentication", attrs['Last failed authentication']
                    attribute "failedPasswordAttempts", attrs['Failed password attempts']
                }
            }
        }
    }
}

log.info("Entering {0} script", operation);
assert operation == OperationType.SEARCH, 'Operation must be a CREATE'
assert objectClass == ObjectClass.ACCOUNT, 'ObjectClass must be __ACCOUNT__'

// Remove __UID__ and __NAME__ from the attributes to get
if (attributesToGet != null) {
    attributesToGet = attributesToGet - [Uid.NAME] - [Name.NAME] as String[]
}

// The prompt is the first thing we should expect from the connection
if (!promptReady(2)) {
    throw new ConnectorException("Can't get the session prompt")
}
log.info("Prompt ready...")

if (filter == null ||
        filter instanceof StartsWithFilter ||
        filter instanceof EndsWithFilter ||
        filter instanceof ContainsFilter) {
    def query = ""
    if (filter != null) {
        query = filter.accept(KerberosFilterVisistor.INSTANCE, null)
    }
    def command = new CommandLineBuilder(kadmin.cmd).p(kadmin.user).q("listprincs $query").build()
    log.info("Command is {0}", command)

    if (!sudo(command)) {
        throw new ConnectorException("Failed to run sudo $command")
    }
    expect "Authenticating as principal $kadmin.user with password."

    // using kadmin.local won't ask for extra authentication. kadmin will.
    if (kadmin.cmd.endsWith("kadmin")) {
        expect "\nPassword for $kadmin.user", { sendln kadmin.password }
    }
    expect prompt, {
        if (it.getMatchedWhere() > 0) {
            def list = it.getBuffer().substring(0, it.getMatchedWhere()).trim().split("\r\n")
            list.each() { princ ->
                if (attributesToGet != null && attributesToGet.length > 0) {
                    getPrincipalDetails(princ)
                } else {
                    handler {
                        uid princ
                        id princ
                    }
                }
            }
        }
    }
} else if (filter instanceof EqualsFilter) {
    //This is a get
    def principal = filter.accept(KerberosFilterVisistor.INSTANCE, null)
    log.info("Getting Principal {0}", principal)
    getPrincipalDetails(principal)
} else {
    throw new ConnectorException("Bad filter")
}

// Put the connection in prompt ready mode for next usage
sendln ""

/**
 *
 * A KerberosFilterVisistor converts a {@link org.identityconnectors.framework.common.objects.filter.Filter} to
 * input search criteria(s) for the kadmin Kerberos admin command line (list_principals)
 */
public class KerberosFilterVisistor implements FilterVisitor<String, Void> {

    public static final KerberosFilterVisistor INSTANCE = new KerberosFilterVisistor();

    /**
     * Only these attributes can be used as a search criteria
     */
    private static final ArrayList<String> ALLOWED = new ArrayList<String>(Arrays.asList(
            "PRINCIPAL",
            "__NAME__",
            "__UID__"
    ));

    @Override
    public String visitContainsFilter(Void p, ContainsFilter filter) {
        String param = filter.getName().toUpperCase();
        if (!ALLOWED.contains(param)) {
            throw new UnsupportedOperationException(param + "is not supported as a search criteria");
        }
        return "*" + filter.getValue() + "*";
    }

    @Override
    public String visitStartsWithFilter(Void p, StartsWithFilter filter) {
        String param = filter.getName().toUpperCase();
        if (!ALLOWED.contains(param)) {
            throw new UnsupportedOperationException(param + "is not supported as a search criteria");
        }
        return filter.getValue() + "*";
    }

    @Override
    public String visitEndsWithFilter(Void p, EndsWithFilter filter) {
        String param = filter.getName().toUpperCase();
        if (!ALLOWED.contains(param)) {
            throw new UnsupportedOperationException(param + "is not supported as a search criteria");
        }
        return "*" + filter.getValue();
    }

    @Override
    public String visitEqualsFilter(Void p, EqualsFilter filter) {
        String param = filter.getName().toUpperCase();
        if (!ALLOWED.contains(param)) {
            throw new UnsupportedOperationException(param + "is not supported as a search criteria");
        }
        return filter.getAttribute().getValue().get(0).toString();
    }

    @Override
    public String visitContainsAllValuesFilter(Void p, ContainsAllValuesFilter filter) {
        throw new UnsupportedOperationException("ContainsAllValuesFilter is not supported.");
    }

    @Override
    public String visitExtendedFilter(Void p, Filter filter) {
        throw new UnsupportedOperationException("Filter type is not supported: " + filter.getClass());
    }

    @Override
    public String visitGreaterThanFilter(Void p, GreaterThanFilter filter) {
        throw new UnsupportedOperationException("GreaterThanFilter is not supported.");
    }

    @Override
    public String visitGreaterThanOrEqualFilter(Void p, GreaterThanOrEqualFilter filter) {
        throw new UnsupportedOperationException("GreaterThanOrEqualFilter is not supported.");
    }

    @Override
    public String visitLessThanFilter(Void p, LessThanFilter filter) {
        throw new UnsupportedOperationException("LessThanFilter is not supported.");
    }

    @Override
    public String visitLessThanOrEqualFilter(Void p, LessThanOrEqualFilter filter) {
        throw new UnsupportedOperationException("LessThanOrEqualFilter is not supported yet.");
    }

    @Override
    public String visitNotFilter(Void p, NotFilter filter) {
        throw new UnsupportedOperationException("NotFilter is not supported yet.");
    }

    @Override
    public String visitOrFilter(Void p, OrFilter filter) {
        throw new UnsupportedOperationException("OrFilter is not supported yet.");
    }

    @Override
    public String visitAndFilter(Void p, AndFilter filter) {
        throw new UnsupportedOperationException("AndFilter is not supported.");
    }
}
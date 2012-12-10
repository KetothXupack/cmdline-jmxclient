/*
 * Client
 *
 * $Id$
 *
 * Created on Nov 12, 2004
 *
 * Copyright (C) 2004 Internet Archive.
 *
 * This file is part of the Heritrix web crawler (crawler.archive.org).
 *
 * Heritrix is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * any later version.
 *
 * Heritrix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser Public License for more details.
 *
 * You should have received a copy of the GNU Lesser Public License
 * along with Heritrix; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.archive.jmx;

import javax.annotation.Nullable;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.MBeanAttributeInfo;
import javax.management.MBeanFeatureInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
import javax.management.MBeanParameterInfo;
import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularData;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.text.FieldPosition;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * A Simple Command-Line JMX Client.
 * Tested against the JDK 1.5.0 JMX Agent.
 * See <a href="http://java.sun.com/j2se/1.5.0/docs/guide/management/agent.html">Monitoring
 * and Management Using JMX</a>.
 * <p>Can supply credentials and do primitive string representation of tabular
 * and composite openmbeans.
 *
 * @author stack
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());

    /** Usage string. */
    private static final String USAGE = "Usage: java -jar" +
                                        " cmdline-jmxclient.jar USER:PASS HOST:PORT [BEAN] [COMMAND]\n" +
                                        "Options:\n" +
                                        " USER:PASS Username and password. Required. If none, pass '-'.\n" +
                                        "           E.g. 'controlRole:secret'\n" +
                                        " HOST:PORT Hostname and port to connect to. Required." +
                                        " E.g. localhost:8081.\n" +
                                        "           Lists registered beans if only USER:PASS and this" +
                                        " argument.\n" +
                                        " BEAN      Optional target bean name. If present we list" +
                                        " available operations\n" +
                                        "           and attributes.\n" +
                                        " COMMAND   Optional operation to run or attribute to fetch. If" +
                                        " none supplied,\n" +
                                        "           all operations and attributes are listed. Attributes" +
                                        " begin with a\n" +
                                        "           capital letter: e.g. 'Status' or 'Started'." +
                                        " Operations do not.\n" +
                                        "           Operations can take arguments by adding an '=' " +
                                        "followed by\n" +
                                        "           comma-delimited params. Pass multiple " +
                                        "attributes/operations to run\n" +
                                        "           more than one per invocation. Use commands 'create' and " +
                                        "'destroy'\n" +
                                        "           to instantiate and unregister beans ('create' takes name " +
                                        "of class).\n" +
                                        "           Pass 'Attributes' to get listing of all attributes and " +
                                        "and their\n" +
                                        "           values.\n" +
                                        "Requirements:\n" +
                                        " JDK1.5.0. If connecting to a SUN 1.5.0 JDK JMX Agent, remote side" +
                                        " must be\n" +
                                        " started with system properties such as the following:\n" +
                                        "     -Dcom.sun.management.jmxremote.port=PORT\n" +
                                        "     -Dcom.sun.management.jmxremote.authenticate=false\n" +
                                        "     -Dcom.sun.management.jmxremote.ssl=false\n" +
                                        " The above will start the remote server with no password. See\n" +
                                        " http://java.sun.com/j2se/1.5.0/docs/guide/management/agent.html" +
                                        " for more on\n" +
                                        " 'Monitoring and Management via JMX'.\n" +
                                        "Client Use Examples:\n" +
                                        " To list MBeans on a non-password protected remote agent:\n" +
                                        "     % java -jar cmdline-jmxclient-X.X.jar - localhost:8081 \\\n" +
                                        "         org.archive.crawler:name=Heritrix,type=Service\n" +
                                        " To list attributes and attributes of the Heritrix MBean:\n" +
                                        "     % java -jar cmdline-jmxclient-X.X.jar - localhost:8081 \\\n" +
                                        "         org.archive.crawler:name=Heritrix,type=Service \\\n" +
                                        "         schedule=http://www.archive.org\n" +
                                        " To set set logging level to FINE on a password protected JVM:\n" +
                                        "     % java -jar cmdline-jmxclient-X.X.jar controlRole:secret" +
                                        " localhost:8081 \\\n" +
                                        "         java.util.logging:type=Logging \\\n" +
                                        "         setLoggerLevel=org.archive.crawler.Heritrix,FINE";

    /**
     * Pattern that matches a command name followed by
     * an optional equals and optional comma-delimited list
     * of arguments.
     */
    protected static final Pattern CMD_LINE_ARGS_PATTERN =
            Pattern.compile("^([^=]+)(?:(?:\\=)(.+))?$");

    private static final String CREATE_CMD_PREFIX = "create=";
    private static final Pattern COMMA = Pattern.compile(",");

    public static void main(final String[] args) throws Exception {
        final Client client = new Client();
        // Set the logger to use our all-on-one-line formatter.
        final Logger l = Logger.getLogger("");
        final Handler[] hs = l.getHandlers();
        for (final Handler h : hs) {
            if (h instanceof ConsoleHandler) {
                h.setFormatter(client.new OneLineSimpleLogger());
            }
        }
        client.execute(args);
    }

    protected static void usage() {
        usage(0, null);
    }


    protected static void usage(final int exitCode, @Nullable final String message) {
        if (message != null && !message.isEmpty()) {
            System.out.println(message);
        }
        System.out.println(USAGE);
        System.exit(exitCode);
    }

    /** Constructor. */
    public Client() {
        super();
    }

    /**
     * Parse a 'login:password' string.  Assumption is that no
     * colon in the login name.
     *
     * @param userpass role password
     * @return Array of strings with login in first position.
     */
    protected static String[] parseUserpass(final String userpass) {
        if (userpass == null || "-".equals(userpass)) {
            return null;
        }
        final int index = userpass.indexOf(':');
        if (index <= 0) {
            throw new RuntimeException("Unable to parse: " + userpass);
        }
        return new String[]{userpass.substring(0, index),
                userpass.substring(index + 1)};
    }

    /**
     * @param login role name
     * @param password role password
     * @return Credentials as map for RMI.
     */
    protected static Map<String, String[]> formatCredentials(@Nullable final String login,
                                                             @Nullable final String password) {
        final Map<String, String[]> env = new HashMap<>(1);
        final String[] creds = new String[]{login, password};
        env.put(JMXConnector.CREDENTIALS, creds);
        return env;
    }

    protected static JMXConnector getJMXConnector(final String hostport,
                                                  @Nullable final String login,
                                                  @Nullable final String password)
            throws IOException {
        // Make up the jmx rmi URL and get a connector.
        final JMXServiceURL rmiurl = new JMXServiceURL("service:jmx:rmi://"
                                                       + hostport + "/jndi/rmi://" + hostport + "/jmxrmi");
        return JMXConnectorFactory.connect(rmiurl, formatCredentials(login, password));
    }

    protected static ObjectName getObjectName(@Nullable final String beanname)
            throws MalformedObjectNameException, NullPointerException {
        return notEmpty(beanname) ? new ObjectName(beanname) : null;
    }

    /**
     * Version of execute called from the cmdline.
     * Prints out result of execution on stdout.
     * Parses cmdline args.  Then calls {@link #execute(String, String,
     * String, String, String[], boolean)}.
     *
     * @param args Cmdline args.
     * @throws Exception
     */
    protected void execute(final String[] args)
            throws Exception {
        // Process command-line.
        if (args.length == 0 || args.length == 1) {
            usage();
        }
        final String userpass = args[0];
        final String hostport = args[1];
        String beanname = null;
        String[] command = null;
        if (args.length > 2) {
            beanname = args[2];
        }
        if (args.length > 3) {
            command = new String[args.length - 3];
            System.arraycopy(args, 3, command, 0, args.length - 3);
        }
        final String[] loginPassword = parseUserpass(userpass);
        final Object[] result = execute(hostport,
                ((loginPassword == null) ? null : loginPassword[0]),
                ((loginPassword == null) ? null : loginPassword[1]),
                beanname, command);
        // Print out results on stdout. Only log if a result.
        if (result != null) {
            for (int i = 0; i < result.length; i++) {
                if (result[i] != null && !result[i].toString().isEmpty()) {
                    if (command != null) {
                        logger.info(command[i] + ": " + result[i]);
                    } else {
                        logger.info("\n" + result[i].toString());
                    }
                }
            }
        }
    }

    protected Object[] execute(final String hostport,
                               @Nullable final String login,
                               @Nullable final String password,
                               @Nullable final String beanname,
                               @Nullable final String[] command)
            throws Exception {
        return execute(hostport, login, password, beanname, command, false);
    }

    public Object[] executeOneCmd(final String hostport, final String login,
                                  final String password, final String beanname,
                                  final String command)
            throws Exception {
        return execute(hostport, login, password, beanname,
                new String[]{command}, true);
    }

    /**
     * Execute command against remote JMX agent.
     *
     * @param hostport 'host:port' combination.
     * @param login RMI login to use.
     * @param password RMI password to use.
     * @param beanname Name of remote bean to run command against.
     * @param command Array of commands to run.
     * @param oneBeanOnly Set true if passed {@code beanname} is
     * an exact name and the query for a bean is only supposed to return
     * one bean instance. If not, we raise an exception (Otherwise, if false,
     * then we deal with possibility of multiple bean instances coming back
     * from query). Set to true when want to get an attribute or run an
     * operation.
     * @return Array of results -- one per command.
     *
     * @throws Exception
     */
    protected Object[] execute(final String hostport,
                               @Nullable final String login,
                               @Nullable final String password,
                               @Nullable final String beanname,
                               @Nullable final String[] command,
                               final boolean oneBeanOnly)
            throws Exception {
        try (JMXConnector jmxc = getJMXConnector(hostport, login, password)) {
            return doBeans(jmxc.getMBeanServerConnection(), getObjectName(beanname), command, oneBeanOnly);
        }
    }

    protected static boolean notEmpty(@Nullable final String s) {
        return s != null && !s.isEmpty();
    }

    protected Object[] doBeans(final MBeanServerConnection mbsc,
                               final ObjectName objName,
                               @Nullable final String[] command,
                               final boolean oneBeanOnly)
            throws Exception {
        Object[] result = null;
        final Set beans = mbsc.queryMBeans(objName, null);
        if (beans.isEmpty()) {
            // No bean found. Check if we are to create a bean?
            if (command!= null && command.length == 1 && notEmpty(command[0])
                && command[0].startsWith(CREATE_CMD_PREFIX)) {
                final String className =
                        command[0].substring(CREATE_CMD_PREFIX.length());
                mbsc.createMBean(className, objName);
            } else {
                // TODO: Is there a better JMX exception that RE for this
                // scenario?
                throw new RuntimeException(objName.getCanonicalName() + " not registered.");
            }
        } else if (beans.size() == 1) {
            result = doBean(mbsc, (ObjectInstance) beans.iterator().next(), command);
        } else {
            if (oneBeanOnly) {
                throw new RuntimeException("Only supposed to be one bean " +
                                           "query result");
            }
            // This is case of multiple beans in query results.
            // Print name of each into a StringBuffer.  Return as one
            // result.
            final StringBuilder buffer = new StringBuilder();
            for (final Object obj : beans) {
                if (obj instanceof ObjectName) {
                    buffer.append((((ObjectName) obj).getCanonicalName()));
                } else if (obj instanceof ObjectInstance) {
                    buffer.append((((ObjectInstance) obj).getObjectName()
                                                         .getCanonicalName()));
                } else {
                    throw new RuntimeException("Unexpected object type: " + obj);
                }
                buffer.append("\n");
            }
            result = new String[]{buffer.toString()};
        }
        return result;
    }

    /**
     * Get attribute or run operation against passed bean {@code instance}.
     *
     * @param mbsc Server connection.
     * @param instance Bean instance we're to get attributes from or run
     * operation against.
     * @param command Command to run (May be null).
     * @return Result.  If multiple commands, multiple results.
     *
     * @throws Exception
     */
    protected Object[] doBean(final MBeanServerConnection mbsc,
                              final ObjectInstance instance,
                              @Nullable final String[] command)
            throws Exception {
        // If no command, then print out list of attributes and operations.
        if (command == null || command.length <= 0) {
            return new String[]{listOptions(mbsc, instance)};
        }

        // Maybe multiple attributes/operations listed on one command line.
        final Object[] result = new Object[command.length];
        for (int i = 0; i < command.length; i++) {
            result[i] = doSubCommand(mbsc, instance, command[i]);
        }
        return result;
    }

    public Object doSubCommand(final MBeanServerConnection mbsc,
                               final ObjectInstance instance, final String subCommand)
            throws Exception {
        // First, handle special case of our being asked to destroy a bean.
        if ("destroy".equals(subCommand)) {
            mbsc.unregisterMBean(instance.getObjectName());
            return null;
        } else if (subCommand.startsWith(CREATE_CMD_PREFIX)) {
            throw new IllegalArgumentException("You cannot call create " +
                                               "on an already existing bean.");
        }

        // Get attribute and operation info.
        final MBeanAttributeInfo[] attributeInfo =
                mbsc.getMBeanInfo(instance.getObjectName()).getAttributes();
        final MBeanOperationInfo[] operationInfo =
                mbsc.getMBeanInfo(instance.getObjectName()).getOperations();
        // Now, bdbje JMX bean doesn't follow the convention of attributes
        // having uppercase first letter and operations having lowercase
        // first letter.  But most beans do. Be prepared to handle the bdbje
        // case.
        Object result;
        if (Character.isUpperCase(subCommand.charAt(0))) {
            // Probably an attribute.
            if (!isFeatureInfo(attributeInfo, subCommand) &&
                isFeatureInfo(operationInfo, subCommand)) {
                // Its not an attribute name. Looks like its name of an
                // operation.  Try it.
                result =
                        doBeanOperation(mbsc, instance, subCommand, operationInfo);
            } else {
                // Then it is an attribute OR its not an attribute name nor
                // operation name and the below invocation will throw a
                // AttributeNotFoundException.
                result = doAttributeOperation(mbsc, instance, subCommand,
                        attributeInfo);
            }
        } else {
            // Must be an operation.
            if (!isFeatureInfo(operationInfo, subCommand) &&
                isFeatureInfo(attributeInfo, subCommand)) {
                // Its not an operation name but looks like it could be an
                // attribute name. Try it.
                result = doAttributeOperation(mbsc, instance, subCommand,
                        attributeInfo);
            } else {
                // Its an operation name OR its neither operation nor attribute
                // name and the below will throw a NoSuchMethodException.
                result =
                        doBeanOperation(mbsc, instance, subCommand, operationInfo);
            }
        }

        // Look at the result.  Is it of composite or tabular type?
        // If so, convert to a String representation.
        if (result instanceof CompositeData) {
            result = recurseCompositeData(new StringBuffer("\n"), "", "",
                    (CompositeData) result);
        } else if (result instanceof TabularData) {
            result = recurseTabularData(new StringBuffer("\n"), "", "",
                    (TabularData) result);
        } else if (result instanceof String[]) {
            final String[] strs = (String[]) result;
            final StringBuffer buffer = new StringBuffer("\n");
            for (final String str : strs) {
                buffer.append(str);
                buffer.append("\n");
            }
            result = buffer;
        } else if (result instanceof AttributeList) {
            final AttributeList list = (AttributeList) result;
            if (list.size() <= 0) {
                result = null;
            } else {
                final StringBuffer buffer = new StringBuffer("\n");
                for (final Object aList : list) {
                    final Attribute a = (Attribute) aList;
                    buffer.append(a.getName());
                    buffer.append(": ");
                    buffer.append(a.getValue());
                    buffer.append("\n");
                }
                result = buffer;
            }
        }
        return result;
    }

    protected static boolean isFeatureInfo(final MBeanFeatureInfo[] infos, final String cmd) {
        return getFeatureInfo(infos, cmd) != null;
    }

    protected static MBeanFeatureInfo getFeatureInfo(final MBeanFeatureInfo[] infos,
                                                     final String cmd) {
        // Cmd may be carrying arguments.  Don't count them in the compare.
        final int index = cmd.indexOf('=');
        final String name = (index > 0) ? cmd.substring(0, index) : cmd;
        for (final MBeanFeatureInfo info : infos) {
            if (info.getName().equals(name)) {
                return info;
            }
        }
        return null;
    }

    protected StringBuffer recurseTabularData(final StringBuffer buffer,
                                              final String indent, final String name, final TabularData data) {
        addNameToBuffer(buffer, indent, name);
        final Collection c = data.values();
        for (final Object obj : c) {
            if (obj instanceof CompositeData) {
                recurseCompositeData(buffer, indent + " ", "",
                        (CompositeData) obj);
            } else if (obj instanceof TabularData) {
                recurseTabularData(buffer, indent, "",
                        (TabularData) obj);
            } else {
                buffer.append(obj);
            }
        }
        return buffer;
    }

    protected StringBuffer recurseCompositeData(final StringBuffer buffer,
                                                String indent, final String name, final CompositeData data) {
        indent = addNameToBuffer(buffer, indent, name);
        for (final String key : data.getCompositeType().keySet()) {
            final Object o = data.get(key);
            if (o instanceof CompositeData) {
                recurseCompositeData(buffer, indent + " ", key,
                        (CompositeData) o);
            } else if (o instanceof TabularData) {
                recurseTabularData(buffer, indent, key, (TabularData) o);
            } else {
                buffer.append(indent);
                buffer.append(key);
                buffer.append(": ");
                buffer.append(o);
                buffer.append("\n");
            }
        }
        return buffer;
    }

    protected static String addNameToBuffer(final StringBuffer buffer, final String indent,
                                            final String name) {
        if (name == null || name.isEmpty()) {
            return indent;
        }
        buffer.append(indent);
        buffer.append(name);
        buffer.append(":\n");
        // Move all that comes under this 'name' over by one space.
        return indent + " ";
    }

    /**
     * Class that parses commandline arguments.
     * Expected format is 'operationName=arg0,arg1,arg2...'. We are assuming no
     * spaces nor comma's in argument values.
     */
    protected class CommandParse {
        private String cmd;
        private String[] args;

        protected CommandParse(final String command) throws ParseException {
            parse(command);
        }

        private void parse(final String command) throws ParseException {
            final Matcher m = CMD_LINE_ARGS_PATTERN.matcher(command);
            if (m == null || !m.matches()) {
                throw new ParseException("Failed parse of " + command, 0);
            }

            this.cmd = m.group(1);
            if (m.group(2) != null && !m.group(2).isEmpty()) {
                this.args = COMMA.split(m.group(2));
            } else {
                this.args = null;
            }
        }

        protected String getCmd() {
            return this.cmd;
        }

        protected String[] getArgs() {
            return this.args;
        }
    }

    protected Object doAttributeOperation(final MBeanServerConnection mbsc,
                                          final ObjectInstance instance, final String command, final MBeanAttributeInfo[] infos)
            throws Exception {
        // Usually we get attributes. If an argument, then we're being asked
        // to set attribute.
        final CommandParse parse = new CommandParse(command);
        if (parse.getArgs() == null || parse.getArgs().length == 0) {
            // Special-casing.  If the subCommand is 'Attributes', then return
            // list of all attributes.
            if ("Attributes".equals(command)) {
                final String[] names = new String[infos.length];
                for (int i = 0; i < infos.length; i++) {
                    names[i] = infos[i].getName();
                }
                return mbsc.getAttributes(instance.getObjectName(), names);
            }
            return mbsc.getAttribute(instance.getObjectName(), parse.getCmd());
        }
        if (parse.getArgs().length != 1) {
            throw new IllegalArgumentException("One only argument setting " +
                                               "attribute values: " + Arrays.toString(parse.getArgs()));
        }
        // Get first attribute of name 'cmd'. Assumption is no method
        // overrides.  Then, look at the attribute and use its type.
        final MBeanAttributeInfo info =
                (MBeanAttributeInfo) getFeatureInfo(infos, parse.getCmd());
        final Constructor c = Class.forName(
                info.getType()).getConstructor(new Class[]{String.class});
        final Attribute a = new Attribute(parse.getCmd(),
                c.newInstance(parse.getArgs()[0]));
        mbsc.setAttribute(instance.getObjectName(), a);
        return null;
    }

    protected Object doBeanOperation(final MBeanServerConnection mbsc,
                                     final ObjectInstance instance, final String command, final MBeanOperationInfo[] infos)
            throws Exception {
        // Parse command line.
        final CommandParse parse = new CommandParse(command);

        // Get first method of name 'cmd'. Assumption is no method
        // overrides.  Then, look at the method and use its signature
        // to make sure client sends over parameters of the correct type.
        final MBeanOperationInfo op =
                (MBeanOperationInfo) getFeatureInfo(infos, parse.getCmd());
        final Object result;
        if (op == null) {
            result = "Operation " + parse.getCmd() + " not found.";
        } else {
            final MBeanParameterInfo[] paraminfos = op.getSignature();
            final int paraminfosLength = (paraminfos == null) ? 0 : paraminfos.length;
            final int objsLength = (parse.getArgs() == null) ?
                    0 : parse.getArgs().length;
            if (paraminfosLength != objsLength) {
                result = "Passed param count does not match signature count";
            } else {
                final String[] signature = new String[paraminfosLength];
                final Object[] params = (paraminfosLength == 0) ? null
                        : new Object[paraminfosLength];
                for (int i = 0; i < paraminfosLength; i++) {
                    final MBeanParameterInfo paraminfo = paraminfos[i];
                    final Constructor c = Class.forName(
                            paraminfo.getType()).getConstructor(
                            new Class[]{String.class});
                    params[i] =
                            c.newInstance(parse.getArgs()[i]);
                    signature[i] = paraminfo.getType();
                }
                result = mbsc.invoke(instance.getObjectName(), parse.getCmd(),
                        params, signature);
            }
        }
        return result;
    }

    protected static String listOptions(final MBeanServerConnection mbsc,
                                        final ObjectInstance instance)
            throws InstanceNotFoundException, IntrospectionException,
                   ReflectionException, IOException {
        final StringBuilder result = new StringBuilder();
        final MBeanInfo info = mbsc.getMBeanInfo(instance.getObjectName());
        final MBeanAttributeInfo[] attributes = info.getAttributes();
        if (attributes.length > 0) {
            result.append("Attributes:");
            result.append("\n");
            for (final MBeanAttributeInfo attribute : attributes) {
                result.append(' ')
                      .append(attribute.getName())
                      .append(": ")
                      .append(attribute.getDescription())
                      .append(" (type=")
                      .append(attribute.getType())
                      .append(")");
                result.append("\n");
            }
        }
        final MBeanOperationInfo[] operations = info.getOperations();
        if (operations.length > 0) {
            result.append("Operations:");
            result.append("\n");
            for (final MBeanOperationInfo operation : operations) {
                final MBeanParameterInfo[] params = operation.getSignature();
                final StringBuilder paramsStrBuffer = new StringBuilder();
                if (params != null) {
                    for (final MBeanParameterInfo param : params) {
                        paramsStrBuffer.append("\n   name=");
                        paramsStrBuffer.append(param.getName());
                        paramsStrBuffer.append(" type=");
                        paramsStrBuffer.append(param.getType());
                        paramsStrBuffer.append(" ");
                        paramsStrBuffer.append(param.getDescription());
                    }
                }
                result.append(' ')
                      .append(operation.getName())
                      .append(": ")
                      .append(operation.getDescription())
                      .append("\n  Parameters ")
                      .append(params.length)
                      .append(", return type=")
                      .append(operation.getReturnType())
                      .append(paramsStrBuffer.toString());
                result.append("\n");
            }
        }
        return result.toString();
    }

    /**
     * Logger that writes entry on one line with less verbose date.
     * Modelled on the OneLineSimpleLogger from Heritrix.
     *
     * @author stack
     * @version $Revision$, $Date$
     */
    private class OneLineSimpleLogger extends SimpleFormatter {
        /**
         * Date instance.
         * <p/>
         * Keep around instance of date.
         */
        private final Date date = new Date();

        /**
         * Field position instance.
         * <p/>
         * Keep around this instance.
         */
        private final FieldPosition position = new FieldPosition(0);

        /** MessageFormatter for date. */
        private final SimpleDateFormat formatter =
                new SimpleDateFormat("MM/dd/yyyy HH:mm:ss Z");

        /** Persistent buffer in which we conjure the log. */
        private final StringBuffer buffer = new StringBuffer();


        public OneLineSimpleLogger() {
            super();
        }

        @Override
        public synchronized String format(final LogRecord record) {
            this.buffer.setLength(0);
            this.date.setTime(record.getMillis());
            this.position.setBeginIndex(0);
            this.formatter.format(this.date, this.buffer, this.position);
            this.buffer.append(' ');
            if (record.getSourceClassName() != null) {
                this.buffer.append(record.getSourceClassName());
            } else {
                this.buffer.append(record.getLoggerName());
            }
            this.buffer.append(' ');
            this.buffer.append(formatMessage(record));
            this.buffer.append(System.getProperty("line.separator"));

            @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
            final Throwable thrown = record.getThrown();
            if (thrown != null) {
                try {
                    final StringWriter writer = new StringWriter();
                    final PrintWriter printer = new PrintWriter(writer);
                    thrown.printStackTrace(printer);
                    writer.close();
                    this.buffer.append(writer.toString());
                } catch (Exception e) {
                    this.buffer.append("Failed to get stack trace: ").append(e.getMessage());
                }
            }
            return this.buffer.toString();
        }
    }
}

package com.wm.app.passman;

import com.wm.app.passman.PassmanUtil.Args.Mode;
import com.wm.app.passman.PassmanUtil.Args.ParametersException;
import com.wm.app.passman.datastore.DefaultDataStore;
import com.wm.app.passman.encryption.EntrustEncryptor;
import com.wm.app.passman.masterpw.EntrustMasterPassword;
import com.wm.passman.util.Logger;
import com.wm.util.security.WmSecureString;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.ParseException;

public class PassmanUtil {

    public static final String SALT_TAG = "<value name=\"salt\">";
    public static final String SALT_TAG_CLOSE = "</value>";
    public static final int READ_BUF_SIZE = 65536;

    private static void prn(String s) {
        System.out.println(s);
    }

    private static void help() {
        prn("Use: [-v] <empw.dat> <txnPassStore.data> <passman.cnf> <-l | -s key value | -d key>");
        prn("     -v                  - verbose mode to log passman messages");
        prn("     <empw.dat>          - path to empw.dat, master password file");
        prn("     <txnPassStore.data> - path to txnPassStore password database");
        prn("     <passman.cnf>       - path to passman configuration file");
        prn("     -l                  - list all passwords");
        prn("     -s <key> <value>    - modify key with value");
        prn("     -d <key>            - delete key");
    }

    public static class Args {
        public static final String LIST_PARAM = "-l";
        public static final String SET_PARAM = "-s";
        public static final String DELETE_PARAM = "-d";
        public static final String VERBOSE_PARAM = "-v";
        public String masterPasswordPath;
        public String passwordStorePath;
        public String passmanConfigPath;

        public static enum Mode {
            INVALID, LIST, SET, DELETE
        };

        public Mode mode;
        public String keyName;
        public String keyValue;
        public boolean verbose;

        public static Args parseArgv(String[] argv) throws ParseException {
            Args res = new Args();
            res.mode = Mode.INVALID;
            int i = 0;
            int stringIndex = 0;
            while (i < argv.length) {
                String curParam = argv[i];
                if (curParam.equals(LIST_PARAM)) {
                    if (res.mode != Mode.INVALID) {
                        throw new ParseException("Only one operation supported, the second operation was: " + curParam,
                                i);
                    }
                    res.mode = Mode.LIST;
                } else if (curParam.equals(SET_PARAM)) {
                    if (res.mode != Mode.INVALID) {
                        throw new ParseException("Only one operation supported, the second operation was: " + curParam,
                                i);
                    }
                    res.mode = Mode.SET;
                    // read two more strings
                    if (argv.length <= i + 2) {
                        throw new ParseException("For " + SET_PARAM + ", two arguments are needed", i);
                    }
                    res.keyName = argv[i + 1];
                    res.keyValue = argv[i + 2];
                    i += 2;
                } else if (curParam.equals(DELETE_PARAM)) {
                    if (res.mode != Mode.INVALID) {
                        throw new ParseException("Only one operation supported, the second operation was: " + curParam,
                                i);
                    }
                    res.mode = Mode.DELETE;
                    // read one more string
                    if (argv.length <= i + 1) {
                        throw new ParseException("For " + SET_PARAM + ", an argument is needed", i);
                    }
                    res.keyName = argv[i + 1];
                    i += 1;
                } else if (curParam.equals(VERBOSE_PARAM)) {
                    res.verbose = true;
                } else {
                    // string
                    switch (stringIndex) {
                    case 0:
                        res.masterPasswordPath = curParam;
                        break;
                    case 1:
                        res.passwordStorePath = curParam;
                        break;
                    case 2:
                        res.passmanConfigPath = curParam;
                        break;
                    default:
                        throw new ParseException("Parameter is unexpected", stringIndex);
                    }
                    stringIndex++;
                }
                i++;
            }
            return res;
        }

        public void validateArgs() throws ParametersException {
            if (mode == Mode.INVALID) {
                throw new ParametersException("Nothing to do, no operation specified in the arguments");
            }
            if (masterPasswordPath == null) {
                throw new ParametersException("Master password file path not specified (usually empw.dat)");
            }
            if (passwordStorePath == null) {
                throw new ParametersException("Password store file path not specified (usually txnPassStore.dat)");
            }
            if (passmanConfigPath == null) {
                throw new ParametersException("Passman configuration file path not specified (usually passman.cnf)");
            }
        }

        public static class ParametersException extends Exception {
            private static final long serialVersionUID = 3200811959205518325L;

            public ParametersException(String message) {
                super(message);
            }
        }
    }

    public static void main(String[] argv) {
        // parse arguments
        Args args = null;

        try {
            args = Args.parseArgv(argv);
            args.validateArgs();
        } catch (ParseException pe) {
            prn("Parameters are invalid: " + pe);
            help();
            System.exit(2);
        } catch (ParametersException pe) {
            prn("Error in parameters: " + pe);
            help();
            System.exit(2);
        }

        // 1. read passman configuration (salt value), this is invalid xml, parsing it
        // using regex
        // so far it worked
        File fXmlFile = new File(args.passmanConfigPath);

        String salt = null;
        try {
            BufferedReader br = new BufferedReader(new FileReader(fXmlFile));
            int charsRead = 0;
            StringBuilder sb = new StringBuilder();
            char[] buff = new char[READ_BUF_SIZE];
            while ((charsRead = br.read(buff)) != -1) {
                sb.append(buff, 0, charsRead);
            }
            String fileContents = sb.toString();
            int saltTagStart = fileContents.indexOf(SALT_TAG);
            if (saltTagStart >= 0) {
                int saltTagTextStart = saltTagStart + SALT_TAG.length();
                int saltCloseTag = fileContents.indexOf(SALT_TAG_CLOSE, saltTagTextStart);
                if (saltCloseTag >= 0) {
                    salt = fileContents.substring(saltTagTextStart, saltCloseTag);
                }
            }
            br.close();
        } catch (Exception ex) {
            prn("Can't read passman configuration: " + ex);
            return;
        }

        if (salt == null) {
            prn("Can't read salt from passman configuration");
            return;
        }

        prn("Working Directory = " + System.getProperty("user.dir"));

        Logger logger = createLogger(args.verbose);

        // 2. reading master password
        EntrustMasterPassword mpi = new EntrustMasterPassword();
        mpi.setFileName(args.masterPasswordPath);
        mpi.setRepeatLimit("3");
        mpi.setLogger(logger);

        try {
            mpi.retrieve();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

        // setting data store
        DefaultDataStore dds = new DefaultDataStore();
        try {
            dds.setFileName(args.passwordStorePath);
        } catch (Exception ex) {
            prn("ex1: " + ex.getMessage());
        }

        try {
            PassMan pm = new PassMan(dds, mpi, logger);
            EntrustEncryptor ee = new EntrustEncryptor();
            ee.setSalt(salt);
            pm.setDefaultEncryptor(ee);
            if (args.mode == Mode.LIST) {
                prn("Listing mode: ");
                for (String s : pm.listHandles()) {
                    WmSecureString wms = pm.retrievePassword(s);
                    prn("\"" + s + "\": \"" + wms.toString() + "\"");
                }
            } else if (args.mode == Mode.SET) {
                prn("Setting mode: ");
                prn("  retrieving old value");
                WmSecureString wms = pm.retrievePassword(args.keyName);
                if (wms == null) {
                    prn("  value with key \"" + args.keyName + "\" does not exist");
                } else {
                    prn("  old value: \"" + wms.toString() + "\"");
                }
                pm.storePassword(args.keyName, new WmSecureString(args.keyValue));
                prn("  new value is set to: \"" + args.keyValue + "\"");
            } else if (args.mode == Mode.DELETE) {
                prn("Deletion mode: ");
                prn("  retrieving old value");
                WmSecureString wms = pm.retrievePassword(args.keyName);
                if (wms == null) {
                    prn("  value with key \"" + args.keyName + "\" does not exist, cannot delete");
                    throw new Exception("Key does not exist");
                } else {
                    prn("  old value: \"" + wms.toString() + "\"");
                }
                pm.removePassword(args.keyName);
                prn("  deleted");
            } else {
                throw new Exception("Invalid mode");
            }
        } catch (Exception ex) {
            prn("ex: " + ex.getMessage());
            StringWriter outError = new StringWriter();
            ex.printStackTrace(new PrintWriter(outError));
            String errorString = outError.toString();
            prn("ex: " + errorString);
            System.exit(1);
        }
    }

    // implementing simple passman logger
    private static Logger createLogger(final boolean verbose) {
        return new Logger() {

            @Override
            public void setFilterLevel(int arg0) {
            }

            public void dbg(String s) {
                if (verbose) {
                    prn(s);
                }
            }

            @Override
            public void logWarning(String arg0, Exception arg1, String arg2) {
                dbg(arg0 + ": " + arg1 + ": " + arg2);
            }

            @Override
            public void logMessage(String arg0, Exception arg1, String arg2, int arg3) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3);
            }

            @Override
            public void logError(String arg0, Exception arg1, String arg2) {
                dbg(arg0 + ": " + arg1 + ": " + arg2);
            }

            @Override
            public void log(String arg0, String arg1, int arg2, int arg3, int arg4, String arg5, Object[] arg6,
                    boolean arg7) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4 + ": " + arg5 + ": " + arg6 + ": "
                        + arg7);
            }

            @Override
            public void log(String arg0, String arg1, int arg2, int arg3, int arg4, String arg5, Object[] arg6) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4 + ": " + arg5 + ": " + arg6);
            }

            @Override
            public void log(String arg0, String arg1, int arg2, int arg3, int arg4, String arg5) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4 + ": " + arg5);
            }

            @Override
            public void log(String arg0, int arg1, int arg2, int arg3, String arg4, Object[] arg5) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4 + ": " + arg5);
            }

            @Override
            public void log(String arg0, int arg1, int arg2, int arg3, String arg4) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4);
            }

            @Override
            public void log(int arg0, int arg1, int arg2, String arg3, Object[] arg4) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3 + ": " + arg4);
            }

            @Override
            public void log(int arg0, int arg1, int arg2, String arg3) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3);
            }

            @Override
            public void log(String arg0, int arg1, int arg2, String arg3) {
                dbg(arg0 + ": " + arg1 + ": " + arg2 + ": " + arg3);
            }

            @Override
            public void log(int arg0, int arg1, String arg2) {
                dbg(arg0 + ": " + arg1 + ": " + arg2);
            }

            @Override
            public void log(String arg0, int arg1, int arg2) {
                dbg(arg0 + ": " + arg1 + ": " + arg2);
            }

            @Override
            public void log(int arg0, int arg1) {
                dbg(arg0 + ": " + arg1);
            }
        };
    }
}

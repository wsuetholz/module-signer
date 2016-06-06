package com.inductiveautomation.ignitionsdk;

import org.apache.commons.cli.*;
import org.apache.commons.io.output.NullOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;

/**
 * Created by BillS on 6/6/2016.
 */
public class Main {

    public static final String OPT_KEY_STORE = "keystore";
    public static final String OPT_KEY_STORE_PWD = "keystore-pwd";
    public static final String OPT_ALIAS = "alias";
    public static final String OPT_ALIAS_PWD = "alias-pwd";
    public static final String OPT_CHAIN = "chain";
    public static final String OPT_MODULE_IN = "module-in";
    public static final String OPT_MODULE_OUT = "module-out";
    public static final String OPT_VERBOSE = "verbose";

    public static void main(String[] args) throws Exception {
        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(makeOptions(), args);

        File keyStoreFile = new File(commandLine.getOptionValue(OPT_KEY_STORE));
        String keyStorePwd = commandLine.getOptionValue(OPT_KEY_STORE_PWD, "");
        String keyStoreType = keyStoreFile.toPath().endsWith("pfx") ? "pkcs12" : "jks";

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(new FileInputStream(keyStoreFile), keyStorePwd.toCharArray());

        String alias = commandLine.getOptionValue(OPT_ALIAS);
        String aliasPwd = commandLine.getOptionValue(OPT_ALIAS_PWD, "");
        Key privateKey = keyStore.getKey(alias, aliasPwd.toCharArray());

        if (!(privateKey instanceof RSAPrivateKey)) {
            System.out.println("no RSAPrivateKey found for alias '" + alias + "'.");
            System.exit(-1);
        }

        InputStream chainInputStream = new FileInputStream(commandLine.getOptionValue(OPT_CHAIN));

        File moduleIn = new File(commandLine.getOptionValue(OPT_MODULE_IN));
        File moduleOut = new File(commandLine.getOptionValue(OPT_MODULE_OUT));

        ModuleSigner moduleSigner = new ModuleSigner((RSAPrivateKey) privateKey, chainInputStream);

        PrintStream printStream = commandLine.hasOption(OPT_VERBOSE) ?
                System.out : new PrintStream(NullOutputStream.NULL_OUTPUT_STREAM);

        moduleSigner.signModule(printStream, moduleIn, moduleOut);
    }

    private static Options makeOptions() {
        Option keyStore = Option.builder()
                .longOpt(OPT_KEY_STORE)
                .required()
                .hasArg()
                .build();

        Option keyStorePassword = Option.builder()
                .longOpt(OPT_KEY_STORE_PWD)
                .hasArg()
                .build();

        Option alias = Option.builder()
                .longOpt(OPT_ALIAS)
                .required()
                .hasArg()
                .build();

        Option aliasPassword = Option.builder()
                .longOpt(OPT_ALIAS_PWD)
                .hasArg()
                .build();

        Option chain = Option.builder()
                .longOpt(OPT_CHAIN)
                .required()
                .hasArg()
                .build();

        Option moduleIn = Option.builder()
                .longOpt(OPT_MODULE_IN)
                .required()
                .hasArg()
                .build();

        Option moduleOut = Option.builder()
                .longOpt(OPT_MODULE_OUT)
                .required()
                .hasArg()
                .build();

        Option verbose = Option.builder("v")
                .longOpt(OPT_VERBOSE)
                .required(false)
                .build();

        return new Options()
                .addOption(keyStore)
                .addOption(keyStorePassword)
                .addOption(alias)
                .addOption(aliasPassword)
                .addOption(chain)
                .addOption(moduleIn)
                .addOption(moduleOut)
                .addOption(verbose);
    }

}

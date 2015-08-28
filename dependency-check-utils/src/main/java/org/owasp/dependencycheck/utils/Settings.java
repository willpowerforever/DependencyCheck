/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;

/**
 * A simple settings container that wraps the dependencycheck.properties file.
 *
 * @author Jeremy Long
 */
public final class Settings {

    //<editor-fold defaultstate="collapsed" desc="KEYS used to access settings">
    /**
     * The collection of keys used within the properties file.
     */
    public static final class KEYS {

        /**
         * private constructor because this is a "utility" class containing constants
         */
        private KEYS() {
            //do nothing
        }
        /**
         * The key to obtain the application name.
         */
        public static final String APPLICATION_VAME = "application.name";
        /**
         * The key to obtain the application version.
         */
        public static final String APPLICATION_VERSION = "application.version";
        /**
         * The key to obtain the URL to retrieve the current release version from.
         */
        public static final String ENGINE_VERSION_CHECK_URL = "engine.version.url";
        /**
         * The properties key indicating whether or not the cached data sources should be updated.
         */
        public static final String AUTO_UPDATE = "autoupdate";
        /**
         * The database driver class name. If this is not in the properties file the embedded database is used.
         */
        public static final String DB_DRIVER_NAME = "data.driver_name";
        /**
         * The database driver class name. If this is not in the properties file the embedded database is used.
         */
        public static final String DB_DRIVER_PATH = "data.driver_path";
        /**
         * The database connection string. If this is not in the properties file the embedded database is used.
         */
        public static final String DB_CONNECTION_STRING = "data.connection_string";
        /**
         * The username to use when connecting to the database.
         */
        public static final String DB_USER = "data.user";
        /**
         * The password to authenticate to the database.
         */
        public static final String DB_PASSWORD = "data.password";
        /**
         * The base path to use for the data directory (for embedded db).
         */
        public static final String DATA_DIRECTORY = "data.directory";
        /**
         * The database file name.
         */
        public static final String DB_FILE_NAME = "data.file_name";
        /**
         * The database schema version.
         */
        public static final String DB_VERSION = "data.version";
        /**
         * The properties key for the URL to retrieve the "meta" data from about the CVE entries.
         */
        public static final String CVE_META_URL = "cve.url.meta";
        /**
         * The properties key for the URL to retrieve the recently modified and added CVE entries (last 8 days) using the 2.0
         * schema.
         */
        public static final String CVE_MODIFIED_20_URL = "cve.url-2.0.modified";
        /**
         * The properties key for the URL to retrieve the recently modified and added CVE entries (last 8 days) using the 1.2
         * schema.
         */
        public static final String CVE_MODIFIED_12_URL = "cve.url-1.2.modified";
        /**
         * The properties key for the URL to retrieve the recently modified and added CVE entries (last 8 days).
         */
        public static final String CVE_MODIFIED_VALID_FOR_DAYS = "cve.url.modified.validfordays";
        /**
         * The properties key for the telling us how many cve.url.* URLs exists. This is used in combination with CVE_BASE_URL to
         * be able to retrieve the URLs for all of the files that make up the NVD CVE listing.
         */
        public static final String CVE_START_YEAR = "cve.startyear";
        /**
         * The properties key for the CVE schema version 1.2.
         */
        public static final String CVE_SCHEMA_1_2 = "cve.url-1.2.base";
        /**
         * The properties key for the CVE schema version 2.0.
         */
        public static final String CVE_SCHEMA_2_0 = "cve.url-2.0.base";
        /**
         * The properties key that indicates how often the CPE data needs to be updated.
         */
        public static final String CPE_MODIFIED_VALID_FOR_DAYS = "cpe.validfordays";
        /**
         * The properties key for the URL to retrieve the CPE.
         */
        public static final String CPE_URL = "cpe.url";
        /**
         * The properties key for the proxy server.
         *
         * @deprecated use {@link org.owasp.dependencycheck.utils.Settings.KEYS#PROXY_SERVER} instead.
         */
        @Deprecated
        public static final String PROXY_URL = "proxy.server";
        /**
         * The properties key for the proxy server.
         */
        public static final String PROXY_SERVER = "proxy.server";
        /**
         * The properties key for the proxy port - this must be an integer value.
         */
        public static final String PROXY_PORT = "proxy.port";
        /**
         * The properties key for the proxy username.
         */
        public static final String PROXY_USERNAME = "proxy.username";
        /**
         * The properties key for the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxy.password";
        /**
         * The properties key for the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connection.timeout";
        /**
         * The location of the temporary directory.
         */
        public static final String TEMP_DIRECTORY = "temp.directory";
        /**
         * The maximum number of threads to allocate when downloading files.
         */
        public static final String MAX_DOWNLOAD_THREAD_POOL_SIZE = "max.download.threads";
        /**
         * The key for a list of suppression files.
         */
        public static final String SUPPRESSION_FILE = "suppression.file";
        /**
         * The properties key for whether the Jar Analyzer is enabled.
         */
        public static final String ANALYZER_JAR_ENABLED = "analyzer.jar.enabled";
        /**
         * The properties key for whether the Archive analyzer is enabled.
         */
        public static final String ANALYZER_ARCHIVE_ENABLED = "analyzer.archive.enabled";
        /**
         * The properties key for whether the Python Distribution analyzer is enabled.
         */
        public static final String ANALYZER_PYTHON_DISTRIBUTION_ENABLED = "analyzer.python.distribution.enabled";
        /**
         * The properties key for whether the Python Package analyzer is enabled.
         */
        public static final String ANALYZER_PYTHON_PACKAGE_ENABLED = "analyzer.python.package.enabled";
        /**
         * The properties key for whether the Ruby Gemspec Analyzer is enabled.
         */
        public static final String ANALYZER_RUBY_GEMSPEC_ENABLED = "analyzer.ruby.gemspec.enabled";
        /**
         * The properties key for whether the Autoconf analyzer is enabled.
         */
        public static final String ANALYZER_AUTOCONF_ENABLED = "analyzer.autoconf.enabled";
        /**
         * The properties key for whether the CMake analyzer is enabled.
         */
        public static final String ANALYZER_CMAKE_ENABLED = "analyzer.cmake.enabled";
        /**
         * The properties key for whether the .NET Assembly analyzer is enabled.
         */
        public static final String ANALYZER_ASSEMBLY_ENABLED = "analyzer.assembly.enabled";
        /**
         * The properties key for whether the .NET Nuspec analyzer is enabled.
         */
        public static final String ANALYZER_NUSPEC_ENABLED = "analyzer.nuspec.enabled";
        /**
         * The properties key for whether the JavaScript analyzer is enabled.
         */
        public static final String ANALYZER_JAVASCRIPT_ENABLED = "analyzer.javascript.enabled";
        /**
         * The properties key for whether the Nexus analyzer is enabled.
         */
        public static final String ANALYZER_NEXUS_ENABLED = "analyzer.nexus.enabled";
        /**
         * The properties key for whether the node.js package analyzer is enabled.
         */
        public static final String ANALYZER_NODE_PACKAGE_ENABLED = "analyzer.node.package.enabled";
        /**
         * The properties key for the Nexus search URL.
         */
        public static final String ANALYZER_NEXUS_URL = "analyzer.nexus.url";
        /**
         * The properties key for using the proxy to reach Nexus.
         */
        public static final String ANALYZER_NEXUS_PROXY = "analyzer.nexus.proxy";
        /**
         * The properties key for whether the Central analyzer is enabled.
         */
        public static final String ANALYZER_CENTRAL_ENABLED = "analyzer.central.enabled";
        /**
         * The properties key for whether the OpenSSL analyzer is enabled.
         */
        public static final String ANALYZER_OPENSSL_ENABLED = "analyzer.openssl.enabled";
        /**
         * The properties key for the Central search URL.
         */
        public static final String ANALYZER_CENTRAL_URL = "analyzer.central.url";
        /**
         * The path to mono, if available.
         */
        public static final String ANALYZER_ASSEMBLY_MONO_PATH = "analyzer.assembly.mono.path";
        /**
         * The properties key for whether the platform analyzer is enabled.
         */
        public static final String ANALYZER_PLATFORM_ENABLED = "analyzer.platform.enabled";


        /**
         * The additional configured zip file extensions, if available.
         */
        public static final String ADDITIONAL_ZIP_EXTENSIONS = "extensions.zip";
        /**
         * The properties key for whether Test Scope dependencies should be skipped.
         */
        public static final String SKIP_TEST_SCOPE = "skip.test.scope";
        /**
         * The properties key for whether Runtime Scope dependencies should be skipped.
         */
        public static final String SKIP_RUNTIME_SCOPE = "skip.runtime.scope";
        /**
         * The properties key for whether Provided Scope dependencies should be skipped.
         */
        public static final String SKIP_PROVIDED_SCOPE = "skip.provided.scope";

        /**
         * The key to obtain the path to the VFEED data file.
         */
        public static final String VFEED_DATA_FILE = "vfeed.data_file";
        /**
         * The key to obtain the VFEED connection string.
         */
        public static final String VFEED_CONNECTION_STRING = "vfeed.connection_string";

        /**
         * The key to obtain the base download URL for the VFeed data file.
         */
        public static final String VFEED_DOWNLOAD_URL = "vfeed.download_url";
        /**
         * The key to obtain the download file name for the VFeed data.
         */
        public static final String VFEED_DOWNLOAD_FILE = "vfeed.download_file";
        /**
         * The key to obtain the VFeed update status.
         */
        public static final String VFEED_UPDATE_STATUS = "vfeed.update_status";

        /**
         * The HTTP request method for query last modified date.
         */
        public static final String DOWNLOADER_QUICK_QUERY_TIMESTAMP = "downloader.quick.query.timestamp";
    }
    //</editor-fold>

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Settings.class);
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "dependencycheck.properties";
    /**
     * Thread local settings.
     */
    private static ThreadLocal<Settings> localSettings = new ThreadLocal<Settings>();
    /**
     * The properties.
     */
    private Properties props = null;

    /**
     * Private constructor for the Settings class. This class loads the properties files.
     *
     * @param propertiesFilePath the path to the base properties file to load
     */
    private Settings(String propertiesFilePath) {
        InputStream in = null;
        props = new Properties();
        try {
            in = this.getClass().getClassLoader().getResourceAsStream(propertiesFilePath);
            props.load(in);
        } catch (IOException ex) {
            LOGGER.error("Unable to load default settings.");
            LOGGER.debug("", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
            }
        }
        logProperties("Properties loaded", props);
    }

    /**
     * Initializes the thread local settings object. Note, to use the settings object you must call this method. However, you must
     * also call Settings.cleanup() to properly release resources.
     */
    public static void initialize() {
        localSettings.set(new Settings(PROPERTIES_FILE));
    }

    /**
     * Initializes the thread local settings object. Note, to use the settings object you must call this method. However, you must
     * also call Settings.cleanup() to properly release resources.
     *
     * @param propertiesFilePath the path to the base properties file to load
     */
    public static void initialize(String propertiesFilePath) {
        localSettings.set(new Settings(propertiesFilePath));
    }

    /**
     * Cleans up resources to prevent memory leaks.
     *
     */
    public static void cleanup() {
        cleanup(true);
    }

    /**
     * Cleans up resources to prevent memory leaks.
     *
     * @param deleteTemporary flag indicating whether any temporary directories generated should be removed
     */
    public static void cleanup(boolean deleteTemporary) {
        if (deleteTemporary && tempDirectory != null && tempDirectory.exists()) {
            FileUtils.delete(tempDirectory);
            if (tempDirectory.exists()) {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ex) {
                    //ignore
                }
                FileUtils.delete(tempDirectory);
            }
        }
        try {
            localSettings.remove();
        } catch (Throwable ex) {
            LOGGER.debug("Error cleaning up Settings", ex);
        }
    }

    /**
     * Gets the underlying instance of the Settings object.
     *
     * @return the Settings object
     */
    public static Settings getInstance() {
        return localSettings.get();
    }

    /**
     * Sets the instance of the Settings object to use in this thread.
     *
     * @param instance the instance of the settings object to use in this thread
     */
    public static void setInstance(Settings instance) {
        localSettings.set(instance);
    }

    /**
     * Logs the properties. This will not log any properties that contain 'password' in the key.
     *
     * @param header the header to print with the log message
     * @param properties the properties to log
     */
    private static void logProperties(String header, Properties properties) {
        if (LOGGER.isDebugEnabled()) {
            final StringWriter sw = new StringWriter();
            PrintWriter pw = null;
            try {
                pw = new PrintWriter(sw);
                pw.format("%s:%n%n", header);
                final Enumeration<?> e = properties.propertyNames();
                while (e.hasMoreElements()) {
                    final String key = (String) e.nextElement();
                    if (key.contains("password")) {
                        pw.format("%s='*****'%n", key);
                    } else {
                        final String value = properties.getProperty(key);
                        if (value != null) {
                            pw.format("%s='%s'%n", key, value);
                        }
                    }
                }
                pw.flush();
                LOGGER.debug(sw.toString());
            } finally {
                if (pw != null) {
                    pw.close();
                }
            }

        }
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public static void setString(String key, String value) {
        localSettings.get().props.setProperty(key, value);
        LOGGER.debug("Setting: {}='{}'", key, value);
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public static void setBoolean(String key, boolean value) {
        if (value) {
            localSettings.get().props.setProperty(key, Boolean.TRUE.toString());
        } else {
            localSettings.get().props.setProperty(key, Boolean.FALSE.toString());
        }
        LOGGER.debug("Setting: {}='{}'", key, value);
    }

    /**
     * Merges a new properties file into the current properties. This method allows for the loading of a user provided properties
     * file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws FileNotFoundException is thrown when the filePath points to a non-existent file
     * @throws IOException is thrown when there is an exception loading/merging the properties
     */
    public static void mergeProperties(File filePath) throws FileNotFoundException, IOException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);
            mergeProperties(fis);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.trace("close error", ex);
                }
            }
        }
    }

    /**
     * Merges a new properties file into the current properties. This method allows for the loading of a user provided properties
     * file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws FileNotFoundException is thrown when the filePath points to a non-existent file
     * @throws IOException is thrown when there is an exception loading/merging the properties
     */
    public static void mergeProperties(String filePath) throws FileNotFoundException, IOException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);
            mergeProperties(fis);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.trace("close error", ex);
                }
            }
        }
    }

    /**
     * Merges a new properties file into the current properties. This method allows for the loading of a user provided properties
     * file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before properties loaded from files.
     *
     * @param stream an Input Stream pointing at a properties file to merge
     * @throws IOException is thrown when there is an exception loading/merging the properties
     */
    public static void mergeProperties(InputStream stream) throws IOException {
        localSettings.get().props.load(stream);
        logProperties("Properties updated via merge", localSettings.get().props);
    }

    /**
     * Returns a value from the properties file as a File object. If the value was specified as a system property or passed in via
     * the -Dprop=value argument - this method will return the value from the system properties before the values in the contained
     * configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    public static File getFile(String key) {
        final String file = getString(key);
        if (file == null) {
            return null;
        }
        return new File(file);
    }

    /**
     * Returns a value from the properties file as a File object. If the value was specified as a system property or passed in via
     * the -Dprop=value argument - this method will return the value from the system properties before the values in the contained
     * configuration file.
     *
     * This method will check the configured base directory and will use this as the base of the file path. Additionally, if the
     * base directory begins with a leading "[JAR]\" sequence with the path to the folder containing the JAR file containing this
     * class.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    protected static File getDataFile(String key) {
        final String file = getString(key);
        LOGGER.debug("Settings.getDataFile() - file: '{}'", file);
        if (file == null) {
            return null;
        }
        if (file.startsWith("[JAR]")) {
            LOGGER.debug("Settings.getDataFile() - transforming filename");
            final File jarPath = getJarPath();
            LOGGER.debug("Settings.getDataFile() - jar file: '{}'", jarPath.toString());
            final File retVal = new File(jarPath, file.substring(6));
            LOGGER.debug("Settings.getDataFile() - returning: '{}'", retVal.toString());
            return retVal;
        }
        return new File(file);
    }

    /**
     * Attempts to retrieve the folder containing the Jar file containing the Settings class.
     *
     * @return a File object
     */
    private static File getJarPath() {
        final String jarPath = Settings.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = ".";
        try {
            decodedPath = URLDecoder.decode(jarPath, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            LOGGER.trace("", ex);
        }

        final File path = new File(decodedPath);
        if (path.getName().toLowerCase().endsWith(".jar")) {
            return path.getParentFile();
        } else {
            return new File(".");
        }
    }

    /**
     * Returns a value from the properties file. If the value was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value for the requested property
     * @return the property from the properties file
     */
    public static String getString(String key, String defaultValue) {
        final String str = System.getProperty(key, localSettings.get().props.getProperty(key, defaultValue));
        return str;
    }

    /**
     * A reference to the temporary directory; used incase it needs to be deleted during cleanup.
     */
    private static File tempDirectory = null;

    /**
     * Returns the temporary directory.
     *
     * @return the temporary directory
     * @throws java.io.IOException thrown if the temporary directory does not exist and cannot be created
     */
    public static File getTempDirectory() throws IOException {
        final File tmpDir = new File(Settings.getString(Settings.KEYS.TEMP_DIRECTORY, System.getProperty("java.io.tmpdir")), "dctemp");
        if (!tmpDir.exists()) {
            if (!tmpDir.mkdirs()) {
                final String msg = String.format("Unable to make a temporary folder '%s'", tmpDir.getPath());
                throw new IOException(msg);
            }
        }
        tempDirectory = tmpDir;
        return tmpDir;
    }

    /**
     * Returns a value from the properties file. If the value was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     */
    public static String getString(String key) {
        return System.getProperty(key, localSettings.get().props.getProperty(key));
    }

    /**
     * Removes a property from the local properties collection. This is mainly used in test cases.
     *
     * @param key the property key to remove
     */
    public static void removeProperty(String key) {
        localSettings.get().props.remove(key);
    }

    /**
     * Returns an int value from the properties file. If the value was specified as a system property or passed in via the
     * -Dprop=value argument - this method will return the value from the system properties before the values in the contained
     * configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving the setting
     */
    public static int getInt(String key) throws InvalidSettingException {
        int value;
        try {
            value = Integer.parseInt(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns an int value from the properties file. If the value was specified as a system property or passed in via the
     * -Dprop=value argument - this method will return the value from the system properties before the values in the contained
     * configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return
     * @return the property from the properties file or the defaultValue if the property does not exist or cannot be converted to
     * an integer
     */
    public static int getInt(String key, int defaultValue) {
        int value;
        try {
            value = Integer.parseInt(Settings.getString(key));
        } catch (NumberFormatException ex) {
            LOGGER.trace("Could not convert property '{}' to an int.", key, ex);
            value = defaultValue;
        }
        return value;
    }

    /**
     * Returns a long value from the properties file. If the value was specified as a system property or passed in via the
     * -Dprop=value argument - this method will return the value from the system properties before the values in the contained
     * configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving the setting
     */
    public static long getLong(String key) throws InvalidSettingException {
        long value;
        try {
            value = Long.parseLong(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns a boolean value from the properties file. If the value was specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving the setting
     */
    public static boolean getBoolean(String key) throws InvalidSettingException {
        boolean value;
        try {
            value = Boolean.parseBoolean(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns a boolean value from the properties file. If the value was specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return if the setting does not exist
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving the setting
     */
    public static boolean getBoolean(String key, boolean defaultValue) throws InvalidSettingException {
        boolean value;
        try {
            final String strValue = Settings.getString(key);
            if (strValue == null) {
                return defaultValue;
            }
            value = Boolean.parseBoolean(strValue);
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns a connection string from the configured properties. If the connection string contains a %s, this method will
     * determine the 'data' directory and replace the %s with the path to the data directory. If the data directory does not
     * exists it will be created.
     *
     * @param connectionStringKey the property file key for the connection string
     * @param dbFileNameKey the settings key for the db filename
     * @return the connection string
     * @throws IOException thrown the data directory cannot be created
     * @throws InvalidSettingException thrown if there is an invalid setting
     */
    public static String getConnectionString(String connectionStringKey, String dbFileNameKey)
            throws IOException, InvalidSettingException {
        final String connStr = Settings.getString(connectionStringKey);
        if (connStr == null) {
            final String msg = String.format("Invalid properties file; %s is missing.", connectionStringKey);
            throw new InvalidSettingException(msg);
        }
        if (connStr.contains("%s")) {
            final File directory = getDataDirectory();
            String fileName = null;
            if (dbFileNameKey != null) {
                fileName = Settings.getString(dbFileNameKey);
            }
            if (fileName == null) {
                final String msg = String.format("Invalid properties file to get a file based connection string; '%s' must be defined.",
                        dbFileNameKey);
                throw new InvalidSettingException(msg);
            }
            if (connStr.startsWith("jdbc:h2:file:") && fileName.endsWith(".h2.db")) {
                fileName = fileName.substring(0, fileName.length() - 6);
            }
            // yes, for H2 this path won't actually exists - but this is sufficient to get the value needed
            final File dbFile = new File(directory, fileName);
            final String cString = String.format(connStr, dbFile.getCanonicalPath());
            LOGGER.debug("Connection String: '{}'", cString);
            return cString;
        }
        return connStr;
    }

    /**
     * Retrieves the directory that the JAR file exists in so that we can ensure we always use a common data directory for the
     * embedded H2 database. This is public solely for some unit tests; otherwise this should be private.
     *
     * @return the data directory to store data files
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public static File getDataDirectory() throws IOException {
        final File path = Settings.getDataFile(Settings.KEYS.DATA_DIRECTORY);
        if (path.exists() || path.mkdirs()) {
            return path;
        }
        throw new IOException(String.format("Unable to create the data directory '%s'", path.getAbsolutePath()));
    }
}

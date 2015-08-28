package org.owasp.dependencycheck.analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.FileFilter;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.FileFilterBuilder;


/**
 * This analyzer is used to collect the platform technologies used in our application.
 * The platform technologies information is provided directly from a *.plt file.
 * The platform including the application server, http server etc.
 * 
 * @author Yu Wu
 *
 */
public class PlatformAnalyzer extends AbstractFileTypeAnalyzer {

  /**
   * The logger.
   */
  private static final Logger LOGGER = Logger.getLogger(PlatformAnalyzer.class.getName());
  
  /**
   * The name of the analyzer.
   */
  private static final String ANALYZER_NAME = "Platform Analyzer";
  /**
   * The phase that this analyzer is intended to run in.
   */
  private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
  
  private static final Set<String> EXTENSIONS = newHashSet("plt");
  
  /**
   * The file filter used to filter supported files.
   */
  private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();

  @Override
  protected FileFilter getFileFilter() {
      return FILTER;
  }
  
  @Override
  public String getName() {
    // TODO Auto-generated method stub
    return ANALYZER_NAME;
  }

  @Override
  public AnalysisPhase getAnalysisPhase() {
    // TODO Auto-generated method stub
    return ANALYSIS_PHASE;
  }

  @Override
  protected void initializeFileTypeAnalyzer() throws Exception {
    // TODO Auto-generated method stub
    
  }

  @Override
  protected void analyzeFileType(Dependency dependency, Engine engine)
      throws AnalysisException {
    // TODO Auto-generated method stub
    BufferedReader fin = null;
    try {
      File file = dependency.getActualFile();
      fin = new BufferedReader(new FileReader(file));
      String text;
      while ((text = fin.readLine()) != null) {
          String[] info = text.split(",");
          final Dependency newDependency = new Dependency(new File(FileUtils.getBitBucket()));
          newDependency.setMd5sum(text);
          newDependency.setSha1sum(text);
          newDependency.setFileName(dependency.getFileName());
          newDependency.setFilePath(dependency.getFilePath());
          newDependency.getVendorEvidence().addEvidence("platform", "vendor", info[0].trim(), Confidence.HIGH);
          newDependency.getProductEvidence().addEvidence("platform", "name", info[1].trim(), Confidence.HIGH);
          newDependency.getVersionEvidence().addEvidence("platform", "version", info[2].trim(), Confidence.HIGH);
          engine.getDependencies().add(newDependency);
      }
    } catch (FileNotFoundException ex) {
      final String msg = String.format("Dependency file not found: '%s'", dependency.getActualFilePath());
      throw new AnalysisException(msg, ex);
    } catch (IOException ex) {
      LOGGER.log(Level.SEVERE, null, ex);
    } finally {
      if (fin != null) {
          try {
              fin.close();
          } catch (IOException ex) {
              LOGGER.log(Level.FINEST, null, ex);
          }
      }
    }
  }

  @Override
  protected String getAnalyzerEnabledSettingKey() {
    // TODO Auto-generated method stub
    return Settings.KEYS.ANALYZER_PLATFORM_ENABLED;
  }


}
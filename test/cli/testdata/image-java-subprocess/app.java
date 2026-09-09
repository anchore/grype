import java.io.IOException;

public class GrypeExecutionTest {

  public static void main(String[] args) {
    try {
      ProcessBuilder builder = new ProcessBuilder("grype", "sbom:/sbom.json", "-vv");

      builder.inheritIO();
      Process process = builder.start();

      // surface grype's exit code so the test can tell a successful scan from a failed one
      System.exit(process.waitFor());

    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}

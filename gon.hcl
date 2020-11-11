source = ["./dist/grype-macos_darwin_amd64/grype"] # The 'dist' directory path should ideally reference an env var, where the source of truth is the Makefile. I wasn't able to figure out how to solve this.
bundle_id = "com.anchore.toolbox.grype"

sign {
  application_identity = "Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)"
}

dmg {
  output_path = "./dist/output.dmg"
  volume_name = "Grype"
}

zip {
  output_path = "./dist/output.zip"
}

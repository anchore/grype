.DEFAULT_GOAL := validate-schema

.PHONY: validate-schema
validate-schema: validate-schema-xml validate-schema-json

.PHONY: validate-schema-xml
validate-schema-xml:
	go run ../../cmd/grype -c ../../test/grype-test-config.yaml ubuntu:latest -v -o cyclonedx-xml > bom.xml
	xmllint --noout --schema ./cyclonedx.xsd bom.xml

.PHONY: validate-schema-json
validate-schema-json:
	go run ../../cmd/grype -c ../../test/grype-test-config.yaml ubuntu:latest -v -o cyclonedx-json > bom.json
	../../.tool/yajsv -s cyclonedx.json bom.json

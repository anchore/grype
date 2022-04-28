.DEFAULT_GOAL := validate-schema

.PHONY: validate-schema
validate-schema: validate-schema-xml validate-schema-json

.PHONY: validate-schema-xml
validate-schema-xml:
	go run ../../main.go -c ../../test/grype-test-config.yaml ubuntu:latest -vv -o embedded-cyclondex-vex-xml > bom.xml
	xmllint --noout --schema ./cyclonedx.xsd bom.xml

.PHONY: validate-schema-json
validate-schema-json:
	go run ../../main.go -c ../../test/grype-test-config.yaml ubuntu:latest -vv -o embedded-cyclondex-vex-json > bom.json
	../../.tmp/yajsv -s cyclonedx.json bom.json

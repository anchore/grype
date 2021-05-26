.DEFAULT_GOAL := validate-schema
.PHONY: validate-schema
validate-schema:
	go run ../../main.go -c ../../test/grype-test-config.yaml ubuntu:latest -vv -o cyclonedx > bom.xml
	xmllint --noout --schema ./cyclonedx.xsd bom.xml
# CycloneDX Schemas

`grype` generates a CycloneDX output. This validation is similar to what is done in `syft`, validating output against CycloneDX schemas.

Validation is done with `xmllint`, which requires a copy of all schemas because it can't work with HTTP references. The schemas are modified to reference local copies of dependent schemas.

## Updating

You will need to go to https://github.com/CycloneDX/specification/blob/1.5/schema and download the latest `bom-#.#.xsd` and `spdx.xsd`.

Additionally, for `xmllint` to function you will need to patch the bom schema with the location to the SPDX schema by changing:

```xml
<xs:import namespace="http://cyclonedx.org/schema/spdx" schemaLocation="http://cyclonedx.org/schema/spdx"/>
```

To:
```xml
<xs:import namespace="http://cyclonedx.org/schema/spdx" schemaLocation="spdx.xsd"/>
```

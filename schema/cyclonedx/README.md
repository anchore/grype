# CycloneDX Schemas

`griffon` generates a CycloneDX output. This validation is similar to what is done in `syft`, validating output against CycloneDX schemas.

Validation is done with `xmllint`, which requires a copy of all schemas because it can't work with HTTP references. The schemas are modified to reference local copies of dependent schemas.

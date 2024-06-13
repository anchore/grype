CREATE TABLE db_metadata
(
    build_timestamp TEXT NOT NULL,
    schema_version  INTEGER NOT NULL
);

CREATE TABLE providers
(
    provider_id         INTEGER PRIMARY KEY,
    name                TEXT NOT NULL,
    version             TEXT,
    date_captured       TEXT,
    input_digest        TEXT,
    data_oci_repository TEXT
);

CREATE TABLE vulnerabilities
(
    vulnerability_id     INTEGER PRIMARY KEY,
    provider_id          INTEGER NOT NULL,
    id                   TEXT NOT NULL,
    modified             TEXT,
    published            TEXT,
    withdrawn            TEXT,
    summary_digest       TEXT,
    detail_digest        TEXT,
    database_specific_id INTEGER,
    FOREIGN KEY (provider_id) REFERENCES providers (provider_id),
    FOREIGN KEY (database_specific_id) REFERENCES database_specific (db_specific_id)
);

CREATE TABLE aliases
(
    alias_id         INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    alias            TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE related_vulnerabilities
(
    related_id               INTEGER PRIMARY KEY,
    vulnerability_id         INTEGER NOT NULL,
    related_vulnerability_id TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE severities
(
    severity_id      INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    type             TEXT NOT NULL,
    score            TEXT NOT NULL,
    source           TEXT,
    tag              TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE package_qualifiers
(
    qualifier_id INTEGER PRIMARY KEY,
    affected_id  INTEGER,
    entity_type  TEXT NOT NULL,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE package_qualifier_platform_cpes
(
    qualifier_id INTEGER PRIMARY KEY,
    cpe          TEXT NOT NULL, -- TODO: should this be broken out into fields?
    FOREIGN KEY (qualifier_id) REFERENCES package_qualifiers (qualifier_id)
);

CREATE TABLE package_qualifier_rpm_modularities
(
    qualifier_id INTEGER PRIMARY KEY,
    module       TEXT NOT NULL,
    FOREIGN KEY (qualifier_id) REFERENCES package_qualifiers (qualifier_id)
);

CREATE TABLE affected
(
    affected_id INTEGER PRIMARY KEY,
    entity_type TEXT NOT NULL
);

CREATE TABLE affected_distro_packages
(
    affected_id      INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    package_name     TEXT NOT NULL,
    os_id            INTEGER NOT NULL,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id),
    FOREIGN KEY (os_id) REFERENCES operating_systems (os_id)
);

CREATE TABLE operating_systems
(
    os_id         INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    major_version TEXT NOT NULL,
    minor_version TEXT,
    codename      TEXT
);

CREATE TABLE affected_packages
(
    affected_id      INTEGER PRIMARY KEY,
    vulnerability_id INTEGER,
    ecosystem        TEXT,
    package_name     TEXT,
    purl             TEXT,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE affected_cpes
(
    affected_id      INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    -- TODO: should we add all CPE fields here?
    type             TEXT NOT NULL,
    vendor           TEXT,
    product          TEXT NOT NULL,
    version          TEXT,
    "update"           TEXT,
    target_software  TEXT,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE logical_package
(
    logical_package_id INTEGER NOT NULL,
    affected_id        INTEGER NOT NULL,
    PRIMARY KEY (logical_package_id, affected_id),
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE package_digests
(
    vulnerability_id INTEGER NOT NULL,
    digest_algorithm TEXT NOT NULL,
    digest_value     TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE affected_versions
(
    version_id  INTEGER PRIMARY KEY,
    affected_id INTEGER NOT NULL,
    version     TEXT NOT NULL,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE not_affected_versions
(
    version_id  INTEGER PRIMARY KEY,
    affected_id INTEGER NOT NULL,
    version     TEXT NOT NULL,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE affected_severities
(
    affected_severity_id INTEGER PRIMARY KEY,
    affected_id          INTEGER NOT NULL,
    type                 TEXT NOT NULL,
    score                TEXT NOT NULL,
    source               TEXT,
    tag                  TEXT,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE range_events
(
    event_id      INTEGER PRIMARY KEY,
    affected_id   INTEGER NOT NULL,
    type          TEXT NOT NULL,
    repo          TEXT,
    introduced    TEXT,
    fixed         TEXT,
    last_affected TEXT,
    "limit"         TEXT,
    state         TEXT,
    FOREIGN KEY (affected_id) REFERENCES affected (affected_id)
);

CREATE TABLE "references"
(
    reference_id     INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    type             TEXT NOT NULL,
    url              TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
);

CREATE TABLE database_specific
(
    db_specific_id INTEGER PRIMARY KEY,
    -- entity_type is a discriminator column (to support pseudo inheritance)
    entity_type    TEXT NOT NULL CHECK( entity_type IN ('nvd') )
);

CREATE TABLE database_specific_nvd
(
    db_specific_id INTEGER PRIMARY KEY,
    vulnStatus               TEXT,
    cisaExploitAdd           TEXT,
    cisaActionDue            TEXT,
    cisaRequiredAction       TEXT,
    cisaVulnerabilityName    TEXT,
    FOREIGN KEY (db_specific_id) REFERENCES database_specific (db_specific_id)
);

CREATE TABLE descriptions
(
    digest TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE INDEX vulnerability_provider_idx ON vulnerabilities (vulnerability_id, provider_id);

PRAGMA foreign_keys = ON;

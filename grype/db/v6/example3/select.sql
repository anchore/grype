SELECT
    v.id AS vulnerability_id,
    v.name AS vulnerability_name,
    v.schema_version,
    v.modified,
    v.published,
    v.withdrawn,
    v.summary,
    v.details,
    a.id AS affected_id,
--     a.ecosystem AS package_ecosystem,
--     a.name AS package_name,
--     a.purl AS package_purl,
    s.type AS severity_type,
    s.score AS severity_score,
    r.type AS range_type,
    r.repo AS range_repo,
    re.introduced AS range_event_introduced,
    re.fixed AS range_event_fixed,
    re.last_affected AS range_event_last_affected,
    re."limit" AS range_event_limit,
    ver.version AS affected_version
FROM
    vulnerabilities v
        LEFT JOIN
    affecteds a ON v.id = a.vulnerability_id
        LEFT JOIN
    affected_severities s ON a.id = s.affected_id
        LEFT JOIN
    ranges r ON a.id = r.affected_id
        LEFT JOIN
    range_events re ON r.id = re.range_id
        LEFT JOIN
    versions ver ON a.id = ver.affected_id
ORDER BY
    v.id, a.id, s.id, r.id, re.id, ver.id;

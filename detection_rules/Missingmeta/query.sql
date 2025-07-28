/*
Name: missing metadata
Description:
*/
SELECT
    'missing_meta' AS report_name,
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
LIMIT 1;

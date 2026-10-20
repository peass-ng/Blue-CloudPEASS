"""Individually reviewed AWS database findings; no cloud requests or mutations."""
from copy import deepcopy
import hashlib
import json
import re

VERSION = "aws-database-clarity-20261019"
ROWS = json.loads(r'''
{
  "aws.cb.rds.cluster_backtrack_window_positive": {
    "description_base_sha256": "47d269221c54babe1e9179e47fd5607e01d619b001c621e53fd07e4a9daa5c1e",
    "description_fields": {
      "description": "Checks for a positive Backtrack window on supported Aurora MySQL versions and Regions."
    },
    "remediation_base_sha256": "7566818fe7f2a246288672cd61980ca04189f7d2b7c7d5630769f87039f6e6cd",
    "remediation_fields": {
      "summary": "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster.",
      "steps": [
        "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster."
      ]
    },
    "static_observed_sentence": "Backtrack is disabled: its window is zero seconds.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_backtrack",
      "predicate_source_sha256": "abb9c1bed37425d4fd69eb51dd9a23f0aba626d03fece42ef64af56298e70881"
    }
  },
  "aws.cb.rds.aurora_backtracking_configured": {
    "description_base_sha256": "7c78ed3e21feaea106a9907bdee1a0d3f1ee1d6890af5136d8dbb5129ba65850",
    "description_fields": {
      "description": "Checks for a positive Backtrack window on supported Aurora MySQL versions and Regions."
    },
    "remediation_base_sha256": "cdc0908e7ecbd4ef1a200f21712e35f37aa98030394155800379bf55ede168bd",
    "remediation_fields": {
      "summary": "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster.",
      "steps": [
        "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster."
      ]
    },
    "static_observed_sentence": "Backtrack is disabled: its window is zero seconds.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_backtracking",
      "predicate_source_sha256": "bd728bb625d6bf5300983aa7a8ed97d0cb444f83523d48531e4b342c0e20645e"
    }
  },
  "aws.cb.rds.cluster_cloudwatch_log_exports": {
    "description_base_sha256": "fcd2b5dd4d07a5c3390ff8a8e170ab05e072cc803952e04f619b3fdfe6d729c0",
    "description_fields": {
      "description": "Checks whether the cluster declares any CloudWatch log exports."
    },
    "remediation_base_sha256": "a0b455413dc2811e701dcd35503991f066a45ca2987951d58f4e25674517af65",
    "remediation_fields": {
      "summary": "Enable the database log exports needed for investigation.",
      "steps": [
        "Enable the database log exports needed for investigation."
      ],
      "caveats": [
        "Export settings do not demonstrate log delivery or database audit settings.",
        "Other engines are NOT_APPLICABLE; one declared export passes this exact predicate, not proof that audit/error logs are complete or delivered. Export changes can expose SQL or user data and add log ingestion charges."
      ]
    },
    "static_observed_sentence": "The cluster declares no CloudWatch log exports.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_cw",
      "predicate_source_sha256": "3827d47ef7f3c1994ac6762b8a6d467cf2e6902e8c8052e81263a71404532af8"
    }
  },
  "aws.cb.rds.cluster_log_exports_declared": {
    "description_base_sha256": "63b0a93ed859df09d2a90c1d448ae743a6d981e6148edd2e0e6a59d0180ff19c",
    "description_fields": {
      "description": "Checks whether the cluster declares any CloudWatch log exports."
    },
    "remediation_base_sha256": "b120eeeb1a43e6793d656e81ea6becb30839e754e8622337980f22f340789a79",
    "remediation_fields": {
      "summary": "Enable the database log exports needed for investigation.",
      "steps": [
        "Enable the database log exports needed for investigation."
      ],
      "caveats": [
        "Export settings do not demonstrate log delivery or database audit settings.",
        "This check is the cluster half of a source UNION labeled enhanced monitoring, but it evaluates log exports only; enabling OS Enhanced Monitoring alone does not clear it. Nonempty exports do not prove event delivery or retention."
      ]
    },
    "static_observed_sentence": "The cluster declares no CloudWatch log exports.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_exports",
      "predicate_source_sha256": "02ed995b707ac99207e86fb4c2524004f2b91ff96bed3426be752a38aafbd899"
    }
  },
  "aws.cb.rds.multi_az_cluster_minor_upgrade": {
    "description_base_sha256": "3bb0082b4de8b101515d189627157161c51e27a417602cb13089b50fe57002fb",
    "description_fields": {
      "description": "Checks AutoMinorVersionUpgrade on applicable Multi-AZ DB clusters."
    },
    "remediation_base_sha256": "f85701d0bab40066ddfaaed5068d84bed424ec67dad90ef6e5c4bb61a9916ebe",
    "remediation_fields": {
      "summary": "Enable automatic minor upgrades after checking maintenance and application compatibility.",
      "steps": [
        "Enable automatic minor upgrades after checking maintenance and application compatibility."
      ]
    },
    "static_observed_sentence": "Automatic minor version upgrades are disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_minor",
      "predicate_source_sha256": "8c824647976218e53f3a100e8b3823b922285758b300b9a7e52409eee908d00e"
    }
  },
  "aws.cb.rds.cluster_engine_default_port_prowler": {
    "description_base_sha256": "b26bc00f9198e818f0a8bda4b513341201c9591abc02da17a039d0862247a7aa",
    "description_fields": {
      "description": "Compares the database port with this profile\u2019s engine-default port map."
    },
    "remediation_base_sha256": "e0874b1178610a22a1690447d936c8086d0c01bbb979b6404fc21dc10f376e52",
    "remediation_fields": {
      "summary": "Keep the default port if required; restrict database access to the necessary networks and identities.",
      "steps": [
        "Keep the default port if required; restrict database access to the necessary networks and identities."
      ],
      "caveats": [
        "A nondefault port does not restrict access or replace authentication.",
        "DocumentDB is not applicable. The source uses a substring engine/default-port map including Db2; a non-default port does not prevent discovery or authorize clients. Port changes can cause downtime and application failures, so no generic modification flag is offered without engine and deployment review."
      ]
    },
    "static_observed_sentence": "The database uses its engine\u2019s default port.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "_port.<locals>.evaluate",
      "predicate_source_sha256": "f0af129ce92257363f9c431987bf1066a9bff5e706d891302c95bbadaee6b9d2"
    }
  },
  "aws.cb.rds.instance_engine_default_port_prowler": {
    "description_base_sha256": "75b4fea4d6cd1c8fd8e8402ba9753dd3b404b1b2a17f078fd7edf053f03f9440",
    "description_fields": {
      "description": "Compares the database port with this profile\u2019s engine-default port map."
    },
    "remediation_base_sha256": "3b5d9a3e691a749bfd907984ac6934bc62aa8419d9adda15e34fc00d01e59adf",
    "remediation_fields": {
      "summary": "Keep the default port if required; restrict database access to the necessary networks and identities.",
      "steps": [
        "Keep the default port if required; restrict database access to the necessary networks and identities."
      ],
      "caveats": [
        "A nondefault port does not restrict access or replace authentication.",
        "DocumentDB is not applicable. The source uses a substring engine/default-port map including Db2; a non-default port does not prevent discovery or authorize clients. Port changes can cause downtime and application failures, so no generic modification flag is offered without engine and deployment review."
      ]
    },
    "static_observed_sentence": "The database uses its engine\u2019s default port.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_port.<locals>.evaluate",
      "predicate_source_sha256": "f0af129ce92257363f9c431987bf1066a9bff5e706d891302c95bbadaee6b9d2"
    }
  },
  "aws.cb.rds.cluster_in_backup_plan_selection": {
    "description_base_sha256": "284b3060ff1abb6c68918f47723453bb5e7a1bc9ecc68f3565d6cc2016edae40",
    "description_fields": {
      "description": "Matches the database ARN against AWS Backup selection ARNs and supported wildcards."
    },
    "remediation_base_sha256": "952bfa0cff8cfcd55f7064dfdea9b80895eb466b31c92808b868854609704ed9",
    "remediation_fields": {
      "summary": "Add this database to an appropriate AWS Backup plan if it should be covered.",
      "steps": [
        "Add this database to an appropriate AWS Backup plan if it should be covered."
      ],
      "caveats": [
        "Selection membership does not prove successful backups or restoration.",
        "DocumentDB is not applicable. The source accepts exact cluster ARN, a broad partition cluster wildcard or *; selection presence does not prove a successful backup or restore. Avoid broad * solely to clear the finding."
      ]
    },
    "static_observed_sentence": "No AWS Backup selection matches this database ARN.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_selected",
      "predicate_source_sha256": "57617a6c993c595dec2d08a477216a08a13b36a0de60c63c019740a73cb4dd3d"
    }
  },
  "aws.cb.rds.instance_in_backup_plan_selection": {
    "description_base_sha256": "8fced6171c0cc4a1ed65bd731641a6b5354d75cb2b95f5a84bd4f187df6e5264",
    "description_fields": {
      "description": "Matches the database ARN against AWS Backup selection ARNs and supported wildcards."
    },
    "remediation_base_sha256": "68dabc8198cc5cff8cbfdc4ff84a866e18c563d4461219fa91c3d766d933fe9d",
    "remediation_fields": {
      "summary": "Add this database to an appropriate AWS Backup plan if it should be covered.",
      "steps": [
        "Add this database to an appropriate AWS Backup plan if it should be covered."
      ],
      "caveats": [
        "Selection membership does not prove successful backups or restoration.",
        "Aurora and DocumentDB instances are not applicable. Selection presence is only policy intent; it does not prove recovery points or successful restore, and a broad * could protect unintended resources."
      ]
    },
    "static_observed_sentence": "No AWS Backup selection matches this database ARN.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_selected",
      "predicate_source_sha256": "82fcfc9cc2f8d5f9e0a065b379d98cd88c9987c76625f9662613adfb2ce4ae3b"
    }
  },
  "aws.cb.rds.aurora_cluster_protected_resource": {
    "description_base_sha256": "ce4be6375f971492b9669499cc91cd032e3be710073009a123fcd7055fe52382",
    "description_fields": {
      "description": "Looks for the database ARN and its resource type in AWS Backup protected resources."
    },
    "remediation_base_sha256": "aba5524442c1fe804f47aac074534eefa8331cb8f5a7ac88caada852e4da631a",
    "remediation_fields": {
      "summary": "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database.",
      "steps": [
        "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database."
      ],
      "caveats": [
        "A protected-resource record is not a restore test or proof of current backup freshness.",
        "The source checks a protected-resource record, which AWS can retain regardless of recovery point status. It does not prove the latest point is valid or restorable; non-Aurora engines are not applicable."
      ]
    },
    "static_observed_sentence": "AWS Backup has no matching protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_protected",
      "predicate_source_sha256": "1aad7f40cf45352084ca35e3f67c9eb934fa3d7e2ccfbe2e52a4cf0c079828db"
    }
  },
  "aws.cb.rds.instance_protected_resource": {
    "description_base_sha256": "ffd5e52af3cd3dfc2a5d77e10f7d62d06f5c0a654ccfa5f3ec56d2666270c8b7",
    "description_fields": {
      "description": "Looks for the database ARN and its resource type in AWS Backup protected resources."
    },
    "remediation_base_sha256": "4c18ae5cd722392e6a87d736626d4fb0935b526b8a684bc436041129f567a644",
    "remediation_fields": {
      "summary": "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database.",
      "steps": [
        "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database."
      ],
      "caveats": [
        "A protected-resource record is not a restore test or proof of current backup freshness.",
        "The record is evidence of a historical AWS Backup recovery point regardless of status; it does not prove the most recent job completed or restore works. A backup plan selection alone does not satisfy this row."
      ]
    },
    "static_observed_sentence": "AWS Backup has no matching protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_protected",
      "predicate_source_sha256": "d493ec68f7cf5578efc6b7d4dfa17d2630b453f5d761be0191580b16df1e6e2f"
    }
  },
  "aws.cb.rds.instance_in_backup_selection_or_tag": {
    "description_base_sha256": "d31a697d377c94ea1a5bf55fda7a850dec1980acdc9b5ed5a22f5f40f71c1a09",
    "description_fields": {
      "description": "Matches the instance ARN or exact tag key and value against collected AWS Backup selections."
    },
    "remediation_base_sha256": "3683fec68087ecfabeb87ac8e2455d68a5711e06122f2843df1d33f908572404",
    "remediation_fields": {
      "summary": "Verify the database\u2019s effective backup selection and tag conditions, then add coverage if needed.",
      "steps": [
        "Verify the database\u2019s effective backup selection and tag conditions, then add coverage if needed."
      ],
      "caveats": [
        "Tag conditions require an exact key and value; unsupported exclusions or conditions remain unknown.",
        "A matching selection does not prove that a backup completed or that recovery works."
      ]
    },
    "static_observed_sentence": "Neither the database ARN nor an exact tag key and value matches a collected backup selection.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_in_plan",
      "predicate_source_sha256": "15833bcb2774d99f9778089de0aaf17f1a1e12c407e33e1bbc9387e7f1bfd4af"
    }
  },
  "aws.cb.rds.aurora_postgres_postgresql_log_export": {
    "description_base_sha256": "e5825296a8b04a4eb23baa5f923e0887860bdfd3209502dfb28742cbd5f7e3a0",
    "description_fields": {
      "description": "Checks whether Aurora PostgreSQL declares the postgresql CloudWatch log export."
    },
    "remediation_base_sha256": "c36050e8758f9c5d4991bb64ff6b42e96b894511f7b0310c2bd28861f9506458",
    "remediation_fields": {
      "summary": "Enable the postgresql log export.",
      "steps": [
        "Enable the postgresql log export."
      ],
      "caveats": [
        "An export declaration does not demonstrate log delivery.",
        "Other engines are NOT_APPLICABLE. A declared postgresql export does not by itself ensure useful server logging or that a CloudWatch log group has correct access and retention."
      ]
    },
    "static_observed_sentence": "The postgresql log export is not configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_pg_logs",
      "predicate_source_sha256": "08be8616366524a735b76a6bb9c0202d0ea909f25355dc44df02303e834fe7c1"
    }
  },
  "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": {
    "description_base_sha256": "7ced129e6503982631d231db8cf2d94d4fcf78cb2ed611f288a0020de52678a5",
    "description_fields": {
      "description": "Checks EnhancedMonitoringResourceArn; db.m1.small is excluded."
    },
    "remediation_base_sha256": "3296cf0e68dea1396c010c7e869482ee6c393508cd0059a77ef7937f5eb4e58f",
    "remediation_fields": {
      "summary": "Configure Enhanced Monitoring if operating-system metrics are required.",
      "steps": [
        "Configure Enhanced Monitoring if operating-system metrics are required."
      ],
      "caveats": [
        "This checks the resource ARN, not monitoring frequency or metric delivery.",
        "db.m1.small is NOT_APPLICABLE under this source. EnhancedMonitoringResourceArn presence alone does not prove current metric delivery, correct retention or a safe monitoring role.",
        "Enabling monitoring grants an IAM role to the service and can add CloudWatch Logs charges. The role name, ARN and interval are operator-reviewed placeholders; do not create or broaden a role from this finding."
      ]
    },
    "static_observed_sentence": "The instance has no Enhanced Monitoring resource ARN.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_em",
      "predicate_source_sha256": "acb9ca081599ab7715f423101819ed7c5ef6d3e53bd00cce82f07bb71d020505"
    }
  },
  "aws.cb.rds.cluster_tls_parameters": {
    "description_base_sha256": "3491d8ed4a1f4281c537e5c8679cb3ac3c1c2284e0012ce4228319be13fe80e4",
    "description_fields": {
      "description": "Checks the engine-appropriate cluster parameter: rds.force_ssl=1 or require_secure_transport=ON/1."
    },
    "remediation_base_sha256": "da4c74693193893af9983540e92d991894f98d3230cc7dac9dba696e1800a939",
    "remediation_fields": {
      "summary": "Enable the engine\u2019s TLS-enforcement parameter and update clients before applying any required restart.",
      "steps": [
        "Enable the engine\u2019s TLS-enforcement parameter and update clients before applying any required restart."
      ],
      "caveats": [
        "Parameter configuration is checked; no TLS handshake is performed.",
        "DocumentDB is NOT_APPLICABLE. The evaluator accepts either parameter independent of engine; the owner must choose the setting supported by the actual engine, not set both blindly. A configured parameter alone does not prove all clients use TLS."
      ]
    },
    "static_observed_sentence": "The engine\u2019s collected TLS-enforcement parameter is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_tls",
      "predicate_source_sha256": "6e2f60be87b1bb648c088733e709b61976165d8942af8d7bd4d60b036008b57f"
    }
  },
  "aws.cb.rds.postgres_force_ssl_parameter": {
    "description_base_sha256": "cffe929310acb32be7ae73eeab112cfcb0cce25b523e1bd3b8518d5d7d13954e",
    "description_fields": {
      "description": "Checks whether the applicable engine parameter rds.force_ssl is 1."
    },
    "remediation_base_sha256": "acf510771774301ddd864fa6506b1cb0e2e8e0f987a96d2d3d3e3e9dc3a5fbd8",
    "remediation_fields": {
      "summary": "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "The parameter value is checked; no network handshake is performed.",
        "The generated PostgreSQL source also names literal Engine=sqlserver, but RDS SQL Server engines use sqlserver-*; this row applies to PostgreSQL in practice. A parameter value alone does not prove connection behavior or client certificate verification; a shared group change can affect other instances."
      ]
    },
    "static_observed_sentence": "The collected rds.force_ssl parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate",
      "predicate_source_sha256": "b013e45921f68f2690411cb46ac335a3b08b8bee244d3035926be57670fa1089"
    }
  },
  "aws.cb.rds.mariadb_require_secure_transport": {
    "description_base_sha256": "b1f989d2e6eff2a5592385616425361e7eb75863bd43e0ef9e6f010041108381",
    "description_fields": {
      "description": "Checks whether the applicable engine parameter require_secure_transport is ON or 1."
    },
    "remediation_base_sha256": "a5007d3cedf9413efd2f41f7f68a866ec5d964dbb5edd0767967be06918becaa",
    "remediation_fields": {
      "summary": "Set require_secure_transport to ON or 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set require_secure_transport to ON or 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "MariaDB applies only from version 10.5; no network handshake is performed.",
        "MariaDB before 10.5 does not support this parameter and is NOT_APPLICABLE. An absent or malformed version/value is UNKNOWN, not a finding that can be cleared by applying a guessed setting.",
        "This check verifies the collected parameter value, not a negotiated TLS session or client certificate verification. A shared group affects other instances; a client unable to establish encrypted transport can lose access."
      ]
    },
    "static_observed_sentence": "The collected require_secure_transport parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate",
      "predicate_source_sha256": "b013e45921f68f2690411cb46ac335a3b08b8bee244d3035926be57670fa1089"
    }
  },
  "aws.cb.rds.sqlserver_force_ssl_parameter": {
    "description_base_sha256": "ab38493febbd12ffa7ef910da05ac3673fc608639c73248a2d2a1be68429b2b2",
    "description_fields": {
      "description": "Checks whether the applicable engine parameter rds.force_ssl is 1."
    },
    "remediation_base_sha256": "83ef254dee0548463041f8b1a2f9db3343ab39ed417172b7dc64398c2d9422d8",
    "remediation_fields": {
      "summary": "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "The parameter value is checked; no network handshake is performed.",
        "Only Engine names beginning sqlserver are applicable. A parameter value alone does not prove connection behavior or client certificate verification; a shared group change can affect other instances."
      ]
    },
    "static_observed_sentence": "The collected rds.force_ssl parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate",
      "predicate_source_sha256": "b013e45921f68f2690411cb46ac335a3b08b8bee244d3035926be57670fa1089"
    }
  },
  "aws.cb.rds.mariadb_log_exports": {
    "description_base_sha256": "55509215fab26e670c25c55e12029ea823dda7b874c69911e995503276c7a248",
    "description_fields": {
      "description": "Checks whether the applicable database exports audit, error, general and slowquery logs."
    },
    "remediation_base_sha256": "44c6259c09251eb9b216b9c3d4d8e63940d7135075eed8e933846e6c64143b30",
    "remediation_fields": {
      "summary": "Enable the missing audit, error, general and slowquery log exports needed for investigation.",
      "steps": [
        "Enable the missing audit, error, general and slowquery log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the mariadb engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required audit, error, general and slowquery logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate",
      "predicate_source_sha256": "1da1746ba510e4b815bb06ca34f2391b9d15a6129d3ff9fcb4a61f3dbf599f87"
    }
  },
  "aws.cb.rds.postgres_log_exports": {
    "description_base_sha256": "69bac9c2f98da9b9d862e2619c273de6eb8ab50a67f66ed234014bcd80433395",
    "description_fields": {
      "description": "Checks whether the applicable database exports postgresql and upgrade logs."
    },
    "remediation_base_sha256": "d805a3ba1a8eeca60b10b9adf8280a6b4fa0199c45ac130dee5051ac14a6afe3",
    "remediation_fields": {
      "summary": "Enable the missing postgresql and upgrade log exports needed for investigation.",
      "steps": [
        "Enable the missing postgresql and upgrade log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the postgres engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required postgresql and upgrade logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate",
      "predicate_source_sha256": "1da1746ba510e4b815bb06ca34f2391b9d15a6129d3ff9fcb4a61f3dbf599f87"
    }
  },
  "aws.cb.rds.sqlserver_error_log_export": {
    "description_base_sha256": "d27f43f3fe78c79ef3e86ef8d3c0cce135500afd0b4a375a791ea9baea499449",
    "description_fields": {
      "description": "Checks whether the applicable database exports error logs."
    },
    "remediation_base_sha256": "f127169da824b685b3f4f9d90093a70effe07662e405cf54b84622b23c5d70b3",
    "remediation_fields": {
      "summary": "Enable the missing error log exports needed for investigation.",
      "steps": [
        "Enable the missing error log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the sqlserver-ee engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required error logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate",
      "predicate_source_sha256": "1da1746ba510e4b815bb06ca34f2391b9d15a6129d3ff9fcb4a61f3dbf599f87"
    }
  },
  "aws.cb.rds.aurora_postgres_local_file_read_versions": {
    "description_base_sha256": "d5905527ec9573903bd091bdff3c92bd5cd6c4a3dd236dce5c3a1111be7119ff",
    "description_fields": {
      "description": "Matches EngineVersion against the profile\u2019s affected versions: 10.11\u201310.13 and 11.6\u201311.8."
    },
    "remediation_base_sha256": "b2a162f9e46890b2fab2035319fdbe6b99c5d20b006ebc8bacda63026e30acf1",
    "remediation_fields": {
      "summary": "Upgrade to a supported release after checking compatibility and the relevant security advisory.",
      "steps": [
        "Upgrade to a supported release after checking compatibility and the relevant security advisory."
      ],
      "caveats": [
        "A version outside this finite list is not a general vulnerability assessment.",
        "The upstream label says DB cluster, but this native evaluator reads rds_instance rows; Aurora engine upgrades are cluster operations. A nonmatching EngineVersion is not proof of current patching. Major upgrades may require application changes and downtime."
      ]
    },
    "static_observed_sentence": "The database version matches this profile\u2019s known affected-version list.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_vuln.<locals>.evaluate",
      "predicate_source_sha256": "bbbe68a1e2ebac95efb71e16a8efafe9ee42e39c2785919cbd64ac400d8990ba"
    }
  },
  "aws.cb.rds.postgres_local_file_read_versions": {
    "description_base_sha256": "1c960a610d0c1d89642b52b310b8a01bd94091176b0de2510615548455143c82",
    "description_fields": {
      "description": "Matches EngineVersion against the profile\u2019s affected versions: 10.11\u201310.13 and 11.6\u201311.8."
    },
    "remediation_base_sha256": "8621f6f2763804aa5e1f201bb8adec9ea73398a81ec69d8d9fb3be6683a12718",
    "remediation_fields": {
      "summary": "Upgrade to a supported release after checking compatibility and the relevant security advisory.",
      "steps": [
        "Upgrade to a supported release after checking compatibility and the relevant security advisory."
      ],
      "caveats": [
        "A version outside this finite list is not a general vulnerability assessment.",
        "The predicate is exact string equality against six historic versions, not a general vulnerability feed or support-policy check. A nonmatching EngineVersion is not proof of current patching. Major upgrades may require application changes and downtime."
      ]
    },
    "static_observed_sentence": "The database version matches this profile\u2019s known affected-version list.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_vuln.<locals>.evaluate",
      "predicate_source_sha256": "bbbe68a1e2ebac95efb71e16a8efafe9ee42e39c2785919cbd64ac400d8990ba"
    }
  },
  "aws.cb.rds.instance_backup_retention_nonzero_all": {
    "description_base_sha256": "023f22e7319b72c87d1b001a3d090f1c466109e948dc785fe99516ee86fd3091",
    "description_fields": {
      "description": "Checks whether automated backup retention is at least one day."
    },
    "remediation_base_sha256": "a37e90418b08801c71115ab742eaabefbf6b56badbd5f060efb69cebb1146dd4",
    "remediation_fields": {
      "summary": "Configure an automated backup retention period suitable for recovery.",
      "steps": [
        "Configure an automated backup retention period suitable for recovery."
      ]
    },
    "static_observed_sentence": "Automated backup retention is zero days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_backup",
      "predicate_source_sha256": "cba4e70db21dd420394dd5f8539bf5a58fa65d2801641e2e6d62d6e25caf5c5f"
    }
  },
  "aws.cb.rds.instance_copy_tags_all_engines": {
    "description_base_sha256": "343e1144bb3f1749366251e331b98859df63d74be5394a0cadd25a2989ea6c4e",
    "description_fields": {
      "description": "Checks CopyTagsToSnapshot on the instance."
    },
    "remediation_base_sha256": "30e935f2ccc6be46848377b4a857131e77c7b3ed43ef019dd08e80f2256df42c",
    "remediation_fields": {
      "summary": "Enable copying tags to snapshots if these tags are needed for ownership or lifecycle management.",
      "steps": [
        "Enable copying tags to snapshots if these tags are needed for ownership or lifecycle management."
      ]
    },
    "static_observed_sentence": "Copying instance tags to snapshots is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_copy_tags",
      "predicate_source_sha256": "16297d138180de75b270ed33c28c542fa34d12b1bbf738dc2a8e61cfa8a7d0cb"
    }
  },
  "aws.cb.rds.instance_iam_auth_supported_engines": {
    "description_base_sha256": "272f87d78aa988c94408de88d5b0ee1926e9861391727a03800acf90a907fcb1",
    "description_fields": {
      "description": "Checks IAM database authentication on MySQL, MariaDB and PostgreSQL instances."
    },
    "remediation_base_sha256": "1b52789f58083a58ed57aa37156ebc22b0bcd436d777dbab4f79dbfb810e6540",
    "remediation_fields": {
      "summary": "Consider enabling IAM database authentication if it suits the application\u2019s connection model.",
      "steps": [
        "Consider enabling IAM database authentication if it suits the application\u2019s connection model."
      ],
      "caveats": [
        "This is an authentication-option preference; it does not prove that existing database credentials are weak.",
        "Unsupported engines are not applicable here. Enabling IAM authentication does not automatically create database users or change existing password logins; cluster members require the cluster-level operation. Token expiry and connection pooling need application review."
      ]
    },
    "static_observed_sentence": "IAM database authentication is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_iam_supported",
      "predicate_source_sha256": "d6d7f3f516ba66b7081e99c85f023c3d039e3ee1e85d07891dd61e9fa993726a"
    }
  },
  "aws.cb.rds.instance_default_master_username": {
    "description_base_sha256": "ec41f3981fb650da57e2f4dcda27b02bce4313e002d2d06a50a3af9c13aaa6be",
    "description_fields": {
      "description": "Checks whether the instance or resolved cluster uses master username admin or postgres."
    },
    "remediation_base_sha256": "10ceee3fb7db3b45f83fc132326c282f2c5651922e92b288ad23cda4f2d8f931",
    "remediation_fields": {
      "summary": "Review master-account use and restrict its access; a familiar username alone does not justify database replacement.",
      "steps": [
        "Review master-account use and restrict its access; a familiar username alone does not justify database replacement."
      ],
      "caveats": [
        "A default username does not demonstrate a default or compromised password.",
        "MasterUsername cannot be changed on an existing RDS instance or cluster through a simple modify flag; a new deployment and data migration are required. A missing cluster join fails this source even when the actual username may be safe; confirm inventory completeness first."
      ]
    },
    "static_observed_sentence": "The master username matches this profile\u2019s default-name list.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_admin",
      "predicate_source_sha256": "0fd2fed40de5b320752336ed89671363abfd4cd2d77c8f1e7b57a43b5f5e3ebb"
    }
  },
  "aws.cb.rds.instance_multi_az_or_cluster": {
    "description_base_sha256": "44603ebb2e235d99ea19b41501e98dd130b9ec2ba030fb564f8129b41a6d8aa9",
    "description_fields": {
      "description": "Checks MultiAZ on the applicable instance or its resolved parent cluster."
    },
    "remediation_base_sha256": "8a70de13231e77ad8004573fc8c40ce4c24ceb8f14c420736287db9f6c32cf51",
    "remediation_fields": {
      "summary": "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage.",
      "steps": [
        "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage."
      ],
      "caveats": [
        "A zonal availability preference; not evidence of unauthorized access.",
        "DocumentDB is not applicable. A missing referenced cluster fails until inventory is resolved; blindly modifying the instance may not fix a cluster-level MultiAZ value. Multi-AZ can increase cost and change failover behavior."
      ]
    },
    "static_observed_sentence": "Multi-AZ is not enabled in the evaluated database configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_multi",
      "predicate_source_sha256": "689f101f8bf6bbea504601e7d36065e5390ce30088505c382dd0325234291259"
    }
  },
  "aws.cb.rds.instance_multi_az_non_aurora": {
    "description_base_sha256": "e1b3789761a8f363b857d7fdf6364190559b37df076fff6b9f83d91ada8a9f1b",
    "description_fields": {
      "description": "Checks MultiAZ on the applicable instance or its resolved parent cluster."
    },
    "remediation_base_sha256": "8d1d981a6cc93f396a4b3d5e4261249163d0efc90255d01cc68433fb8f56cb3c",
    "remediation_fields": {
      "summary": "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage.",
      "steps": [
        "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage."
      ],
      "caveats": [
        "A zonal availability preference; not evidence of unauthorized access.",
        "Aurora engines are not applicable to this branch. Multi-AZ adds a standby and can cause a brief outage during conversion or failover; it does not replace backups or cross-Region recovery."
      ]
    },
    "static_observed_sentence": "Multi-AZ is not enabled in the evaluated database configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_multi_c",
      "predicate_source_sha256": "ef713881da9ac69940de61658d57f1936701198eed981ab9a13d0e6b0596f87a"
    }
  },
  "aws.cb.rds.instance_extended_support": {
    "description_base_sha256": "6537ef452a8d62bf0a47746b4652eec3c1469f5349a445a2b2f1fde862807a98",
    "description_fields": {
      "description": "Checks whether EngineLifecycleSupport selects open-source-rds-extended-support."
    },
    "remediation_base_sha256": "d345ba168de8431aae51189dbf6e3855e5961a887800dcda19479e19defaa435",
    "remediation_fields": {
      "summary": "Plan a compatible upgrade if Extended Support is no longer needed.",
      "steps": [
        "Plan a compatible upgrade if Extended Support is no longer needed."
      ],
      "caveats": [
        "Extended Support enrollment does not mean that security patches are unavailable.",
        "Extended Support keeps older open-source engines available for a fee; disabling it before a supported upgrade can be rejected or disrupt availability. The source only checks the string value, not whether a future major version is operationally compatible."
      ]
    },
    "static_observed_sentence": "The database is enrolled in RDS Extended Support.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_extended",
      "predicate_source_sha256": "96471daef0a6d1534cd14377e72c9da839f79776ce204c41e18541825c6ed15c"
    }
  },
  "aws.cb.rds.ca_certificate_valid_3_months": {
    "description_base_sha256": "17bd4eca2820eb57880acb8eb4eeb82c3f1b4ecbb34a24233ed420bdbebab0cb",
    "description_fields": {
      "description": "Compares the joined CA certificate expiry with collection time plus three calendar months."
    },
    "remediation_base_sha256": "2edaae89ee4127262c0ae44e337805de9dcb3569f868d436f93a54581238ebcd",
    "remediation_fields": {
      "summary": "Plan a CA rotation and update client trust stores before expiry.",
      "steps": [
        "Plan a CA rotation and update client trust stores before expiry."
      ],
      "caveats": [
        "This evaluates the CA metadata, not the leaf certificate served by the database endpoint.",
        "DocumentDB is not applicable. The source joins CACertificateIdentifier to one collected rds_certificate and returns UNKNOWN if unresolved; exactly three calendar months remaining still fails. Client trust stores must be updated before rotation. Some engine versions support rotation without restart while others need a restart; do not assume either behavior without checking the instance capabilities."
      ]
    },
    "static_observed_sentence": "The collected RDS CA certificate expires within the required window or has expired.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "ca_three_months",
      "predicate_source_sha256": "f743b451d9127abcec07721f1fb3e3b990a35b2d24fbf4e68e86b76614af4ee4"
    }
  },
  "aws.cb.rds.ca_certificate_not_expiring_7_days": {
    "description_base_sha256": "c74a28199c24178da08275df5e7bfe70c6e6daf3712cd7da54895dae454ea16c",
    "description_fields": {
      "description": "Compares the joined CA certificate expiry with collection time plus seven days."
    },
    "remediation_base_sha256": "239ec519eb2fce7f3b22cf124bcca1277851a315a9df84aae1fb55b238f6a42f",
    "remediation_fields": {
      "summary": "Plan a CA rotation and update client trust stores before expiry.",
      "steps": [
        "Plan a CA rotation and update client trust stores before expiry."
      ],
      "caveats": [
        "This evaluates the CA metadata, not the leaf certificate served by the database endpoint.",
        "This check includes every engine and truncates the day component of the expiry delta; a certificate close to eight days can enter the seven-day band. Missing certificate join is UNKNOWN, not proof of expiry. Some engine versions support rotation without restart while others need a restart; do not assume either behavior without checking the instance capabilities."
      ]
    },
    "static_observed_sentence": "The collected RDS CA certificate expires within the required window or has expired.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "ca_seven",
      "predicate_source_sha256": "68cb3f9cdca98f782b58192768cb156716695936dfdb5981990276ad479c6254"
    }
  },
  "aws.cb.rds.engine_version_available": {
    "description_base_sha256": "6257717f96877995b8a2b009046cde8cfc06baedd6bf189abe8a98b399622f74",
    "description_fields": {
      "description": "Looks for the database\u2019s exact engine/version pair in collected RDS engine-version inventory."
    },
    "remediation_base_sha256": "9c626b22247f080bead40ce5fc215cbca594bcffb8075affc6c1e479a089af57",
    "remediation_fields": {
      "summary": "Review the engine\u2019s support status and plan a supported compatible upgrade if needed.",
      "steps": [
        "Review the engine\u2019s support status and plan a supported compatible upgrade if needed."
      ],
      "caveats": [
        "Being offered by the API is not proof that an engine version has no vulnerabilities.",
        "DocumentDB is not applicable. Absence from offered versions does not identify an automatically safe target or prove the engine is exploitable; a major upgrade may require intermediate versions and downtime."
      ]
    },
    "static_observed_sentence": "The engine/version pair is absent from collected RDS engine-version inventory.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "engine_version",
      "predicate_source_sha256": "80db15ad50ac2513c6587228b20abf6f849ffa4b25132aa15b7b7c67b8c77d25"
    }
  },
  "aws.cb.rds.instance_internet_exposed": {
    "description_base_sha256": "fc0879719a62b9b9ff48a16a73d98f73ca0478a31b6d0c95af2aba168c17c0a4",
    "description_fields": {
      "description": "Combines PubliclyAccessible, active security-group access to the TCP endpoint port and a DB subnet\u2019s Internet-gateway default route."
    },
    "remediation_base_sha256": "54b8c29d87424f9f48109e1bcf6b796a28415f6535c26a016d490eb487412117",
    "remediation_fields": {
      "summary": "Remove Internet-wide ingress to the database port; retain only the networks that need database access.",
      "steps": [
        "Remove Internet-wide ingress to the database port; retain only the networks that need database access."
      ],
      "caveats": [
        "This is a configuration-path model; no connection or authentication attempt is made.",
        "DocumentDB is not applicable. This native conjunction can pass a publicly accessible instance when no matching open SG or public subnet is collected; that PASS is not a blanket internet-exposure guarantee. Disabling public access before clients migrate can cause an outage."
      ]
    },
    "static_observed_sentence": "The declared public database configuration includes Internet-wide ingress to its endpoint port.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_exposed",
      "predicate_source_sha256": "17b2fadb88536bad21dfb4c8cffd8e017fd3c62ebdfef70bc0291a5404ade3a1"
    }
  },
  "aws.cb.rds.instance_snapshot_restore_not_all_exact": {
    "description_base_sha256": "229d1f813c385e9076c126e8b7e7c62b7b4576956c5302bb37f96b7db122478a",
    "description_fields": {
      "description": "Checks whether the snapshot\u2019s restore attribute includes the public principal all."
    },
    "remediation_base_sha256": "d8b9b97640fdc1d2e8e265b5c9a9d788ef8de0d40f0bbe58fd4da78ae3e9c0b0",
    "remediation_fields": {
      "summary": "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access.",
      "steps": [
        "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access."
      ]
    },
    "static_observed_sentence": "The snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.exact",
      "predicate_source_sha256": "9c3639600864d0ca0293210e5e60ed881b1dfcf8f182db5d4c44daa5737b2b53"
    }
  },
  "aws.cb.rds.instance_snapshot_not_public_prowler": {
    "description_base_sha256": "d08208edf1f088f8b41e6e0a779895aaa94ad6b962ec9578c2c0aefcbee61ec4",
    "description_fields": {
      "description": "Checks whether any collected snapshot attribute contains the public value all."
    },
    "remediation_base_sha256": "b7cefb9e97773eeb3986df44cd168236678278e0949a9465676c7d5240e3c9e7",
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot attributes."
      ],
      "caveats": [
        "This profile inspects every attribute, rather than only the restore attribute.",
        "DocumentDB snapshots are not applicable. This branch detects all even when other account IDs share the same list; removing all preserves named shares but still needs consumer review."
      ]
    },
    "static_observed_sentence": "A snapshot attribute contains the public sharing value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.prowler_public",
      "predicate_source_sha256": "022e9444e49fd3e4caffda51540f6eaf9f4c1f906c0098b0a44d3601b0e63f14"
    }
  },
  "aws.cb.rds.instance_snapshot_shared_accounts_review": {
    "description_base_sha256": "86d2c9962f458b63300a8a20c435a098cf4cdacbb126285dd697f21a645c91ef",
    "description_fields": {
      "description": "Lists snapshot share accounts for manual trust review; no automatic failing verdict is defined."
    },
    "remediation_base_sha256": "d19b65fc9e735318740ebbf4c2f2177efb70be1b5712fe7c735ba415db54e31b",
    "remediation_fields": {
      "summary": "Review snapshot sharing only through an explicitly configured organizational approval process.",
      "steps": [
        "Review snapshot sharing only through an explicitly configured organizational approval process."
      ],
      "caveats": [
        "Archived: deciding whether another account is trusted requires a customer-approved list.",
        "This native branch returns MANUAL for any share value and PASS only for no values; it cannot decide whether a named recipient account is trusted. Do not remove an approved recovery share solely to obtain PASS."
      ]
    },
    "static_observed_sentence": "The snapshot is shared with another account.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.shared",
      "predicate_source_sha256": "feca073d9c4727906b9300d67edbd9f664c44cdc4eb0ca68b3ed90a01acff36e"
    }
  },
  "aws.cb.rds.cluster_snapshot_restore_not_all_exact": {
    "description_base_sha256": "eea54f328fa77afe719c9298bbc14919ba47ce5e2b51b86cf77db1edc22da839",
    "description_fields": {
      "description": "Checks whether the snapshot\u2019s restore attribute includes the public principal all."
    },
    "remediation_base_sha256": "cb0b239c3f0e1e550d257b0dfc998a2be993d333666d589828dc10759d5288fb",
    "remediation_fields": {
      "summary": "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access.",
      "steps": [
        "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access."
      ]
    },
    "static_observed_sentence": "The snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.exact",
      "predicate_source_sha256": "9c3639600864d0ca0293210e5e60ed881b1dfcf8f182db5d4c44daa5737b2b53"
    }
  },
  "aws.cb.rds.cluster_snapshot_not_public_prowler": {
    "description_base_sha256": "378d1b595f46f958a22341a8f46a94994f951ca234a0349e3d26aed0c23b5a8e",
    "description_fields": {
      "description": "Checks whether any collected snapshot attribute contains the public value all."
    },
    "remediation_base_sha256": "b4ba79986869c49ded43a8c71d065c6da90027d3b62b479727fc0c01b0f445f4",
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot attributes."
      ],
      "caveats": [
        "This profile inspects every attribute, rather than only the restore attribute.",
        "DocumentDB snapshots are not applicable. This branch detects all even when other account IDs share the same list; removing all preserves named shares but still needs consumer review."
      ]
    },
    "static_observed_sentence": "A snapshot attribute contains the public sharing value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.prowler_public",
      "predicate_source_sha256": "022e9444e49fd3e4caffda51540f6eaf9f4c1f906c0098b0a44d3601b0e63f14"
    }
  },
  "aws.cb.rds.cluster_snapshot_shared_accounts_review": {
    "description_base_sha256": "4f6ec028e519135364c78abce23837ec04210061bd6e6b8dc8e7eaefe2092f66",
    "description_fields": {
      "description": "Lists snapshot share accounts for manual trust review; no automatic failing verdict is defined."
    },
    "remediation_base_sha256": "45e1b6c8d18fb405f7af7b7ddab153b4aef6ddd8a6445faf8dae1799bbc2a891",
    "remediation_fields": {
      "summary": "Review snapshot sharing only through an explicitly configured organizational approval process.",
      "steps": [
        "Review snapshot sharing only through an explicitly configured organizational approval process."
      ],
      "caveats": [
        "Archived: deciding whether another account is trusted requires a customer-approved list.",
        "This native branch returns MANUAL for any share value and PASS only for no values; it cannot decide whether a named recipient account is trusted. Do not remove an approved recovery share solely to obtain PASS."
      ]
    },
    "static_observed_sentence": "The snapshot is shared with another account.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.shared",
      "predicate_source_sha256": "feca073d9c4727906b9300d67edbd9f664c44cdc4eb0ca68b3ed90a01acff36e"
    }
  },
  "aws.cb.rds.cluster_snapshot_encrypted": {
    "description_base_sha256": "0bf9ba10bc0576aed4e0a4cc2901591f4611a802e9afb9036b12abe0610dde5b",
    "description_fields": {
      "description": "Checks StorageEncrypted on non-DocumentDB cluster snapshots."
    },
    "remediation_base_sha256": "db0560b7f2d214fb60cd02a3b18ac4b7d355447fefd48b345debe86ca44e6ea7",
    "remediation_fields": {
      "summary": "Create and verify an encrypted snapshot copy before removing any unencrypted recovery copy.",
      "steps": [
        "Create and verify an encrypted snapshot copy before removing any unencrypted recovery copy."
      ],
      "caveats": [
        "Keep a recoverable copy until the encrypted replacement has been verified.",
        "Snapshot encryption is immutable for the existing snapshot; copying creates a new resource and does not convert the original finding. DocumentDB is not applicable. Deleting the old copy before KMS and restore validation can destroy recovery capability."
      ]
    },
    "static_observed_sentence": "The cluster snapshot is not encrypted.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "csnap_encrypted",
      "predicate_source_sha256": "1b59d28292b2f2465ec0ab1245ff56c264afec05eaea556dc2cbaa29cca5c2f9"
    }
  },
  "aws.cb.rds.cluster_critical_event_subscription": {
    "description_base_sha256": "c584ba7235beb0cc219c39cf9783c6b91fa1b07dace472e4548aa7c65cd6e3b3",
    "description_fields": {
      "description": "Looks for an enabled regional db-cluster subscription covering failure and maintenance."
    },
    "remediation_base_sha256": "a6db6d1608c3ff11b5ec0d6222fd1b212e96537f8545d2099668f0516eb5ecd8",
    "remediation_fields": {
      "summary": "Configure an enabled db-cluster event subscription for failure and maintenance and its notification destination.",
      "steps": [
        "Configure an enabled db-cluster event subscription for failure and maintenance and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-cluster subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_cluster resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-cluster subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate",
      "predicate_source_sha256": "0a447dad37d9fd2f4da368b1e63b2160c57944b06d2c82847414eda6aaf49e54"
    }
  },
  "aws.cb.rds.instance_critical_event_subscription": {
    "description_base_sha256": "6b3df41da2416e0b3e51640eaddcbf9b2d04131ab628d833738acd6677330fe9",
    "description_fields": {
      "description": "Looks for an enabled regional db-instance subscription covering configuration change, failure and maintenance."
    },
    "remediation_base_sha256": "d96df0dbcdb1c7e14a4a7abe9da46125836c6a154a36553fe0fa7e5beab4595c",
    "remediation_fields": {
      "summary": "Configure an enabled db-instance event subscription for configuration change, failure and maintenance and its notification destination.",
      "steps": [
        "Configure an enabled db-instance event subscription for configuration change, failure and maintenance and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-instance subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-instance subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate",
      "predicate_source_sha256": "0a447dad37d9fd2f4da368b1e63b2160c57944b06d2c82847414eda6aaf49e54"
    }
  },
  "aws.cb.rds.parameter_group_critical_event_subscription": {
    "description_base_sha256": "073659ea673455c219f393101e5491612ff6e049b601ce1eaa94a94448e3c5b6",
    "description_fields": {
      "description": "Looks for an enabled regional db-parameter-group subscription covering configuration change."
    },
    "remediation_base_sha256": "a4651d4cdd197d6327c854ffb9d5b064000b58ca28e1ae9a2689b011c188761e",
    "remediation_fields": {
      "summary": "Configure an enabled db-parameter-group event subscription for configuration change and its notification destination.",
      "steps": [
        "Configure an enabled db-parameter-group event subscription for configuration change and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-parameter-group subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-parameter-group subscription covers the required event categories.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate",
      "predicate_source_sha256": "0a447dad37d9fd2f4da368b1e63b2160c57944b06d2c82847414eda6aaf49e54"
    }
  },
  "aws.cb.rds.security_group_critical_event_subscription": {
    "description_base_sha256": "03e9bf852596de18143109266ec6d3688ba0c52cd60a9f08027f9a5054bed782",
    "description_fields": {
      "description": "Looks for an enabled regional db-security-group subscription covering configuration change and failure."
    },
    "remediation_base_sha256": "873a3e041e8001a8ba4c4877ef990ee9082c2122414c4193eb122eaffc8ba7f0",
    "remediation_fields": {
      "summary": "Configure an enabled db-security-group event subscription for configuration change and failure and its notification destination.",
      "steps": [
        "Configure an enabled db-security-group event subscription for configuration change and failure and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-security-group subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-security-group subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate",
      "predicate_source_sha256": "0a447dad37d9fd2f4da368b1e63b2160c57944b06d2c82847414eda6aaf49e54"
    }
  },
  "aws.cb.neptune.backup_retention_7_days": {
    "description_base_sha256": "7fe4d779ec1fd537765be5d1f8d8af016600080e16b86ae3f92be47db6196321",
    "description_fields": {
      "description": "Checks whether Neptune backup retention is at least seven days."
    },
    "remediation_base_sha256": "dd5c8c0ea7834a5df67c3b3780062555cb708290dfcc42e917f116ec92c51694",
    "remediation_fields": {
      "summary": "Set backup retention to at least seven days if it meets the workload\u2019s recovery needs.",
      "steps": [
        "Set backup retention to at least seven days if it meets the workload\u2019s recovery needs."
      ]
    },
    "static_observed_sentence": "Neptune backup retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "nep_backup",
      "predicate_source_sha256": "64226878e95f388c06996da96b3fc68a34ff8d4ee9c64ae1130028e7a43166ac"
    }
  },
  "aws.cb.neptune.audit_log_export": {
    "description_base_sha256": "b592086ede5db87dcb30bc21d752153e50e8451c477062cdd1d03bcdb6082e76",
    "description_fields": {
      "description": "Checks whether the Neptune cluster declares the audit CloudWatch log export."
    },
    "remediation_base_sha256": "bf451beb6030912aa643ac9f4736627bd6b65a622b7b4e23e00e5c156b650753",
    "remediation_fields": {
      "summary": "Enable the audit log export and the corresponding database audit setting.",
      "steps": [
        "Enable the audit log export and the corresponding database audit setting."
      ],
      "caveats": [
        "The predicate checks the export declaration only, not audit generation or delivery.",
        "Other DB cluster engines are not applicable. The check sees only the export list; audit events also require neptune_enable_audit_log and a working log group. A shared parameter group change may affect other clusters or require a reboot."
      ]
    },
    "static_observed_sentence": "The Neptune audit log export is not configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "nep_audit",
      "predicate_source_sha256": "21119058e6b31a8e33ac1c1a5f6d41aa79ddb639094b1c3424e046f5e1613f5b"
    }
  },
  "aws.cb.neptune.snapshot_encrypted": {
    "description_base_sha256": "b3ff6954e40070377c35eb7d631e29d9091d7c28a6cdcdb4454e072f25aa7cc4",
    "description_fields": {
      "description": "Checks StorageEncrypted on Neptune cluster snapshots."
    },
    "remediation_base_sha256": "6d0bb697ecf41edc9a0564177090cf2421add1db19a15b26dfb56b7d8fac9c06",
    "remediation_fields": {
      "summary": "Create and verify an encrypted snapshot copy before removing an unencrypted recovery copy.",
      "steps": [
        "Create and verify an encrypted snapshot copy before removing an unencrypted recovery copy."
      ]
    },
    "static_observed_sentence": "The Neptune snapshot is not encrypted.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_enc",
      "predicate_source_sha256": "937805b13995ff8b08e1b165273c8a304148e04a9afa6a24252aca24cce86da5"
    }
  },
  "aws.cb.neptune.snapshot_not_public_prowler": {
    "description_base_sha256": "45a259424e0c76ccef5495c093d2331f356b0d4cf677d29e663e30c747216e17",
    "description_fields": {
      "description": "Checks whether any Neptune snapshot attribute includes all."
    },
    "remediation_base_sha256": "d0ae4ccade326d274dfbac50f6869126282df2264fb82f1fb92769aa6693d812",
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot\u2019s restore attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot\u2019s restore attributes."
      ]
    },
    "static_observed_sentence": "A Neptune snapshot attribute includes the public value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_public",
      "predicate_source_sha256": "072a74bd0cb9bac6e8340e074d5f850156901d1fb31b10298f2b8153a65e5d8f"
    }
  },
  "aws.cb.neptune.snapshot_restore_not_all_exact": {
    "description_base_sha256": "78e5dc17bbb6efe9a2c4f94a896e297ad8aa7f38a6d22e83fcbe44bd4e803d48",
    "description_fields": {
      "description": "Checks whether the Neptune snapshot restore attribute includes all."
    },
    "remediation_base_sha256": "3a46d4ab931489e8a4b9476c2a22fe353a674663b965a33693471d71e01f3b25",
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot\u2019s restore attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot\u2019s restore attributes."
      ]
    },
    "static_observed_sentence": "The Neptune snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_exact",
      "predicate_source_sha256": "569f9430ce219d1fb57d1bca99c38eac4f737888cc1946141a627c2561098c76"
    }
  },
  "aws.cb.neptune.no_public_subnet_prowler": {
    "description_base_sha256": "6fed40eab2e9d97d0afd317fdbc93fc69e4d46845c4439d00a7365e1b60bf869",
    "description_fields": {
      "description": "Resolves DB subnets and their effective IPv4 default routes to an Internet gateway."
    },
    "remediation_base_sha256": "4a572ac608dab1001e3bc807f9745e36538ac0ffc95745bcf7adea91182f1fe7",
    "remediation_fields": {
      "summary": "Use database subnets without an Internet-gateway default route if public routing is unnecessary.",
      "steps": [
        "Use database subnets without an Internet-gateway default route if public routing is unnecessary."
      ],
      "caveats": [
        "NAT-only egress is not public ingress; routes alone do not demonstrate database reachability.",
        "The source detects an IGW default route only; it does not prove the Neptune endpoint is publicly reachable through security groups or authentication. DBSubnetGroup is absent from ModifyDBCluster, so changing the cluster placement requires replacement and endpoint migration. An unresolved route-table join is UNKNOWN."
      ]
    },
    "static_observed_sentence": "A Neptune DB subnet has an Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "_nep_subnet.<locals>.evaluate",
      "predicate_source_sha256": "1bcf4eb37cebe43add97db9237f99047337b8e774236b0b7807bdd68aa755d8a"
    }
  },
  "aws.cb.neptune.no_public_subnet_steampipe": {
    "description_base_sha256": "1546ee6c21761162c3175eed06ea75c69c207cdb0b63a3e9ff72d76c6619056d",
    "description_fields": {
      "description": "Resolves DB subnets and their effective IPv4 default routes to an Internet gateway."
    },
    "remediation_base_sha256": "080b6dfb276bf1da78c3c8ee8fc2f66fa5ec510385221ff8bfb991abf55b6b31",
    "remediation_fields": {
      "summary": "Use database subnets without an Internet-gateway default route if public routing is unnecessary.",
      "steps": [
        "Use database subnets without an Internet-gateway default route if public routing is unnecessary."
      ],
      "caveats": [
        "NAT-only egress is not public ingress; routes alone do not demonstrate database reachability.",
        "The source detects an IGW default route only; it does not prove the Neptune endpoint is publicly reachable through security groups or authentication. DBSubnetGroup is absent from ModifyDBCluster, so changing the cluster placement requires replacement and endpoint migration. An unresolved route-table join is UNKNOWN. The pinned Steampipe text also treated outbound NAT as public; this native check correctly tests an ingress-capable IGW route instead."
      ]
    },
    "static_observed_sentence": "A Neptune DB subnet has an Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "_nep_subnet.<locals>.evaluate",
      "predicate_source_sha256": "1bcf4eb37cebe43add97db9237f99047337b8e774236b0b7807bdd68aa755d8a"
    }
  },
  "aws.cb.redshift.non_default_master_username": {
    "description_base_sha256": "9b1cd471e676304602faf544e50a58ac4c0f4d94634e2d6d49d762f625d1a456",
    "description_fields": {
      "description": "Compares MasterUsername with the profile\u2019s default name awsuser."
    },
    "remediation_base_sha256": "c293c51d77c754378c6272158f737aed39e7297a11036f879537f91ca93f82eb",
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "ModifyCluster has no MasterUsername field; an in-place flag would be invalid. Replacement and credential migration can interrupt authentication, so no deletion or automatic cutover command is offered."
      ]
    },
    "static_observed_sentence": "MasterUsername uses the default name awsuser.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "_not_default.<locals>.evaluate",
      "predicate_source_sha256": "38c5c94257960038e5430dce8ccef0a8b1760e392acac1a6d72d2c324b79e8a8"
    }
  },
  "aws.cb.redshift.non_default_database_name": {
    "description_base_sha256": "3d8326d2a7257502a511e01457df6bb18822752d2920404db081c1d9022bb3b4",
    "description_fields": {
      "description": "Compares DBName with the profile\u2019s default name dev."
    },
    "remediation_base_sha256": "2657a70e5b09174a53acbd7f3fabb5269cf285b9149f693d5601aed9ccb6fd71",
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "ModifyCluster has no DBName field, so an in-place cluster setting command would be invalid. SQL-level database renames may not change the cluster metadata field this predicate reads."
      ]
    },
    "static_observed_sentence": "DBName uses the default name dev.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "_not_default.<locals>.evaluate",
      "predicate_source_sha256": "38c5c94257960038e5430dce8ccef0a8b1760e392acac1a6d72d2c324b79e8a8"
    }
  },
  "aws.cb.redshiftserverless.non_default_admin_username": {
    "description_base_sha256": "f12779d086006a0086ec087636e81831c4a369e4a2b8353a8a9aa45301c58eb6",
    "description_fields": {
      "description": "Compares adminUsername with the profile\u2019s default name admin."
    },
    "remediation_base_sha256": "535587b8ec39896c440f640671c1a7c571885f24abb2f4f0097ee81bc58607f8",
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "Changing the username can break clients and secret references; coordinate the credential rotation and connection cutover. The check compares only the literal admin and does not assess password strength or IAM access."
      ]
    },
    "static_observed_sentence": "adminUsername uses the default name admin.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "_ns.<locals>.evaluate",
      "predicate_source_sha256": "9420a069c3dcdc6ee1b2aae85ce00b0e29fceed97f5d4e347ebca4123002f857"
    }
  },
  "aws.cb.redshiftserverless.non_default_database_name": {
    "description_base_sha256": "e30ab598dc349fbd09efc41957168cea3aad1092b3c8d7a26fd4917aed83ab28",
    "description_fields": {
      "description": "Compares dbName with the profile\u2019s default name dev."
    },
    "remediation_base_sha256": "0af60e526cb5535f099fd9306f8e5da8fd35b9216a416edaedb5974edc6de581",
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "dbName is a CreateNamespace field but absent from UpdateNamespace; no in-place rename flag is offered for this check. Replacement can interrupt clients and incur data migration cost; a separate SQL database rename would not necessarily change the namespace dbName field."
      ]
    },
    "static_observed_sentence": "dbName uses the default name dev.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "_ns.<locals>.evaluate",
      "predicate_source_sha256": "9420a069c3dcdc6ee1b2aae85ce00b0e29fceed97f5d4e347ebca4123002f857"
    }
  },
  "aws.cb.redshift.audit_logging": {
    "description_base_sha256": "9a4b2ae41d3a4b0f32393c1b9ea57d891a1bb5564ddd64700de02756a2d787e5",
    "description_fields": {
      "description": "Checks the collected Redshift LoggingEnabled setting."
    },
    "remediation_base_sha256": "030b340efa8d445b9f3b0cb94468067aaf61d99280d59651a4c188840a36d73b",
    "remediation_fields": {
      "summary": "Enable Redshift audit logging and configure its destination.",
      "steps": [
        "Enable Redshift audit logging and configure its destination."
      ],
      "caveats": [
        "The setting does not demonstrate log delivery.",
        "The check reads LoggingStatus.LoggingEnabled only and does not prove log delivery or user-activity content. User activity events additionally require enable_user_activity_logging=true in the cluster parameter group."
      ]
    },
    "static_observed_sentence": "Redshift audit logging is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_logging",
      "predicate_source_sha256": "d7deb5f1688bb0b92885dfc433afe0cb4ad22454568054b06422db904f754f65"
    }
  },
  "aws.cb.redshift.encrypted_and_logging": {
    "description_base_sha256": "0cf4069d02a6cf8338c2db45f6feb83648c66b858dac48875c0d77dcc2c570b9",
    "description_fields": {
      "description": "Checks that Redshift storage encryption and audit logging are both enabled."
    },
    "remediation_base_sha256": "4f3e8c8dd31038d2513b87ace48428532fc11afa73671406b5f1d8f047aa2b0f",
    "remediation_fields": {
      "summary": "Enable any missing storage encryption or audit logging; plan migration before replacing storage.",
      "steps": [
        "Enable any missing storage encryption or audit logging; plan migration before replacing storage."
      ]
    },
    "static_observed_sentence": "Redshift encryption or audit logging is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_enc_logging",
      "predicate_source_sha256": "f8136bbc5ad2ff30be82243e36c25957d4d9f757bd086644fdd585fed45d3dbd"
    }
  },
  "aws.cb.redshift.require_ssl": {
    "description_base_sha256": "196acfe2e8d0c1b1860963bc67373548f4793fadcd0e13e037e041feee5f2a17",
    "description_fields": {
      "description": "Checks whether the require_ssl cluster parameter is the case-insensitive string true."
    },
    "remediation_base_sha256": "dd90d2a0366c66a7a8c1f2953dba02f13b33c1e2a291cca019f0225ebdd6c995",
    "remediation_fields": {
      "summary": "Require SSL and update clients to use TLS before applying the parameter.",
      "steps": [
        "Require SSL and update clients to use TLS before applying the parameter."
      ]
    },
    "static_observed_sentence": "The require_ssl cluster parameter is absent or not true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_ssl",
      "predicate_source_sha256": "98d0a384d849fce9970399397856e404102f5554b66e086caedfdc2ae9b65c37"
    }
  },
  "aws.cb.redshift.has_snapshot": {
    "description_base_sha256": "c1e2351a0a15b9a662a7018d72d61ce28c0cb1e7fd63b7bec83e9e346c3b506d",
    "description_fields": {
      "description": "Looks for any collected Redshift snapshot matching the cluster identifier."
    },
    "remediation_base_sha256": "ae24f51e47da658126d99c682ad910b154485be9ec791dedd078f428e4447117",
    "remediation_fields": {
      "summary": "Create a recoverable snapshot and investigate missing backup coverage.",
      "steps": [
        "Create a recoverable snapshot and investigate missing backup coverage."
      ],
      "caveats": [
        "The predicate counts any matching snapshot; it does not check freshness or restore success.",
        "The evaluator counts any matching snapshot, including manual or in-progress; it does not prove a recent, completed or restorable snapshot. Automated snapshots can be deleted when retention becomes zero."
      ]
    },
    "static_observed_sentence": "No collected Redshift snapshot matches this cluster.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_snapshot",
      "predicate_source_sha256": "4f74a3b4378f12a02d61500a8731101b93aa131f1801b2fc3f3c7455f99f4176"
    }
  },
  "aws.cb.redshift.snapshot_retention_7_days": {
    "description_base_sha256": "aaf76b7de4962693c8eb90cef108613afef8db276453987ac0be6c18bb5ba3f5",
    "description_fields": {
      "description": "Compares automated snapshot retention with seven days."
    },
    "remediation_base_sha256": "8e14bc917f518203b04daf89b251e3038ecc718c9f1ed4714ccd8a24ac6ac650",
    "remediation_fields": {
      "summary": "Configure at least seven days of automated snapshots if suitable for recovery.",
      "steps": [
        "Configure at least seven days of automated snapshots if suitable for recovery."
      ]
    },
    "static_observed_sentence": "Automated Redshift snapshot retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_retention",
      "predicate_source_sha256": "1b5dda0ab71d95af13c83e867f3afe2ecdb2db28c127ec56d05b52b53aafec91"
    }
  },
  "aws.cb.redshift.maintenance_settings": {
    "description_base_sha256": "cbe75bc70649a3d1926689641790cd873255dadf4d1f2c9ceeb8b01aefc0a554",
    "description_fields": {
      "description": "Checks AllowVersionUpgrade and automated snapshot retention of at least seven days."
    },
    "remediation_base_sha256": "f8033c0b05007f1e8e77c5192afe2df5f51c929124a6c88d5cac8bfe78ebffde",
    "remediation_fields": {
      "summary": "Enable version upgrades and adjust snapshot retention after reviewing maintenance and recovery needs.",
      "steps": [
        "Enable version upgrades and adjust snapshot retention after reviewing maintenance and recovery needs."
      ]
    },
    "static_observed_sentence": "Version upgrades are disabled or automated snapshot retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_maint",
      "predicate_source_sha256": "d77187b8580f1be5852d354b6858e468eae3450cda70eb85a8915a930d417466"
    }
  },
  "aws.cb.redshift.kms_key_declared": {
    "description_base_sha256": "06b72fa5516d7eb5354f82d4e7e88923c021d5fc6aefbd5e81bca807c10013f3",
    "description_fields": {
      "description": "Checks that storage encryption is enabled and KmsKeyId is present."
    },
    "remediation_base_sha256": "6a21cc86ea90310be96c2cb152fcd78d3001e5d0adcdfe5887e895deb8e98bb0",
    "remediation_fields": {
      "summary": "Enable storage encryption with an appropriate KMS key; plan migration if required.",
      "steps": [
        "Enable storage encryption with an appropriate KMS key; plan migration if required."
      ]
    },
    "static_observed_sentence": "Storage encryption is disabled or no KMS key is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_kms",
      "predicate_source_sha256": "21fda8212ad7af8782849312bac9f45aa6bdc74a2a60f9046db0837553e6f9d4"
    }
  },
  "aws.cb.redshift.cmk_encryption": {
    "description_base_sha256": "f23c9ab6a8f106ed2a927f052635cf578627c9df2cc5925087b6b6693fd01942",
    "description_fields": {
      "description": "Checks storage encryption and the joined KMS key\u2019s KeyManager=CUSTOMER."
    },
    "remediation_base_sha256": "b722d569f5d9fa8a790a417a375442184139e95cb936ab4fa5e40f5976d5bd2c",
    "remediation_fields": {
      "summary": "Use a customer-managed KMS key if separate key administration is required.",
      "steps": [
        "Use a customer-managed KMS key if separate key administration is required."
      ],
      "caveats": [
        "An AWS-managed key still provides encryption; key ownership is a separate requirement.",
        "The evaluator joins KMS metadata; a missing key row is unknown rather than evidence of AWS-managed encryption. The documented in-place modify flow explicitly covers enabling encryption on an unencrypted cluster; do not assume an existing encrypted cluster can switch keys with the same flag."
      ]
    },
    "static_observed_sentence": "Storage is unencrypted or its resolved key is not customer managed.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_cmk",
      "predicate_source_sha256": "37783c4747695df901be7033d05fd5bc91aac5b1d2df0b9e53cf7336d922476b"
    }
  },
  "aws.cb.redshift.internet_exposed": {
    "description_base_sha256": "1a511cb9975ae9f55ba15845a038f1f57ffd87239b19dc1fc249aab5461bdf9c",
    "description_fields": {
      "description": "Combines an endpoint, PubliclyAccessible, a public subnet and the source profile\u2019s world-address security-group ingress rule."
    },
    "remediation_base_sha256": "a9dcc7fa5e0b35c93157fe0a566f6cfbd13896520db418e6214290b3478d8dc3",
    "remediation_fields": {
      "summary": "Restrict Internet-wide database ingress to the networks that need access.",
      "steps": [
        "Restrict Internet-wide database ingress to the networks that need access."
      ],
      "caveats": [
        "No connection is attempted; this source profile\u2019s security-group test is broader than a single endpoint-port test.",
        "This conjunctive predicate does not fail every publicly accessible cluster or every world-open rule by itself. A route-table declaration and broad rule do not prove effective reachability; shared security groups and endpoint changes can break other clients."
      ]
    },
    "static_observed_sentence": "The declared Redshift network configuration matches the profile\u2019s public-exposure path.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_exposed",
      "predicate_source_sha256": "7e9e652e24e762139d1cff42b6b2bc43c2d405704e628b8e999c9a72aced7cbe"
    }
  },
  "aws.cb.redshift.security_group_port_restricted": {
    "description_base_sha256": "ac9a7a9113e96328cb2287da76a400183ffb51404d819ef9916cd634e6547d4e",
    "description_fields": {
      "description": "Checks attached security groups for a world CIDR and a range covering the cluster port, default 5439."
    },
    "remediation_base_sha256": "8083b8ec909617d990af86009c72ca9f597e1f30e10c0d178a84fd997d07feb4",
    "remediation_fields": {
      "summary": "Restrict the database port to the client networks that need it.",
      "steps": [
        "Restrict the database port to the client networks that need it."
      ],
      "caveats": [
        "This source profile counts any protocol with a matching port range; it does not prove a TCP connection.",
        "The evaluator accepts any protocol whose port range covers the endpoint port and protocol -1 without explicit ports; it does not require actual public route reachability. Shared security groups can serve other workloads, so removal needs dependency review."
      ]
    },
    "static_observed_sentence": "A security-group rule permits world-address ingress matching the database port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_sg",
      "predicate_source_sha256": "1d7df449f5bbfadf7d7986493c57b8793a88eab596e63e45957d2687d247db16"
    }
  },
  "aws.cb.redshiftserverless.connection_user_log_exports": {
    "description_base_sha256": "2b425b4dc3287cb57ec1d72794b42d6978e05cce6eb05052c0b060c47715e817",
    "description_fields": {
      "description": "Checks that namespace logExports contains connectionlog and userlog."
    },
    "remediation_base_sha256": "6b4e3e5f818a5f9d5be59e6dac64fc714f5f399d590b6993c838742c47b89a1f",
    "remediation_fields": {
      "summary": "Enable connectionlog and userlog exports needed for investigation.",
      "steps": [
        "Enable connectionlog and userlog exports needed for investigation."
      ]
    },
    "static_observed_sentence": "The namespace is missing connectionlog or userlog exports.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "ns_logs",
      "predicate_source_sha256": "cc69b6988d8d4e13a7fb8a0a973631091f4aa67380b6cf7675f955515e3e3d02"
    }
  },
  "aws.cb.redshiftserverless.require_ssl": {
    "description_base_sha256": "857f157d85fe925b0223c0d2d37de1ad95b1fff216d213121c9fe961f98f7de9",
    "description_fields": {
      "description": "Looks for a workgroup config parameter require_ssl with value true."
    },
    "remediation_base_sha256": "f5f8a4887ef9419900307ad6bc6e5eca07f65fa740657fef4677690f3f44301b",
    "remediation_fields": {
      "summary": "Require SSL for workgroup connections and check client compatibility.",
      "steps": [
        "Require SSL for workgroup connections and check client compatibility."
      ]
    },
    "static_observed_sentence": "The workgroup does not declare require_ssl=true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshiftserverless_workgroup",
      "predicate_qualname": "wg_ssl",
      "predicate_source_sha256": "82b1604a430bdb3bb4d6cc0b3e3772e2d470ed3e3bbfd76432fa72421b5a0b47"
    }
  },
  "aws.cb.opensearch.encryption_at_rest": {
    "description_base_sha256": "aef9cd568be3fa0ee57f51236c4296d3cea32e166d0cddf5bf91e239b5ed945a",
    "description_fields": {
      "description": "Checks EncryptionAtRestOptions.Enabled on the domain."
    },
    "remediation_base_sha256": "80fd86f088729e2e471d3465f9d3862a98a9b640a8b16768e6a88d2870e221b2",
    "remediation_fields": {
      "summary": "Enable encryption at rest; plan a replacement domain if the existing deployment cannot be updated.",
      "steps": [
        "Enable encryption at rest; plan a replacement domain if the existing deployment cannot be updated."
      ]
    },
    "static_observed_sentence": "OpenSearch encryption at rest is disabled.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_enc",
      "predicate_source_sha256": "194c3fbcc9187737357dc978c89b30907fb5535eaa598044a36a95c6c1e51728"
    }
  },
  "aws.cb.opensearch.fine_grained_access_control": {
    "description_base_sha256": "fe595f2761a6c7cd39b9b16a0bf70526de1df712fb51e981da2c7262bc4c3a9c",
    "description_fields": {
      "description": "Checks AdvancedSecurityOptions.Enabled on the domain."
    },
    "remediation_base_sha256": "aba389e4b7e5a228f4f3a536c7712645e107e90a8a6f945124b6beb8276452a5",
    "remediation_fields": {
      "summary": "Enable fine-grained access control and map users to the minimum required index permissions.",
      "steps": [
        "Enable fine-grained access control and map users to the minimum required index permissions."
      ]
    },
    "static_observed_sentence": "OpenSearch fine-grained access control is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_fgac",
      "predicate_source_sha256": "862945b58b0324e6dbd1b7c4f7b00fe108bd7a2346edb74ff1cc1a2ce6d0a8fa"
    }
  },
  "aws.cb.opensearch.internal_user_database_disabled": {
    "description_base_sha256": "67f49737661dff0a5ab3704d6d749e56f78f739fe72957d2b89f4e5e5559190b",
    "description_fields": {
      "description": "Checks the source profile\u2019s preference for disabling the internal user database."
    },
    "remediation_base_sha256": "79c16131eb51cd0b9673fc2752d4995af2347b002c8bb91799dc3fd3157f6df7",
    "remediation_fields": {
      "summary": "Disable the internal user database only if an alternative authentication model is intended and working.",
      "steps": [
        "Disable the internal user database only if an alternative authentication model is intended and working."
      ],
      "caveats": [
        "Internal users are a supported authentication option; this profile conflicts with an internal-user-enabled profile.",
        "The evaluator treats an absent InternalUserDatabaseEnabled field as false; absence alone does not prove federation is working. Switching the master user can disable HTTP basic authentication without deleting internal user records."
      ]
    },
    "static_observed_sentence": "The OpenSearch internal user database is enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_iudb",
      "predicate_source_sha256": "c4c8090b0b1795d2e65ebaee0775919c863b20ee0fe66421ad82373b0b3045d3"
    }
  },
  "aws.cb.opensearch.service_software_current": {
    "description_base_sha256": "43e6f7ed8c14711c3ea39777015b392752eaee72756f0956532ed181bbbf2ba6",
    "description_fields": {
      "description": "Checks ServiceSoftwareOptions.UpdateAvailable on the domain."
    },
    "remediation_base_sha256": "13c79fb2ffffedadc307349f2424c39882df126b66312598a9dbd83add4e74a2",
    "remediation_fields": {
      "summary": "Review and schedule the available service software update.",
      "steps": [
        "Review and schedule the available service software update."
      ],
      "caveats": [
        "Availability of an update is not evidence of an actively exploited vulnerability.",
        "A service software patch differs from an engine-version upgrade. A pending request may take hours or days and can temporarily strain master capacity; the field may remain true until the deployment finishes."
      ]
    },
    "static_observed_sentence": "An OpenSearch service software update is available.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_sw",
      "predicate_source_sha256": "e8a3ae22b6b84969b7c90685681db1a99348327d5f0772025dbab09925db631b"
    }
  },
  "aws.cb.opensearch.data_node_fault_tolerance": {
    "description_base_sha256": "d6371f87ad52f38fa307fc6159f80ed7cb043c3e39a8ef056e932c658d93ccc7",
    "description_fields": {
      "description": "Checks for at least three data nodes and enabled zone awareness."
    },
    "remediation_base_sha256": "2a2a847396b1085743d06d77065f91269268f4f9477e5098a8e1ad81d4db0ed6",
    "remediation_fields": {
      "summary": "Use sufficient nodes and zone awareness if the workload requires zonal fault tolerance.",
      "steps": [
        "Use sufficient nodes and zone awareness if the workload requires zonal fault tolerance."
      ]
    },
    "static_observed_sentence": "The domain has fewer than three data nodes or zone awareness is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_data",
      "predicate_source_sha256": "ddbd2d5cfdef9ae4b4af141dedcaf29b3ef4febfbae31e95d9f6a33c319bbfcf"
    }
  },
  "aws.cb.opensearch.dedicated_master_nodes": {
    "description_base_sha256": "bb8952fedbce1b1fa86664262612c9dbebe6c9eca2c4857ff664826f3742f8ed",
    "description_fields": {
      "description": "Checks that dedicated masters are enabled and their count is at least three."
    },
    "remediation_base_sha256": "b61bccf8f6388d3b65b4df90b3c719bde707057b1a66a3262db426add3d20c96",
    "remediation_fields": {
      "summary": "Use at least three dedicated masters where the domain\u2019s availability requirements justify them.",
      "steps": [
        "Use at least three dedicated masters where the domain\u2019s availability requirements justify them."
      ]
    },
    "static_observed_sentence": "Dedicated masters are disabled or fewer than three are configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_master",
      "predicate_source_sha256": "5c11e0a1cefd2f2f05159295c39bf7691565b6dfefcee09293b898e2ad940d44"
    }
  },
  "aws.cb.opensearch.cognito_dashboards_auth": {
    "description_base_sha256": "731a9edf32b41456fc2a32fd5873fcbf85d688c3d1109a799b799bbbd6509eea",
    "description_fields": {
      "description": "Checks CognitoOptions.Enabled for the Dashboards authentication profile."
    },
    "remediation_base_sha256": "2d9b1517eb3e84a31993c2cbaab7397f38444ee5b0e7e3c2cd5c86d6f4b0c879",
    "remediation_fields": {
      "summary": "Enable Cognito only if it is the intended Dashboards authentication method.",
      "steps": [
        "Enable Cognito only if it is the intended Dashboards authentication method."
      ],
      "caveats": [
        "Other valid authentication methods can protect Dashboards; Cognito absence alone does not mean anonymous access.",
        "This check requires Cognito specifically; a working SAML or IAM login does not make it pass. Pool IDs and service role are owner-supplied, and merely setting Enabled does not prove users can sign in."
      ]
    },
    "static_observed_sentence": "Cognito authentication for Dashboards is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_cognito",
      "predicate_source_sha256": "aec21a289f087b2df989a18103899fa4966fed8fb77cf4ade20bd7f159456d6e"
    }
  },
  "aws.cb.opensearch.cognito_or_saml_dashboards_auth": {
    "description_base_sha256": "3be2d61f4489838b431ed9b5d4a4184968c0e931d57846f0297a17a9d70e0b0f",
    "description_fields": {
      "description": "Checks whether Cognito or SAML is enabled for Dashboards."
    },
    "remediation_base_sha256": "33f22ef4aab6cccac7626f5f1069a2605b8ab265ebe872468ecb4da72919699b",
    "remediation_fields": {
      "summary": "Configure Cognito or SAML if that is the intended authentication model.",
      "steps": [
        "Configure Cognito or SAML if that is the intended authentication model."
      ],
      "caveats": [
        "This does not establish that every other authentication method is absent.",
        "The evaluator accepts either option, but does not prove correct IdP metadata or role mapping. SAML requires fine-grained access control and an identity-provider setup; do not interpolate metadata or secrets into commands."
      ]
    },
    "static_observed_sentence": "Neither Cognito nor SAML authentication is enabled for Dashboards.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_cognito_saml",
      "predicate_source_sha256": "34517e732442ee62575c6a17ddd9ce298442095221bde04a6df10341280fb9b8"
    }
  },
  "aws.cb.opensearch.node_to_node_encryption": {
    "description_base_sha256": "fd3dab346f89241b966633c6496ae7d88ac89029fe6c3cd2131f15dad871b131",
    "description_fields": {
      "description": "Checks NodeToNodeEncryptionOptions.Enabled within the source profile\u2019s regional scope."
    },
    "remediation_base_sha256": "724719b80aa206810b37892679fdea58982a84b5b47b2185d331f94516b34589",
    "remediation_fields": {
      "summary": "Enable node-to-node encryption; plan migration if the deployment cannot be updated.",
      "steps": [
        "Enable node-to-node encryption; plan migration if the deployment cannot be updated."
      ],
      "caveats": [
        "The setting is checked; encrypted traffic is not independently captured.",
        "Existing-domain enablement requires OpenSearch or Elasticsearch 6.7 or later; after enabling, it cannot be disabled in place. An older incompatible domain needs upgrade or snapshot-based replacement."
      ]
    },
    "static_observed_sentence": "OpenSearch node-to-node encryption is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_n2n",
      "predicate_source_sha256": "3d92b08e88bc8919460d4ca39b4eb59d9cedebb0901203e072688a1f3e3d54c7"
    }
  },
  "aws.cb.opensearch.node_to_node_encryption_region_skip": {
    "description_base_sha256": "36e22a91f9463baeefe5d006017b682f8a4fb5e15925d40fc4d2ad839e25b0ff",
    "description_fields": {
      "description": "Checks NodeToNodeEncryptionOptions.Enabled within the source profile\u2019s regional scope."
    },
    "remediation_base_sha256": "ec3bd67c98ff9f89d6e3ba21f4bc718f1ef7c4ccd1a7e62fb147d8bb18578512",
    "remediation_fields": {
      "summary": "Enable node-to-node encryption; plan migration if the deployment cannot be updated.",
      "steps": [
        "Enable node-to-node encryption; plan migration if the deployment cannot be updated."
      ],
      "caveats": [
        "The region-exception variant omits its four explicitly listed legacy Regions.",
        "The source marks af-south-1, eu-south-1, cn-north-1 and cn-northwest-1 NOT_APPLICABLE without checking the setting. Existing-domain enablement requires OpenSearch or Elasticsearch 6.7 or later; after enabling, it cannot be disabled in place. An older incompatible domain needs upgrade or snapshot-based replacement."
      ]
    },
    "static_observed_sentence": "OpenSearch node-to-node encryption is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_n2n_skip",
      "predicate_source_sha256": "1e5df0a1a1dc54f71656223005fba05aa297ee5ac579d13fea0f752ebc0623c1"
    }
  },
  "aws.cb.opensearch.enforce_https": {
    "description_base_sha256": "a8a558912a242eb128e9ea2815e1f458531b29f741a7c936cfc11aa87c7fa14f",
    "description_fields": {
      "description": "Checks whether the OpenSearch domain requires HTTPS."
    },
    "remediation_base_sha256": "157d588cd39bad095822d6ece9d6007286a3b071de1fde0d4967ead62b6a8e0a",
    "remediation_fields": {
      "summary": "Require HTTPS and update clients that still use HTTP.",
      "steps": [
        "Require HTTPS and update clients that still use HTTP."
      ]
    },
    "static_observed_sentence": "The OpenSearch domain does not enforce HTTPS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_https",
      "predicate_source_sha256": "ed9ecb730d2aab2219114795a7005fdbfa0f779d2ce46fe33e35c5bdf28ea641"
    }
  },
  "aws.cb.opensearch.audit_logs_enabled": {
    "description_base_sha256": "8de02b913ecf1c726d4ccc093a5c6fe48957189ef2a7e132da5e5f23d82d3870",
    "description_fields": {
      "description": "Checks whether OpenSearch audit log publishing is enabled."
    },
    "remediation_base_sha256": "23f6efcae75fcbe2751826a2cb323ee90d2982850b2bdc1f8503a92adf75ea8e",
    "remediation_fields": {
      "summary": "Enable audit log publishing and configure a usable CloudWatch destination.",
      "steps": [
        "Enable audit log publishing and configure a usable CloudWatch destination."
      ],
      "caveats": [
        "Publishing configuration does not prove log delivery.",
        "This check reads Enabled only; it does not verify a CloudWatch log group ARN, resource policy or actual events. Audit logging requires fine-grained access control and a separate in-cluster audit setting."
      ]
    },
    "static_observed_sentence": "Audit log publishing is not enabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_audit",
      "predicate_source_sha256": "60195b790e43d4ad879a062da4f600c6d72403dc61684ee1d84184bea5afc544"
    }
  },
  "aws.cb.opensearch.slow_logs_enabled": {
    "description_base_sha256": "6032d499add1452f962ed4331f257554db2d13079a2e128c1b4171cb75f741d8",
    "description_fields": {
      "description": "Checks that search and index slow-log publishing are both enabled."
    },
    "remediation_base_sha256": "661d084363f82715cb2604b23b106221dcaee4cbd326a607d41549dee43e72cb",
    "remediation_fields": {
      "summary": "Enable the slow logs needed for operational diagnosis and configure thresholds.",
      "steps": [
        "Enable the slow logs needed for operational diagnosis and configure thresholds."
      ],
      "caveats": [
        "Slow logs are an operational diagnostic setting, not a general audit trail.",
        "Enabled flags alone do not guarantee events; shard slow logs remain quiet until index thresholds are set and requests exceed them. Log publication can increase cost and reveal query data, so access and retention require review."
      ]
    },
    "static_observed_sentence": "Search or index slow-log publishing is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_slow",
      "predicate_source_sha256": "be8322b24147858fc0bf8a20013733b5685d85b1889cbadb0725153c94a23eaa"
    }
  },
  "aws.cb.opensearch.enabled_logs_have_log_group": {
    "description_base_sha256": "815db5d43e67882eb8c622532cbad01dedcc7ead3c72abe0c604a95ee43c89d0",
    "description_fields": {
      "description": "Checks that each enabled supported log type declares a CloudWatch log-group ARN."
    },
    "remediation_base_sha256": "bd70d910ced399b374686bf28090bb19e3064f8dc0378a1c0010fa3ef38e422b",
    "remediation_fields": {
      "summary": "Set a CloudWatch log-group destination for each enabled log type.",
      "steps": [
        "Set a CloudWatch log-group destination for each enabled log type."
      ],
      "caveats": [
        "A declared log-group ARN does not establish delivery permissions or received logs.",
        "An empty but present LogPublishingOptions map passes this evaluator; it does not require any log type to be enabled. Destination presence does not prove resource-policy permission or successful delivery."
      ]
    },
    "static_observed_sentence": "A supported enabled log type has no log-group ARN, or log publishing configuration is absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_log_groups",
      "predicate_source_sha256": "26f8f70f8ffc0b637ec4d4735e88b037f018e864d6a44bb3e45d227d7c70d47d"
    }
  },
  "aws.cb.opensearch.in_vpc_private_subnets": {
    "description_base_sha256": "cb815b1dcda0b5d257c6e45f143331773460a07786b91e4219612f5cefa8be96",
    "description_fields": {
      "description": "Checks VPCId and rejects domain subnets with an explicitly associated Internet-gateway default route."
    },
    "remediation_base_sha256": "6d030cdde608d9a8bd4a9f73acc5baa99fd690ab31e948633a6eeb8de3872f67",
    "remediation_fields": {
      "summary": "Use private VPC subnets when public placement is unnecessary.",
      "steps": [
        "Use private VPC subnets when public placement is unnecessary."
      ],
      "caveats": [
        "This source profile uses explicit route-table associations; it does not resolve an inherited main route table.",
        "AWS cannot move an existing public-endpoint domain into a VPC in place. This evaluator only checks explicitly associated route tables for a 0.0.0.0/0 Internet Gateway route; it does not inspect main-table inheritance or effective reachability."
      ]
    },
    "static_observed_sentence": "The domain has no VPC ID or one of its subnets has an explicit public route.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_vpc",
      "predicate_source_sha256": "013fded7d7f7bb69e23c3ba9bc36d8309cda39c140180d3b3ca29893657fc190"
    }
  },
  "aws.cb.opensearch.access_policy_not_public": {
    "description_base_sha256": "2fe7699d1b6838f976a1e5ca59db03e41ea8cb156ff3df3996803d4d49bfef22",
    "description_fields": {
      "description": "Checks the source profile\u2019s public Allow statements on domains outside a VPC."
    },
    "remediation_base_sha256": "2fba6be4310dce6cdf80baccda832eeffc2285497bc3655d455e3d4c9f483be2",
    "remediation_fields": {
      "summary": "Restrict the access policy to the identities and conditions that need domain access.",
      "steps": [
        "Restrict the access policy to the identities and conditions that need domain access."
      ],
      "caveats": [
        "A policy statement is evaluated; no request is sent to the endpoint.",
        "Domains with VPCId pass without inspecting the policy, and an absent policy also passes; neither proves private reachability. Restricting an access policy can immediately block workloads, so the replacement document needs owner approval and rollback."
      ]
    },
    "static_observed_sentence": "The non-VPC domain access policy contains a public Allow statement.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_public",
      "predicate_source_sha256": "1f2f0bcfc7f0c856e243f3d7a12352b4ffa5dd1bf2417ac093ba9e1227ca4606"
    }
  }
}
''' )

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode()).hexdigest()

def _apply(cid, original, kind):
    row = ROWS.get(cid)
    if row is None:
        return original
    if _digest(original) != row[kind + '_base_sha256']:
        raise ValueError('Reviewed database clarity base changed: ' + cid)
    result = deepcopy(original)
    result.update(deepcopy(row[kind + '_fields']))
    return result

def description(cid,original):
    return _apply(cid,original,'description')

def remediation(cid,original):
    return _apply(cid,original,'remediation')

REVIEWED_RISKS = {cid:(row['reviewed_source_severity'],row['reviewed_severity']) for cid,row in ROWS.items()}

def _strings(value, *, nonempty=False):
    return isinstance(value,list) and (not nonempty or bool(value)) and all(isinstance(v,str) and bool(v) for v in value)


def _false(evidence,key):return key in evidence and evidence[key] is False

def _true(evidence,key):return key in evidence and evidence[key] is True

def _absent(evidence,key):return key in evidence and (evidence[key] is None or evidence[key]=='')

def _integer(evidence,key,low,high):
    value=evidence.get(key)
    return type(value) is int and low<=value<=high


def _ca_within(evidence,months=None,days=None):
    from datetime import datetime,timedelta
    from calendar import monthrange
    try:
        expiry=evidence['valid_till'];capture=evidence['evaluated_at']
        if not isinstance(expiry,str) or not isinstance(capture,str):return False
        expiry=datetime.fromisoformat(expiry.replace('Z','+00:00'))
        capture=datetime.fromisoformat(capture.replace('Z','+00:00'))
        if expiry.tzinfo is None or capture.tzinfo is None:return False
        if months is not None:
            month=capture.month-1+months;year=capture.year+month//12;month=month%12+1
            cutoff=capture.replace(year=year,month=month,day=min(capture.day,monthrange(year,month)[1]))
        else:cutoff=capture+timedelta(days=days)
        return expiry<=cutoff
    except (KeyError,ValueError,OverflowError):return False


def _decisive_failure(cid,e):
    # A stored FAIL label alone is not evidence of the displayed claim.
    if cid.endswith('_snapshot_shared_accounts_review'):return False
    if cid in {'aws.cb.rds.cluster_backtrack_window_positive','aws.cb.rds.aurora_backtracking_configured'}:
        return _integer(e,'backtrack_window',0,0)
    if cid in {'aws.cb.rds.cluster_cloudwatch_log_exports','aws.cb.rds.cluster_log_exports_declared'}:
        return _strings(e.get('exports')) and not e['exports']
    requirements={
        'aws.cb.rds.aurora_postgres_postgresql_log_export':{'postgresql'},
        'aws.cb.rds.mariadb_log_exports':{'audit','error','general','slowquery'},
        'aws.cb.rds.postgres_log_exports':{'postgresql','upgrade'},
        'aws.cb.rds.sqlserver_error_log_export':{'error'},
        'aws.cb.neptune.audit_log_export':{'audit'},
        'aws.cb.redshiftserverless.connection_user_log_exports':{'connectionlog','userlog'},
    }
    if cid in requirements:
        key='log_exports' if 'redshiftserverless' in cid else 'exports'
        return _strings(e.get(key)) and not requirements[cid]<=set(e[key])
    booleans_false={
        'aws.cb.rds.multi_az_cluster_minor_upgrade':'auto_minor_version_upgrade',
        'aws.cb.rds.instance_copy_tags_all_engines':'copy_tags_to_snapshot',
        'aws.cb.rds.instance_iam_auth_supported_engines':'iam_database_authentication',
        'aws.cb.rds.instance_multi_az_or_cluster':'multi_az',
        'aws.cb.rds.instance_multi_az_non_aurora':'multi_az',
        'aws.cb.rds.cluster_snapshot_encrypted':'storage_encrypted',
        'aws.cb.neptune.snapshot_encrypted':'storage_encrypted',
        'aws.cb.redshift.audit_logging':'logging_enabled',
        'aws.cb.redshiftserverless.require_ssl':'require_ssl_enabled',
        'aws.cb.opensearch.encryption_at_rest':'enabled',
        'aws.cb.opensearch.fine_grained_access_control':'enabled',
        'aws.cb.opensearch.cognito_dashboards_auth':'cognito',
        'aws.cb.opensearch.node_to_node_encryption':'enabled',
        'aws.cb.opensearch.node_to_node_encryption_region_skip':'enabled',
        'aws.cb.opensearch.enforce_https':'enforce_https',
    }
    if cid in booleans_false:return _false(e,booleans_false[cid])
    booleans_true={
        'aws.cb.neptune.snapshot_not_public_prowler':'public_attribute_value_detected',
        'aws.cb.neptune.snapshot_restore_not_all_exact':'public_restore_attribute',
        'aws.cb.opensearch.internal_user_database_disabled':'internal_user_database',
        'aws.cb.opensearch.service_software_current':'update_available',
        'aws.cb.opensearch.access_policy_not_public':'public',
    }
    if cid in booleans_true:return _true(e,booleans_true[cid])
    if cid in {'aws.cb.rds.cluster_engine_default_port_prowler','aws.cb.rds.instance_engine_default_port_prowler'}:
        defaults={3306:('mysql','mariadb','aurora-mysql'),5432:('postgres','aurora-postgresql'),1521:('oracle',),1433:('sqlserver',),50000:('db2',)}
        return isinstance(e.get('engine'),str) and type(e.get('port')) is int and any(name in e['engine'].lower() for name in defaults.get(e['port'],()))
    matching={
        'aws.cb.rds.cluster_in_backup_plan_selection':'backup_selection_match',
        'aws.cb.rds.instance_in_backup_plan_selection':'backup_selection_match',
        'aws.cb.rds.aurora_cluster_protected_resource':'protected_resource_match',
        'aws.cb.rds.instance_protected_resource':'protected_resource_match',
        'aws.cb.rds.instance_in_backup_selection_or_tag':'selection_or_tag_key_match',
    }
    if cid in matching:
        arn=e.get('resource_arn')
        return _false(e,matching[cid]) and isinstance(arn,str) and re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:rds:[a-z0-9-]+:[0-9]{12}:(?:cluster|db):[A-Za-z0-9._-]+',arn) is not None
    if cid=='aws.cb.rds.instance_enhanced_monitoring_except_m1_small':return _absent(e,'enhanced_monitoring_resource_arn')
    if cid in {'aws.cb.rds.cluster_tls_parameters','aws.cb.rds.postgres_force_ssl_parameter','aws.cb.rds.mariadb_require_secure_transport','aws.cb.rds.sqlserver_force_ssl_parameter'}:
        param=e.get('parameter');value=e.get('value')
        if not isinstance(value,str):return False
        if cid=='aws.cb.rds.cluster_tls_parameters':return (param=='rds.force_ssl' and value=='0') or (param=='require_secure_transport' and value in {'0','OFF'})
        expected='require_secure_transport' if 'mariadb' in cid else 'rds.force_ssl'
        return param==expected and value in ({'0','OFF'} if 'mariadb' in cid else {'0'})
    if cid in {'aws.cb.rds.aurora_postgres_local_file_read_versions','aws.cb.rds.postgres_local_file_read_versions'}:
        return e.get('engine_version') in ('10.11','10.12','10.13','11.6','11.7','11.8')
    if cid=='aws.cb.rds.instance_backup_retention_nonzero_all':return _integer(e,'backup_retention_days',0,0)
    if cid=='aws.cb.rds.instance_default_master_username':return e.get('master_username') in ('admin','postgres')
    if cid=='aws.cb.rds.instance_extended_support':return e.get('engine_lifecycle_support')=='open-source-rds-extended-support'
    if cid=='aws.cb.rds.ca_certificate_valid_3_months':return _ca_within(e,months=3)
    if cid=='aws.cb.rds.ca_certificate_not_expiring_7_days':return _ca_within(e,days=7)
    if cid=='aws.cb.rds.engine_version_available':
        return _false(e,'engine_version_available') and all(isinstance(e.get(k),str) and e[k] for k in ('engine','engine_version'))
    if cid=='aws.cb.rds.instance_internet_exposed':
        return _strings(e.get('open_security_groups'),nonempty=True) and _strings(e.get('public_subnets'),nonempty=True) and _integer(e,'endpoint_port',1,65535)
    if cid in {'aws.cb.rds.instance_snapshot_restore_not_all_exact','aws.cb.rds.cluster_snapshot_restore_not_all_exact'}:
        return _strings(e.get('public_attributes')) and 'restore' in e['public_attributes']
    if cid in {'aws.cb.rds.instance_snapshot_not_public_prowler','aws.cb.rds.cluster_snapshot_not_public_prowler'}:
        # The current callback emits attribute NAMES only, including on PASS.
        # Never infer the all VALUE from attributes=['restore'] or stored FAIL.
        return _true(e,'public_attribute_value_detected') or _true(e,'public_restore_attribute')
    if cid.endswith('_critical_event_subscription'):
        return isinstance(e.get('scope'),str) and re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]',e['scope']) is not None and _strings(e.get('matching_subscriptions')) and not e['matching_subscriptions']
    if cid=='aws.cb.neptune.backup_retention_7_days':return _integer(e,'backup_retention_days',0,6)
    if cid in {'aws.cb.neptune.no_public_subnet_prowler','aws.cb.neptune.no_public_subnet_steampipe'}:
        return _strings(e.get('public_subnets'),nonempty=True)
    names={
        'aws.cb.redshift.non_default_master_username':('MasterUsername','awsuser'),
        'aws.cb.redshift.non_default_database_name':('DBName','dev'),
        'aws.cb.redshiftserverless.non_default_admin_username':('adminUsername','admin'),
        'aws.cb.redshiftserverless.non_default_database_name':('dbName','dev'),
    }
    if cid in names:
        key,value=names[cid];return e.get(key)==value
    if cid=='aws.cb.redshift.encrypted_and_logging':return _false(e,'encrypted') or (_true(e,'encrypted') and _false(e,'logging_enabled'))
    if cid=='aws.cb.redshift.require_ssl':return 'require_ssl' in e and (e['require_ssl'] is None or isinstance(e['require_ssl'],str) and e['require_ssl'].lower()!='true')
    if cid=='aws.cb.redshift.has_snapshot':return _integer(e,'snapshots',0,0)
    if cid=='aws.cb.redshift.snapshot_retention_7_days':return _integer(e,'retention_days',0,6)
    if cid=='aws.cb.redshift.maintenance_settings':return _false(e,'allow_version_upgrade') or (_true(e,'allow_version_upgrade') and _integer(e,'retention_days',0,6))
    if cid=='aws.cb.redshift.kms_key_declared':return _false(e,'encrypted') or (_true(e,'encrypted') and _absent(e,'kms_key_id'))
    if cid=='aws.cb.redshift.cmk_encryption':return _false(e,'encrypted') or (_true(e,'encrypted') and e.get('key_manager')=='AWS')
    if cid=='aws.cb.redshift.internet_exposed':return _strings(e.get('open_security_groups'),nonempty=True)
    if cid=='aws.cb.redshift.security_group_port_restricted':return _integer(e,'port',1,65535) and _strings(e.get('offending_security_groups'),nonempty=True)
    if cid=='aws.cb.opensearch.data_node_fault_tolerance':
        return type(e.get('instance_count')) is int and e['instance_count']>=0 and type(e.get('zone_awareness')) is bool and (e['instance_count']<3 or not e['zone_awareness'])
    if cid=='aws.cb.opensearch.dedicated_master_nodes':return _false(e,'dedicated_master') or _integer(e,'dedicated_master_count',0,2)
    if cid=='aws.cb.opensearch.cognito_or_saml_dashboards_auth':return _false(e,'cognito') and _false(e,'saml')
    if cid=='aws.cb.opensearch.audit_logs_enabled':return 'audit_logs' in e and (e['audit_logs'] is None or e['audit_logs'] is False)
    if cid=='aws.cb.opensearch.slow_logs_enabled':return type(e.get('search_slow')) is bool and type(e.get('index_slow')) is bool and not (e['search_slow'] and e['index_slow'])
    if cid=='aws.cb.opensearch.enabled_logs_have_log_group':
        missing=e.get('enabled_without_log_group')
        return ('log_publishing_options' in e and e['log_publishing_options'] is None) or (_strings(missing,nonempty=True) and set(missing)<={'AUDIT_LOGS','INDEX_SLOW_LOGS','SEARCH_SLOW_LOGS','ES_APPLICATION_LOGS'})
    if cid=='aws.cb.opensearch.in_vpc_private_subnets':return _absent(e,'vpc_id') or (isinstance(e.get('vpc_id'),str) and bool(e['vpc_id']) and _strings(e.get('public_subnets'),nonempty=True))
    return False


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider') != 'aws' or finding.get('status') != 'FAIL' or not isinstance(finding.get('evidence'),dict):
        return None
    cid=finding.get('check_id');row=ROWS.get(cid)
    if row is None or not _decisive_failure(cid,finding['evidence']):return None
    return row['static_observed_sentence']

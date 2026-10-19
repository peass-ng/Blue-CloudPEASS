"""Individually source-reviewed AWS compute/storage finding guidance. No cloud operations."""
from copy import deepcopy
import hashlib
import json

VERSION = "aws-compute-storage-clarity-20261019"
ROWS = json.loads(r'''
{
  "aws.claude_a.ebs.attached_volume_encrypted": {
    "description_base_sha256": "4f68128513217dc546e84019d8dae456b874c0dd0f5304bd9ff752245d4afade",
    "description_fields": {
      "description": "For in-use volumes, reads the Encrypted flag."
    },
    "remediation_base_sha256": "71f460dad34c0a5050955eed5a27c5e30fd3783b089d25fe8a6eee61b07a1aaa",
    "remediation_fields": {
      "summary": "If encryption is required, plan a supported encrypted-copy migration while preserving needed data.",
      "steps": [
        "If encryption is required, plan a supported encrypted-copy migration while preserving needed data."
      ],
      "caveats": [
        "Other volume states are not applicable; no disk data is read."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached EBS volume declares encryption disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_attached_encrypted",
      "predicate_source_sha256": "dd6207b746182bdc4fb429a81613fb12e283483b294f3c23d49aae86f70fe591",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.attached_delete_on_termination": {
    "description_base_sha256": "0bf8bc4ec8df03e95c88b59c0b8a3f3af4424a6b73b880dcddc40ea4e47643bc",
    "description_fields": {
      "description": "For in-use volumes, requires nonempty attachments with DeleteOnTermination=true."
    },
    "remediation_base_sha256": "a35a4339bea9f304c4138c9e1c7243f73ebe6427f8c409d567bc21cf5f1ba3d1",
    "remediation_fields": {
      "summary": "Set deletion-on-termination only for data that should be removed with the instance.",
      "steps": [
        "Set deletion-on-termination only for data that should be removed with the instance."
      ],
      "caveats": [
        "Persistent data may intentionally outlive an instance; other volume states are not applicable."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one volume attachment lacks deletion-on-termination.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_attached_dot",
      "predicate_source_sha256": "47e820bf9ff26da66f2db31789f1a255e07a001054fb6bd8797d76c3b0682323",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_use": {
    "description_base_sha256": "39f2941c6290a29ac85a36104b706e03d00a404824e0d4fe42cacab32e67a15a",
    "description_fields": {
      "description": "Compares the EBS volume state with in-use."
    },
    "remediation_base_sha256": "641d88b31a38ff5036d63a68897efc9c24523bd831be4291e0dbd18970dfe04f",
    "remediation_fields": {
      "summary": "Review the volume\u2019s recovery purpose and owner before retaining or retiring unused storage.",
      "steps": [
        "Review the volume\u2019s recovery purpose and owner before retaining or retiring unused storage."
      ],
      "caveats": [
        "An available volume can be intentional recovery storage; this is not evidence of public data."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS volume is not in the in-use state.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_use",
      "predicate_source_sha256": "94af20157eac5719d01ac303c7af1ca090f37a4da6c952ef53724ab8d4ada17e",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_has_snapshot": {
    "description_base_sha256": "49b008f771c1fd3a010cb9c3423b0e3d140cfb564531e019d6d87e7eeefde42c",
    "description_fields": {
      "description": "Joins the volume ID to self-owned snapshot VolumeId values."
    },
    "remediation_base_sha256": "930151ad0e1959800e87f16b71938a4b337c8952579eeed1e52fd8501cd61129",
    "remediation_fields": {
      "summary": "Configure suitable snapshots or backups and verify recovery when required.",
      "steps": [
        "Configure suitable snapshots or backups and verify recovery when required."
      ],
      "caveats": [
        "Snapshot existence does not establish freshness or restore success."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No snapshot with the volume\u2019s ID is present in the complete snapshot inventory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_has_snapshot",
      "predicate_source_sha256": "6f5b7cf030bc3c8eca95b0a3554062273081848284a74c0924835fdface88a78",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_protected_by_backup": {
    "description_base_sha256": "53f86ad30a55747074237b1d88c99cf263cab6e3efccacea0ad08749f9ddce8d",
    "description_fields": {
      "description": "Matches the regional volume ARN to EBS records in AWS Backup protected resources."
    },
    "remediation_base_sha256": "02b001e09ee9a8fabcbb317018ef3276abefa41ac07d72acf12a1aa7219221f1",
    "remediation_fields": {
      "summary": "Configure intended backup protection and verify required recovery points.",
      "steps": [
        "Configure intended backup protection and verify required recovery points."
      ],
      "caveats": [
        "This checks the protected-resource inventory, not every backup plan or recovery outcome."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The volume has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_protected",
      "predicate_source_sha256": "7dbe66e090c6fa725e638d7b8f78425068cd8fd6ebaaba6263dde45ecbf27a40",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_backup_selection": {
    "description_base_sha256": "1abe1000a4db969902961853ae1071f9fd6fa64ae85f5dd61781b024566ece53",
    "description_fields": {
      "description": "Matches the volume ARN or any volume tag key against Backup selection entries."
    },
    "remediation_base_sha256": "f9153ebe55ce008fcc825025605dce44abbbb0d4d2c2a106af1de784c2e7c335",
    "remediation_fields": {
      "summary": "Configure the intended Backup resource assignment and verify its actual selection.",
      "steps": [
        "Configure the intended Backup resource assignment and verify its actual selection."
      ],
      "caveats": [
        "Tag values, operators, exclusions and effective selection are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The volume matches neither an exact selection ARN nor a listed tag key.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_selection",
      "predicate_source_sha256": "c6def6d6493ecdacccc10dc4ce0fcf2db8506aa2ac8a8935a38a7a9f784e1fcb",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.volume_in_backup_plan_resources": {
    "description_base_sha256": "5df4a051f8c96a7f930d1d1851466e5dd00e747e65fdbb46c0360bd3be36a60c",
    "description_fields": {
      "description": "Matches the volume ARN, the EC2 volume wildcard or * in Backup selection Resources."
    },
    "remediation_base_sha256": "49e9b68fd3e29780d80d0b0805eeef62280138f15f43d531bb9123828f1397b7",
    "remediation_fields": {
      "summary": "Add the required supported resource assignment and verify actual backup coverage.",
      "steps": [
        "Add the required supported resource assignment and verify actual backup coverage."
      ],
      "caveats": [
        "Tag-based selection and completed recovery points are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No exact or supported wildcard volume ARN occurs in Backup selection Resources.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ebs_volume",
      "predicate_qualname": "ebs_in_plan_resources",
      "predicate_source_sha256": "9c8437fba9371f761bdb29436ec1ff14bdff0aaee7df02b47d57a93da7400b8e",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.snapshot_encrypted": {
    "description_base_sha256": "9295d7ae346a8c59a4644332d4946bc7cd1c6cca5abc7079b4b3b48543ccafd1",
    "description_fields": {
      "description": "Reads the snapshot Encrypted flag."
    },
    "remediation_base_sha256": "ef52ffdc21b7122b9225621974a3bd95c382b5889e982839d2adb04fe7185a16",
    "remediation_fields": {
      "summary": "If needed, create and validate an encrypted snapshot copy before retiring the old copy.",
      "steps": [
        "If needed, create and validate an encrypted snapshot copy before retiring the old copy."
      ],
      "caveats": [
        "Sharing, contents and recovery success are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS snapshot declares encryption disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "snapshot_encrypted",
      "predicate_source_sha256": "bcfec26faefbe5a2fb35d38009d6e9fa0ca5cb024a455550c795b7ad659de621",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ebs.snapshot_not_public": {
    "description_base_sha256": "1e7866ccbb507e2805944796f409d0c42269d2982924097b5b4f600292c0c369",
    "description_fields": {
      "description": "Checks create-volume permissions for Group=all without a UserId."
    },
    "remediation_base_sha256": "d3bef274364e3108125aa4a4aa4f6819351c1d8cad655e4566f2df1cb76e9211",
    "remediation_fields": {
      "summary": "Remove unintended public restore permission while retaining required account-specific sharing.",
      "steps": [
        "Remove unintended public restore permission while retaining required account-specific sharing."
      ],
      "caveats": [
        "This is a declared public restore permission, not a completed restore."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EBS snapshot permits the all group to create volumes.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "snapshot_public",
      "predicate_source_sha256": "70f56c66082c21b23254eb7909a60bd377a8d645d3c4bc4ea7ac7653f6860b44",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ebs_encryption_by_default": {
    "description_base_sha256": "b366f364f08c4bbecfb3ad95777f8ae9b6b00f2f6df9b8341f162fe620d27ba3",
    "description_fields": {
      "description": "Reads the regional EBS encryption-by-default flag."
    },
    "remediation_base_sha256": "5849b9fdea0b0a099e77c5e97c13aca2a381b15c2578e4ea51f5d8c0182274f3",
    "remediation_fields": {
      "summary": "Enable the intended encryption default for future EBS storage and review existing volumes separately.",
      "steps": [
        "Enable the intended encryption default for future EBS storage and review existing volumes separately."
      ],
      "caveats": [
        "Existing volumes are not reconfigured by this default."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EBS encryption by default is disabled in this Region.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ebs_default_encryption",
      "predicate_source_sha256": "267d5adc55e11199bbfa1c65b54ee63a43af7c12cc500157e03eefccc06d5905",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ebs_encryption_by_default_with_volumes": {
    "description_base_sha256": "c8d6f41398a124bd4d624eb6b765efcf3f2b9722d496ce63d58d39a9c057ffa0",
    "description_fields": {
      "description": "In Regions with volumes, reads the EBS encryption-by-default flag."
    },
    "remediation_base_sha256": "467003af9e90d4676c38cb49a2ab601b10413e85aac3e997ed156b2a0aa05095",
    "remediation_fields": {
      "summary": "Enable the intended encryption default for future EBS storage and review existing volumes separately.",
      "steps": [
        "Enable the intended encryption default for future EBS storage and review existing volumes separately."
      ],
      "caveats": [
        "Regions without volumes are not applicable; current volume encryption is separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EBS encryption by default is disabled in a Region containing volumes.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ebs_default_encryption_used",
      "predicate_source_sha256": "27c2aec59fa3d381d19722c9111bcecfaefd7be06435c9ab43fcccb0dbe0b470",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.snapshot_block_public_access": {
    "description_base_sha256": "7cd4b405aa28bfe7cc49538702b1f424d0dcad791774b881574c2ac401e48eed",
    "description_fields": {
      "description": "In Regions with snapshots, compares snapshot public-access blocking with block-all-sharing."
    },
    "remediation_base_sha256": "3be46c8cf9c48f225a3ec1602730106e03413048531ded292f6eadb7cb1b63ea",
    "remediation_fields": {
      "summary": "Choose the intended public-sharing protection and separately review existing shares.",
      "steps": [
        "Choose the intended public-sharing protection and separately review existing shares."
      ],
      "caveats": [
        "Regions without snapshots are not applicable; block-new-sharing fails this stronger baseline."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Snapshot public-access protection is not set to block-all-sharing.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "snapshot_bpa",
      "predicate_source_sha256": "cb0c02284bc5719bc0913241e5fcc0d76a8499979fa2292930fa5bc340cc036b",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_block_public_access": {
    "description_base_sha256": "a7df0fc126d574f087666d077cdf31ad45f3bca2c06125242af47a7b6f5a3935",
    "description_fields": {
      "description": "Compares the regional AMI public-access setting with block-new-sharing."
    },
    "remediation_base_sha256": "ee31b7f7e096053308dca89e94c5415f636ac6141bf3ead235d97bd8e5092ff8",
    "remediation_fields": {
      "summary": "Block new public AMI sharing unless public image distribution is intended.",
      "steps": [
        "Block new public AMI sharing unless public image distribution is intended."
      ],
      "caveats": [
        "This default does not inventory or revoke existing public image permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "AMI public-access blocking is unblocked.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "ami_bpa",
      "predicate_source_sha256": "f345f6079488b8e3a1a1bb2e605bdf123716d040a34934e43cf0020a7c3b33ce",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.account_imdsv2_default": {
    "description_base_sha256": "cebeb89152ad25bbe9e3b162b5b2905a89e1eff38bd9c59088621e9763426b68",
    "description_fields": {
      "description": "In Regions with instances, checks regional metadata defaults for HttpTokens=required."
    },
    "remediation_base_sha256": "5edab3aaba6815eee055eab639608f57c0f9884ed82abde6716047412b797e59",
    "remediation_fields": {
      "summary": "Require IMDSv2 in intended launch defaults and separately review existing instances.",
      "steps": [
        "Require IMDSv2 in intended launch defaults and separately review existing instances."
      ],
      "caveats": [
        "Regions without instances are not applicable; account defaults do not prove existing instance settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Regional instance-metadata defaults do not explicitly require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_regional_settings",
      "predicate_qualname": "account_imdsv2",
      "predicate_source_sha256": "af0337a7dcb5b30038428805dde6a86194d2ebede61f6d3a5fff6dc7b68600a2",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_not_public": {
    "description_base_sha256": "f6444d94f57cd354d716b95d9e09a171ce58d2b8ab01337d70b4fd9a1cd374fe",
    "description_fields": {
      "description": "Reads Public on account-owned AMIs."
    },
    "remediation_base_sha256": "e2297d780adfd5665cb3ca2ff888a9080a0c6fb31237397ceafb615e8ce69492",
    "remediation_fields": {
      "summary": "Remove unintended public image sharing while preserving deliberate public distributions.",
      "steps": [
        "Remove unintended public image sharing while preserving deliberate public distributions."
      ],
      "caveats": [
        "This does not inspect the image\u2019s contents or an actual launch."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The account-owned AMI is declared public.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_public",
      "predicate_source_sha256": "50db4cd6cbe13ecb4ba34314b579ea8a3e059afa515dbee9438f984e5d49c39a",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_ebs_encrypted": {
    "description_base_sha256": "45e012c9f0d352d2efde5f5d640e17f83f3bdaa43ce58b00b6674191189dbf32",
    "description_fields": {
      "description": "Checks every AMI block mapping for Ebs.Encrypted=true."
    },
    "remediation_base_sha256": "bad7c8f0c31c28d0b03f590ba68d4f77f3095c9c0e08f513b8f674e08f8cc129",
    "remediation_fields": {
      "summary": "If encryption is required, create and validate a supported encrypted image copy.",
      "steps": [
        "If encryption is required, create and validate a supported encrypted image copy."
      ],
      "caveats": [
        "No mappings is not applicable; instance-store mappings fail this particular EBS-only criterion."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one AMI block mapping does not declare encrypted EBS storage.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_encrypted",
      "predicate_source_sha256": "d3d18780eb4a5d0c5057cfdb0c05a1ec39ddd0adc252d581981b70847d2f269b",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.ami_not_older_than_90_days": {
    "description_base_sha256": "0271e4832c53777eb67abbba8b30d15899cd7cd69084d060d74c6e21744a125f",
    "description_fields": {
      "description": "Compares AMI creation with midnight UTC ninety days before the snapshot."
    },
    "remediation_base_sha256": "5d2884116fce0555dbc47812cbdeaba692d10cc451b931786aea50f38650beeb",
    "remediation_fields": {
      "summary": "Review image support and patch status; rebuild outdated images when needed.",
      "steps": [
        "Review image support and patch status; rebuild outdated images when needed."
      ],
      "caveats": [
        "Image creation age alone does not establish installed patch versions or vulnerabilities."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The AMI was created before the ninety-day cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_image",
      "predicate_qualname": "ami_age",
      "predicate_source_sha256": "f8d699aeffe1d4a1baf38c63cf7f37ba7439bbba0acc16dab491a861139e1749",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_detailed_monitoring": {
    "description_base_sha256": "ead8761c22124c88e54aa9e62cfd96829aed71fd2ddd51fc3dbc7a60573b9502",
    "description_fields": {
      "description": "Reads instance Monitoring.State and requires enabled."
    },
    "remediation_base_sha256": "40e375d916844c2491f47d994ce012cb98a2c77f10086f7a81894db89a6e579e",
    "remediation_fields": {
      "summary": "Enable detailed monitoring if the workload needs one-minute metrics.",
      "steps": [
        "Enable detailed monitoring if the workload needs one-minute metrics."
      ],
      "caveats": [
        "Basic monitoring and alternative observability are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Detailed EC 2 monitoring is not declared enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_monitoring",
      "predicate_source_sha256": "f98318cdb7fe2fa2b8fa00d67be2440e9abe5cd1b6f2721602788996d5e556b1",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ebs_optimized": {
    "description_base_sha256": "a3e9c29ffb6444a08d08a3cafc3493ad3d0c43b0d4f6b8592d8d5dfedab9d641",
    "description_fields": {
      "description": "Reads whether the instance declares EBS optimization enabled."
    },
    "remediation_base_sha256": "48e8f40c3fa0fd0ef53db6e2510a256c00aa028c2b43739c5fd7c4b23ec359bb",
    "remediation_fields": {
      "summary": "Use appropriate EBS performance settings where required by the workload.",
      "steps": [
        "Use appropriate EBS performance settings where required by the workload."
      ],
      "caveats": [
        "This is a performance preference, not proof of insecure storage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance is not declared EBS-optimized.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ebs_optimized",
      "predicate_source_sha256": "dab9c302055625a9de75b8beb9e6f39943e26f319576214a55609e97ed0d0ef2",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_profile_attached": {
    "description_base_sha256": "a79c4d4c1c794ef6f7a7a02ac66f4a7a90331a01fa280ae1e1c0522481981070",
    "description_fields": {
      "description": "Checks whether IamInstanceProfile is present."
    },
    "remediation_base_sha256": "a9151cc57b0d7f0f5199c953d58b44bf011240d91ba2a51dfe51bd8eb094b227",
    "remediation_fields": {
      "summary": "Attach a suitable least-privilege instance profile only if the workload needs AWS API access.",
      "steps": [
        "Attach a suitable least-privilege instance profile only if the workload needs AWS API access."
      ],
      "caveats": [
        "Instance-profile presence does not prove appropriate grants or absence of static credentials."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No IAM instance profile is declared on the applicable instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_profile",
      "predicate_source_sha256": "527a0496a88c6c529a83e256bc3ebf22388c361915e4689c515d74d543ff1f4d",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_profile_attached_not_terminated": {
    "description_base_sha256": "b0a1f133044979ae29f477a46c42f462c5e9f925ce543b234b354b504b604267",
    "description_fields": {
      "description": "For non-terminated instances, checks whether IamInstanceProfile is present."
    },
    "remediation_base_sha256": "47b382859c9951dd34fb54f095707d783bd4d0ba1aec9b938517ae583a5b402c",
    "remediation_fields": {
      "summary": "Attach a suitable least-privilege instance profile only if the workload needs AWS API access.",
      "steps": [
        "Attach a suitable least-privilege instance profile only if the workload needs AWS API access."
      ],
      "caveats": [
        "Terminated instances are not applicable; profile grants and credential use are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No IAM instance profile is declared on the applicable instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_profile_live",
      "predicate_source_sha256": "2f30cee75a508ec06c00969b4e6041ebe4e6d593a83eb2579eddf0ab2694a1b2",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_in_vpc": {
    "description_base_sha256": "c93b8ed41169715087aa86e8adf670feb8c52760e0c8bbb12a2da8a191df3655",
    "description_fields": {
      "description": "Checks whether a VpcId is declared on the instance."
    },
    "remediation_base_sha256": "778c2278aea18daa849f1fc80899c1d9280dba1a8993c4e03474c5176c7f9058",
    "remediation_fields": {
      "summary": "Use the intended supported VPC networking design when migrating legacy workloads.",
      "steps": [
        "Use the intended supported VPC networking design when migrating legacy workloads."
      ],
      "caveats": [
        "This checks metadata, not traffic filtering or actual routing."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has no VPC ID declaration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_in_vpc",
      "predicate_source_sha256": "989834c15deaaa181b82247ff3bc9f718039172bcac9511ba7373d98957b30a6",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_public_ip": {
    "description_base_sha256": "6cf15ffa31c80a30478ad6d2d44988c0f1f482270ab9be2b11c4bd1de14968db",
    "description_fields": {
      "description": "Checks whether a public IPv4 address is declared."
    },
    "remediation_base_sha256": "6a07b7edee777212c3e202c6169c3f47941f1849dd7f59494f1fbdd7c9dcef04",
    "remediation_fields": {
      "summary": "Remove unnecessary public addressing while preserving intended public services.",
      "steps": [
        "Remove unnecessary public addressing while preserving intended public services."
      ],
      "caveats": [
        "A public address does not prove a route, open listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public IPv4 address is declared on the instance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public",
      "predicate_source_sha256": "f8e774f8c22632bdc3e7273e2477feb5d11f919958ab9b5cb393570b7bebc820",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_public_ip_not_terminated": {
    "description_base_sha256": "fa60fd075db48e8117bc49004ef2e0407064018270b7fd34febb776587d7f76c",
    "description_fields": {
      "description": "For non-terminated instances, checks whether a public IPv4 address is declared."
    },
    "remediation_base_sha256": "5ddc853c04eb25e6807afe8d304e1944a5e220096cb80f07dd90bc72d41e4981",
    "remediation_fields": {
      "summary": "Remove unnecessary public addressing while preserving intended public services.",
      "steps": [
        "Remove unnecessary public addressing while preserving intended public services."
      ],
      "caveats": [
        "Terminated instances are not applicable; routes and listeners are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public IPv4 address is declared on the instance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public_live",
      "predicate_source_sha256": "414022a50fc541104a4d14053d944ac82d1888677f4be2b3047118c14bfac36a",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.public_instance_has_profile": {
    "description_base_sha256": "f72d8df0f91c12b9e28f39fe43c7714af79600d5647f2e0fb5c40169e318c0c4",
    "description_fields": {
      "description": "For instances declaring public IPv4, checks whether an IAM instance profile is present."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure a suitable profile if the publicly addressed workload needs AWS access.",
      "steps": [
        "Configure a suitable profile if the publicly addressed workload needs AWS access."
      ],
      "caveats": [
        "Instances without public IPv4 are not applicable; a profile is not proof of least privilege."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The publicly addressed instance declares no IAM instance profile.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_public_profile",
      "predicate_source_sha256": "d1b7dec2c9246fe63b15b3d4f307c5b2609c59e9414b5c0997a263c33fb5f2c6",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.internet_facing_without_profile": {
    "description_base_sha256": "8b836a484b4c235eedb9b822cd1a95a1f375c2ea983204e0044d81b0530401a0",
    "description_fields": {
      "description": "For non-terminated instances, flags the combination of public IPv4 and an instance profile."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review public addressing and the profile\u2019s required permissions before changing either.",
      "steps": [
        "Review public addressing and the profile\u2019s required permissions before changing either."
      ],
      "caveats": [
        "A public address plus role is not proof of exposed metadata or a usable escalation path."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The instance declares both a public IPv4 address and an IAM instance profile.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_internet_profile",
      "predicate_source_sha256": "0a0e0857b09553a1129b68f357c447870912c3f098e2dd79325b10e22176a6f1",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.running_instance_no_key_pair": {
    "description_base_sha256": "b1bbad8556c0027e75bdd081e23ff5fd9678f5eaf71660901bddcb13e648ad67",
    "description_fields": {
      "description": "For running instances, checks whether KeyName is declared."
    },
    "remediation_base_sha256": "2f7cedd3bb628526455d507905d85d2d50973b557ee1b203b9edadcdde27778a",
    "remediation_fields": {
      "summary": "Use the intended managed access method; retire unnecessary long-lived key-pair access safely.",
      "steps": [
        "Use the intended managed access method; retire unnecessary long-lived key-pair access safely."
      ],
      "caveats": [
        "Non-running instances are not applicable; a launch key name does not prove current SSH access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The running instance declares an EC 2 key-pair name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_key_pair",
      "predicate_source_sha256": "6fb941ad04bbb48dbcea8b7a3e7cb3f3a3735e43ed59ae3deaacbb1cb256dbce",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_imdsv2_applied": {
    "description_base_sha256": "9622d4004b4f0b57d6a1773cfb18734778af887a872b1a773a7479c447dd26eb",
    "description_fields": {
      "description": "Requires HttpTokens=required and metadata-option State=applied."
    },
    "remediation_base_sha256": "9da8d9944aeda05556bdbf8a414d8c119dc27b147dc41c062c8d029a18d7c628",
    "remediation_fields": {
      "summary": "Require IMDSv2 for intended workloads and verify the metadata change is applied.",
      "steps": [
        "Require IMDSv2 for intended workloads and verify the metadata change is applied."
      ],
      "caveats": [
        "The metadata endpoint\u2019s reachability from a process is not probed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Instance metadata tokens are not required or the settings are not applied.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_imdsv2_applied",
      "predicate_source_sha256": "19094d8d29e835da0de2d6bd6a3a093f963c3db4080826963a1a5f5fb4200a15",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_imdsv2_or_disabled": {
    "description_base_sha256": "9f27b16f103aa0c9134b077bf13e43b2e00ef17ceae93915f44110c52229dc78",
    "description_fields": {
      "description": "For non-terminated instances, requires tokens on enabled metadata endpoints or accepts a disabled endpoint."
    },
    "remediation_base_sha256": "35b8cfe3b3dd4f659c60f6a40f00a52386a7c4f359294cfeb080e89caa4eca53",
    "remediation_fields": {
      "summary": "Require IMDSv2 or disable unnecessary metadata access after checking workload requirements.",
      "steps": [
        "Require IMDSv2 or disable unnecessary metadata access after checking workload requirements."
      ],
      "caveats": [
        "Terminated instances are not applicable; metadata access paths are not exercised."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable metadata endpoint is not declared disabled or enabled with required tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_imdsv2_prowler",
      "predicate_source_sha256": "5177f8e2cf54fa8ee62a72a7465635fa93939b723a341e1fa11897a7d2fdfb9c",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_protected_by_backup": {
    "description_base_sha256": "e996aeb988c0769cfe28caf09b76fefe98241575471829c7b49cf1c26cbd7d94",
    "description_fields": {
      "description": "Matches the instance ARN to EC2 records in AWS Backup protected resources."
    },
    "remediation_base_sha256": "a264c29ab279a3b9ce8f0cf7986595f3d90c19d9be3e98dfe09f6284e7945075",
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "Alternative backup mechanisms and restore success are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_backup",
      "predicate_source_sha256": "6a6c47caee3aa306c2ba034a2171bbb231ae3af5a2453d026a5b6321c00f8349",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_no_launch_wizard_sg": {
    "description_base_sha256": "caefea18d2b1f8e9b683cd0463808dba50c5e73e0feec40e9a0e6f8d7370c13a",
    "description_fields": {
      "description": "Looks for attached security-group names beginning with launch-wizard."
    },
    "remediation_base_sha256": "cacfc987137bac134c5ce3cbbff98797a86641ea1bfe6258c548545fae369f87",
    "remediation_fields": {
      "summary": "Review the group\u2019s rules and replace or narrow unnecessary access as appropriate.",
      "steps": [
        "Review the group\u2019s rules and replace or narrow unnecessary access as appropriate."
      ],
      "caveats": [
        "A group name alone does not establish permissive rules or network exposure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security-group name begins with launch-wizard.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_launch_wizard",
      "predicate_source_sha256": "9935559ced0aaf79c1716936c8b4f5474516bfc2a79b4ec27f4a74229f6b163d",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_paravirtual": {
    "description_base_sha256": "3a1684fadde0a946532d3de03804d128feb70a67c9f05d7c5ff3bd6bdc5b4489",
    "description_fields": {
      "description": "Checks the instance VirtualizationType for the legacy paravirtual value."
    },
    "remediation_base_sha256": "e69c42be0a4c3fad4b7316e76d8634331467b985b6a73162364acbeadbe3b488",
    "remediation_fields": {
      "summary": "Plan a supported HVM migration if the workload no longer needs legacy virtualization.",
      "steps": [
        "Plan a supported HVM migration if the workload no longer needs legacy virtualization."
      ],
      "caveats": [
        "Virtualization type alone does not establish an exploitable vulnerability."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable instance declares paravirtual virtualization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_paravirtual",
      "predicate_source_sha256": "ed2d167e499586bfa6368fbb85a86d78de56f9b9102081b91d4599b7e702ddd2",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_paravirtual_not_terminated": {
    "description_base_sha256": "177cbab033d03aa5bb8b21750ad52c7a19c3014a54d455f4168d0e9335269f4e",
    "description_fields": {
      "description": "For non-terminated instances, compares VirtualizationType with paravirtual."
    },
    "remediation_base_sha256": "0b0a586ce824a2c42a67d2fb8512f7d177d11300686fb7e63536f85f2fdaa8d4",
    "remediation_fields": {
      "summary": "Plan a supported HVM migration if the workload no longer needs legacy virtualization.",
      "steps": [
        "Plan a supported HVM migration if the workload no longer needs legacy virtualization."
      ],
      "caveats": [
        "Terminated instances are not applicable; patch support requires separate review."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable instance declares paravirtual virtualization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_paravirtual_live",
      "predicate_source_sha256": "c3871fcd15dd230c7228ad8b8273e108530ffe1411003a083e5241936edeb1f8",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_termination_protection": {
    "description_base_sha256": "0f65b34ec5c7aa65a40e0241a62c535786c13415177b37c9bf24661fe50c259d",
    "description_fields": {
      "description": "Reads the instance DisableApiTermination protection flag and requires true."
    },
    "remediation_base_sha256": "0062a11b09b2b5649d68c5bd25d48153210beb4c3a894d0e37bb08f1bd480b17",
    "remediation_fields": {
      "summary": "Enable termination protection where accidental instance deletion must be prevented.",
      "steps": [
        "Enable termination protection where accidental instance deletion must be prevented."
      ],
      "caveats": [
        "This flag does not provide backups or prevent every form of workload termination."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "API termination protection is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_termination",
      "predicate_source_sha256": "1bd711aaf51e275f6cc2e4ebf31d1ee996ff5a8dabae3b42242003369f98cbaa",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_not_older_than_180_days": {
    "description_base_sha256": "20dc8ad6781e66f4fa064758d04fe0814dc1e39cc4d86afcd73fd3c4ed9bfb57",
    "description_fields": {
      "description": "Compares LaunchTime with midnight UTC 180 days before the snapshot."
    },
    "remediation_base_sha256": "c5d90b49096675a058f1a74b9da67386975b46d8c2f2063e44f31e3318b47d7e",
    "remediation_fields": {
      "summary": "Review patch and image-maintenance status before rebuilding an older instance.",
      "steps": [
        "Review patch and image-maintenance status before rebuilding an older instance."
      ],
      "caveats": [
        "Launch age is not an installed-patch or vulnerability assessment."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance launch predates the 180-day cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_age_compliance",
      "predicate_source_sha256": "9454d9bd05643430d69490794a0993a48f66efed5ee176617547d3b5b1706d1f",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.running_instance_age_180_days": {
    "description_base_sha256": "4758d52355ae990ac61cd6e9c74ac1fbcdc0fad005750bc75da223a7cc0c388a",
    "description_fields": {
      "description": "For running instances, flags whole days since launch greater than 180."
    },
    "remediation_base_sha256": "e94403423c9822cacf2ea67c8fb3300ce7a519ebb555671d96831d3d34648859",
    "remediation_fields": {
      "summary": "Review patch and image-maintenance status before rebuilding older running instances.",
      "steps": [
        "Review patch and image-maintenance status before rebuilding older running instances."
      ],
      "caveats": [
        "Non-running instances are not applicable; age does not prove missing security patches."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The running instance has more than 180 whole days since launch.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_age_prowler",
      "predicate_source_sha256": "55fc7a0f62cc6853a9cbd8c31e5a277eb7d8e85d5f355dfb38861ac90758aaab",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_30_days": {
    "description_base_sha256": "8621ab049eb321c0814a3f160298127ab5fc76eaab7d1af6f16a3107baa3c334",
    "description_fields": {
      "description": "For stopped or stopping instances, compares the parsed transition time with the midnight UTC30-day cutoff."
    },
    "remediation_base_sha256": "e9fe6579b5d243a691d9598d4ecc2e5267ac81d49eae510fa64fbc038a07fa30",
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring the stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring the stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; transition timestamps are parsed from provider metadata."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance transition is on or before the 30-day stopped-age cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_stopped_compliance.<locals>.evaluate",
      "predicate_source_sha256": "0924f0dca2b1b2de984f5a66d992cebcdf099dd259b21cf1128cb82969616802",
      "closure": {
        "days": 30
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_90_days": {
    "description_base_sha256": "ab316d2e8c0b36f7f10437fefd45f8fa985d3eaf7573513bde19a8372499440d",
    "description_fields": {
      "description": "For stopped or stopping instances, compares the parsed transition time with the midnight UTC90-day cutoff."
    },
    "remediation_base_sha256": "a505fba7d7cba8b8d437e6b0c2d3891b2b9e20b778533180b23f24c96a04ed5a",
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring the stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring the stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; transition timestamps are parsed from provider metadata."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance transition is on or before the 90-day stopped-age cutoff.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_stopped_compliance.<locals>.evaluate",
      "predicate_source_sha256": "0924f0dca2b1b2de984f5a66d992cebcdf099dd259b21cf1128cb82969616802",
      "closure": {
        "days": 90
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.stopped_instance_more_than_30_days": {
    "description_base_sha256": "426acd468c9c301c2b744bcb4241430b4cf2716fb24de8aa4c17eb2a65ae29ce",
    "description_fields": {
      "description": "For stopped instances, parses the transition timestamp and flags more than 30 whole days."
    },
    "remediation_base_sha256": "ef92b03381156ad4be08c668c5174a1991f8ee23c6cda73788c7e3cdef76f833",
    "remediation_fields": {
      "summary": "Review ownership and recovery purpose before restarting or retiring an old stopped instance.",
      "steps": [
        "Review ownership and recovery purpose before restarting or retiring an old stopped instance."
      ],
      "caveats": [
        "Other states are not applicable; unresolved transition timestamps remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance has been stopped for more than 30 whole days.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "stopped_prowler",
      "predicate_source_sha256": "a2d4cc9df050214d2b7f143cceb13b4ae72e5f9d3e514a79dc15df1edfdc14d5",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ebs_delete_on_termination": {
    "description_base_sha256": "78bc4066c998c574786f31131672a8192bee30e203a7700c2a0e70b246427282",
    "description_fields": {
      "description": "Checks EBS block mappings for DeleteOnTermination=false."
    },
    "remediation_base_sha256": "fd3a7445e29dcc221ba714594b2de17173a0d4ac18852f6e3f2c7bc34f77432c",
    "remediation_fields": {
      "summary": "Set automatic deletion only for disks whose data should not outlive the instance.",
      "steps": [
        "Set automatic deletion only for disks whose data should not outlive the instance."
      ],
      "caveats": [
        "Intentional persistent volumes can safely use false; disk contents and recovery needs are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An EBS block-device mapping declares deletion-on-termination disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_dot",
      "predicate_source_sha256": "5e5d9b0709d620ba19227e841894a9b6c5c63f390b43dcdd5ab9aae9f68af897",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_single_eni": {
    "description_base_sha256": "877ddcea4e318511505ade40ade6b880daf630fc9ea59f75f9b7c1d85c9ab813",
    "description_fields": {
      "description": "Counts declared instance network interfaces and requires exactly one."
    },
    "remediation_base_sha256": "15403cb439e185e47d773dcaa001ad9c52842c2e7ec65a174c56d6d6304e8477",
    "remediation_fields": {
      "summary": "Retain only the interfaces required by the intended workload or network appliance.",
      "steps": [
        "Retain only the interfaces required by the intended workload or network appliance."
      ],
      "caveats": [
        "Multiple interfaces can be intentional; their count alone does not prove bypass or exposure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance does not declare exactly one network interface.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_enis",
      "predicate_source_sha256": "ad5dad51fc5ad5b1c2b4d6b1451f63b3e5f460a14e6d40af5280658e4f144847",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_single_attachable_eni": {
    "description_base_sha256": "20e1a983a0492e5dfd6d05c9f8cf2a874ded7db5db8ff8bf4f6acb202c24aa2a",
    "description_fields": {
      "description": "Joins attached interfaces and counts efa, interface and trunk types, requiring at most one."
    },
    "remediation_base_sha256": "d46c2dcd263b1e17cebb1fd05bb7e7eb203c8f2b6f7855917e8f0326340bdae7",
    "remediation_fields": {
      "summary": "Retain the interfaces needed by the intended network design.",
      "steps": [
        "Retain the interfaces needed by the intended network design."
      ],
      "caveats": [
        "Zero interfaces passes this count preference; missing referenced inventory remains undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "More than one counted attachable network interface is present.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_enis_prowler",
      "predicate_source_sha256": "a639f57f29022d871ec058e216e30073c425df589badba0ab9c3c066d5c4f9bf",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ssm_managed": {
    "description_base_sha256": "1e451de457bb8d426ed625f3cc12ab3920f5aa2def005f18ef7455af3890aa52",
    "description_fields": {
      "description": "Except stopped instances, joins the instance ID to Systems Manager managed-instance records."
    },
    "remediation_base_sha256": "ea71c3ea29979e84ede77b894320f9a88bc1bd516342455d1c12abeb02529457",
    "remediation_fields": {
      "summary": "Register with Systems Manager if it is the intended management system and grant only required permissions.",
      "steps": [
        "Register with Systems Manager if it is the intended management system and grant only required permissions."
      ],
      "caveats": [
        "Stopped instances are not applicable; registration does not prove online status or patch compliance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No matching Systems Manager managed-instance record is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ssm",
      "predicate_source_sha256": "362ba363259ee4e62760a433ddd34f9684120638bb8505766595b7ba4c301686",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.active_instance_ssm_managed": {
    "description_base_sha256": "e050f39570b51b47e79942ee20c74c7662eed5230915d2785c72287875ac7630",
    "description_fields": {
      "description": "Except pending, terminated and stopped instances, joins the instance ID to Systems Manager records."
    },
    "remediation_base_sha256": "b09b49ba4c73d710ea56661d3daaa059b2887948919fb7e9603856d6e2857a7e",
    "remediation_fields": {
      "summary": "Register with Systems Manager if it is the intended management system and grant only required permissions.",
      "steps": [
        "Register with Systems Manager if it is the intended management system and grant only required permissions."
      ],
      "caveats": [
        "Excluded states are not applicable; registration is distinct from online health and patch compliance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No matching Systems Manager managed-instance record is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_ssm_prowler",
      "predicate_source_sha256": "0f306b6c24660fdae0f8cde93d6bbe000a923da1dd338bbbe541ff280b166f72",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_ami_not_deprecated": {
    "description_base_sha256": "cd5eeda7196013d921d4c17fb1058cdf7a9398006de739dc3c5a4507f757c444",
    "description_fields": {
      "description": "Joins the instance AMI to visible Amazon-owned images and compares DeprecationTime with the snapshot."
    },
    "remediation_base_sha256": "a9d90811e3ffce6db333d9cc23a913c5d4274387bf0e542028392cced9d6b263",
    "remediation_fields": {
      "summary": "Review support and rebuild from an appropriate supported image when needed.",
      "steps": [
        "Review support and rebuild from an appropriate supported image when needed."
      ],
      "caveats": [
        "Non-Amazon or invisible images are not applicable; deprecation is not a direct vulnerability scan."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The instance\u2019s Amazon-owned AMI deprecation time is before the snapshot.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "inst_outdated_ami",
      "predicate_source_sha256": "ad2259c43223290a3d68cc2b7b3187886bf8e338df4b05d4f74822c47809b74b",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_imdsv2": {
    "description_base_sha256": "f4dfe2d02f5ae1bd1c16ecc84df2e3ab2edd3faf712459b4944d1f457e1a13ff",
    "description_fields": {
      "description": "For active Nitro Enclave parents, requires HttpTokens=required."
    },
    "remediation_base_sha256": "7de05c387d7097eaaac6924fae9b231cb16fc8ce5ebe175859a296120fcfdb25",
    "remediation_fields": {
      "summary": "Require IMDSv2 on applicable enclave parent instances.",
      "steps": [
        "Require IMDSv2 on applicable enclave parent instances."
      ],
      "caveats": [
        "Non-parent and excluded lifecycle states are not applicable; no metadata request is sent."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The enclave parent does not declare required IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_imds",
      "predicate_source_sha256": "4d0101498e779a673c21968f5dfcae6f105df40c6353c3cdb8bfa43c67511e80",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_running": {
    "description_base_sha256": "2ec7a83b60fbfca0fca6260a5d9fd6713296862becb13a62d90bfca851010b5a",
    "description_fields": {
      "description": "For Enclave-enabled instances, flags stopped, shutting-down or terminated state."
    },
    "remediation_base_sha256": "f8d1816ce2d631f834120214ee026e0d6cc173336520200c429dc55dfce2c0fa",
    "remediation_fields": {
      "summary": "Review the host\u2019s purpose before restarting it or retiring obsolete attestation dependencies.",
      "steps": [
        "Review the host\u2019s purpose before restarting it or retiring obsolete attestation dependencies."
      ],
      "caveats": [
        "An enabled flag does not prove an enclave workload currently exists."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Enclave-enabled host is stopped, shutting down or terminated.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_running",
      "predicate_source_sha256": "b3de1c64bcb56576a550896da5333eb611cdb525a69f5029dc49ebffd17edee3",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_not_public": {
    "description_base_sha256": "fb1e59fa7ffc4787432c8abcc1a0d0db1dcf83cf3688aaae9180e13b4bd22a2e",
    "description_fields": {
      "description": "For active enclave parents, inspects public IPv4, global attached IPv6 and subnet Internet-gateway default routes."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove unnecessary public addressing or routing from enclave parents after preserving required access.",
      "steps": [
        "Remove unnecessary public addressing or routing from enclave parents after preserving required access."
      ],
      "caveats": [
        "These are separate declared exposure signals, not proof of an end-to-end reachable listener."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The enclave parent has a public address or a declared Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_public",
      "predicate_source_sha256": "a8aad0c1057c985d4b6932ac12f83cb01b37fde3a619daedd09343519793edac",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_ingress_allowlist": {
    "description_base_sha256": "26c63a34786cacf3bd5c65c56b3d1f07bceb2822df71d90ecdbeebc9e723e3fe",
    "description_fields": {
      "description": "For enclave parents, flags public-CIDR TCP/UDP ranges extending beyond 22,80 and 443."
    },
    "remediation_base_sha256": "d46504be594a2b56c51f981c702cdcb88e270e353a06ebd108a7b33e710e71b0",
    "remediation_fields": {
      "summary": "Restrict unnecessary public-source ports to the sources that need them.",
      "steps": [
        "Restrict unnecessary public-source ports to the sources that need them."
      ],
      "caveats": [
        "The source\u2019s fixed allowance includes SSH; required services, routes and listeners are not independently validated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An enclave-parent group permits public-source traffic outside the fixed port allowance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_ingress",
      "predicate_source_sha256": "83c85c6c73f30e691e2fea2384cf87f652c6312f1771971ac43555ec5cc65e77",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.enclave_host_vsock_ports_closed": {
    "description_base_sha256": "e83524a561fc874fc195448e42037036c94bb6547fa4c148d5261f4b4eb751ee",
    "description_fields": {
      "description": "For enclave parents, matches public-source TCP rules against 5000,8000\u20138090 and 9000."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Restrict unnecessary public-source access to the matched listener ports.",
      "steps": [
        "Restrict unnecessary public-source access to the matched listener ports."
      ],
      "caveats": [
        "The check matches conventional port numbers; it does not prove a vsock proxy or full network path exists."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An enclave-parent security group permits public-source access to a listed vsock-proxy port.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "enclave_vsock",
      "predicate_source_sha256": "a8ffc8aaa412f994cb584270ea95611253ff6ac409032ab22d92f90c335ca3c9",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_cassandra_not_internet_exposed": {
    "description_base_sha256": "38927b8c6a300283c8b65e6df479a3dd6a70b75e98f202a8427ba2c5787dc40e",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 7000, 7001, 7199, 9042, 9160."
    },
    "remediation_base_sha256": "dd7499f98b73912e1dac10a71b250e2535fd6d1f6f242f1664d9abcb986bc714",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 7000, 7001, 7199, 9042, 9160.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          7000,
          7001,
          7199,
          9042,
          9160
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_cifs_not_internet_exposed": {
    "description_base_sha256": "1001089928c0af0fba343132bb76755f4bb68a30c6fad5de982135a80ce9ccc9",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 139, 445."
    },
    "remediation_base_sha256": "d57d0ccf3df6f1018388301e76edf63b2399b1f516cec66ed93c70e70d2618b4",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 139, 445.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          139,
          445
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_elasticsearch_kibana_not_internet_exposed": {
    "description_base_sha256": "b657f049c12383a22839b4a46b63e358fae4199cea6c2bb14b0b25b2447cc543",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 9200, 9300, 5601."
    },
    "remediation_base_sha256": "67bea0c1e8e4dd1fa83bfb93e537fd9ce04656a46db4268a00b0ea00754cee64",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 9200, 9300, 5601.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          9200,
          9300,
          5601
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ftp_not_internet_exposed": {
    "description_base_sha256": "19cbfd7b27fef6a74aeb4e8d70035bdaf1cfd59ffeb2658e8f6770e1efd2664a",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 20, 21."
    },
    "remediation_base_sha256": "fbf38cca9697f911001a8f885ccf3c88cc1f5346de3044d829c7dd34104e26c0",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 20, 21.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          20,
          21
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_kafka_not_internet_exposed": {
    "description_base_sha256": "bbfe002b5a4d1c681d3ada6fb9fd511f2963254edbf94f90bbfaf15062fc3e87",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 9092."
    },
    "remediation_base_sha256": "33982433a8d657df6789713b6c35aee824a9c1de07c848cf342b1a2aa7d15308",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 9092.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          9092
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_kerberos_not_internet_exposed": {
    "description_base_sha256": "1e0814d39ba2c2747990fb563b8408f34f8a63533af5751d44d05d262661038b",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 88, 464, 749, 750."
    },
    "remediation_base_sha256": "875c4f02d19b54142741c5a3c0aa615978f7c61e5ca6aba9ba48220c31f9837a",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 88, 464, 749, 750.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          88,
          464,
          749,
          750
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ldap_not_internet_exposed": {
    "description_base_sha256": "ea32837be19263282cb32028db05b6d0fccb0f91d8303ccc50d5da3132a53225",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 389, 636."
    },
    "remediation_base_sha256": "1cbfbd700b3907af904209f2e4b5d1b8cd86b770899afdb1ea0afb4b66637037",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 389, 636.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          389,
          636
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_memcached_not_internet_exposed": {
    "description_base_sha256": "a11c366b7566a03df96e45962957c0e2ee23919b96f49d9b684758b05d939f44",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 11211."
    },
    "remediation_base_sha256": "073241323dece35f93f43b787adb4c0fed5d62288bedc892702f49f998c47a4a",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 11211.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          11211
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_mongodb_not_internet_exposed": {
    "description_base_sha256": "9892092e709b5e0d2c58a2da10e9013d900e800389069f44f56211847ed7756b",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 27017, 27018."
    },
    "remediation_base_sha256": "a5037da9782805006b428652292c61927ce038c83f65491f16a40bbf3011def8",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 27017, 27018.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          27017,
          27018
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_mysql_not_internet_exposed": {
    "description_base_sha256": "c9e7c2289d72b68b3edea9a179c8060421f7978d91af505015f05716503e8cce",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 3306."
    },
    "remediation_base_sha256": "3f481ae65f5adba3cab35e50b685a1d0ff025da138adf2ff9bf29ca942b7bd6c",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 3306.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          3306
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_oracle_not_internet_exposed": {
    "description_base_sha256": "a899a8738ee8e019b3fc82d126b87056d35cd8c58ee4e97623fe1e92b770dbbb",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 1521, 2483, 2484."
    },
    "remediation_base_sha256": "2bc87f3dbc87230c291192ec4a5d75b71d16ed00f3dd2ff182338aa5547b7372",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 1521, 2483, 2484.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          1521,
          2483,
          2484
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_postgresql_not_internet_exposed": {
    "description_base_sha256": "34f951c653081f48f64313a9b804f259cb9c70d768eacbe7063b318a831fe36a",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 5432."
    },
    "remediation_base_sha256": "26ca30b74edd9dacf2e61ce2a8761797b7072417958aab6da114292988d28326",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 5432.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          5432
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_rdp_not_internet_exposed": {
    "description_base_sha256": "0a2e9720708a359735f7acaef93a24db72a209c435dae41c1dc4df9345ccbdf9",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 3389."
    },
    "remediation_base_sha256": "048e00d1a33ef2e8ad0adc2b994493921ef01027e1c022c7ad9eb7cb492c9c5b",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 3389.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          3389
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_redis_not_internet_exposed": {
    "description_base_sha256": "1bc1dcba5f1c22f8a858e9fdfbbc1e49463cb77975c8e1ea4880beef98e606ec",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 6379."
    },
    "remediation_base_sha256": "7668437b033a1f090ee9362622268fffd555d046e90556182717fb6a683bbd1f",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 6379.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          6379
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_sqlserver_not_internet_exposed": {
    "description_base_sha256": "2877e8507f85650743775d86d6e4c500391f1c034a21abcf43febe3ce8d6cc29",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 1433, 1434."
    },
    "remediation_base_sha256": "521516bad693bdad78b39504b2facf144849da5a22e67f0d7ed1e6bbf3baf6e1",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 1433, 1434.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          1433,
          1434
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_ssh_not_internet_exposed": {
    "description_base_sha256": "5fb22f4ca3cf0c0b7ebe7527cf73048848137a28947849c1506f4ec0ae93ad82",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 22."
    },
    "remediation_base_sha256": "d855170ca3619534a4cf3afd896f40c175e2dba774438354182340cfe930aaa9",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 22.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          22
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.instance_port_telnet_not_internet_exposed": {
    "description_base_sha256": "e1f2259972c278c51b1973502f97fd22716e7b45429bb98dd1b0eee83f61bbf0",
    "description_fields": {
      "description": "Joins instance security groups and matches global-source TCP rules against ports 23."
    },
    "remediation_base_sha256": "79d0a05e42ef58009c1c184c2ca756ec07323875491425ee7940cfad8f7bf3d4",
    "remediation_fields": {
      "summary": "Restrict unnecessary matching public-source ports to the clients that need access.",
      "steps": [
        "Restrict unnecessary matching public-source ports to the clients that need access."
      ],
      "caveats": [
        "This is a security-group declaration match, not proof of routing, a listener or authentication bypass."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An attached security group allows global-source TCP traffic to at least one of ports 23.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_instance_port_check.<locals>.evaluate",
      "predicate_source_sha256": "654811e74a8389bae376e9b8236a1b059667834ababefcbd57b33dc77461e055",
      "closure": {
        "ports": [
          23
        ]
      }
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_default_imdsv2": {
    "description_base_sha256": "ef4552a06de33ee3d9a2678f0316e9406967630a7222f08a1850cd933061172b",
    "description_fields": {
      "description": "Reads the single marked default launch-template version and requires HttpTokens=required."
    },
    "remediation_base_sha256": "13c05ed902967e0d7cba404e8af56276462672602096abbc26f9eb3d4c1eace9",
    "remediation_fields": {
      "summary": "Create the intended metadata configuration and update the default version after compatibility review.",
      "steps": [
        "Create the intended metadata configuration and update the default version after compatibility review."
      ],
      "caveats": [
        "Inherited settings and a deliberately disabled endpoint do not satisfy this explicit-token preference."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The default launch-template version does not explicitly require IMDSv2 tokens.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_default_imds",
      "predicate_source_sha256": "82a8bbe45a033d478f1fb0b8099a9b49820410881c18d5a85cb785a75e0df8d9",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_default_ebs_encrypted": {
    "description_base_sha256": "6879d9b73882a4d0c9fb4bfba812caee6df2cd04cb90b4cebb2d80877f3d5260",
    "description_fields": {
      "description": "In the default template version, checks EBS mappings for Encrypted=true."
    },
    "remediation_base_sha256": "9ecf186d6ef0317c441f1c90236161d7f82ad2e2394c5e8cfeb1969c9a21b988",
    "remediation_fields": {
      "summary": "Declare required EBS encryption while preserving the intended launch behavior.",
      "steps": [
        "Declare required EBS encryption while preserving the intended launch behavior."
      ],
      "caveats": [
        "No mappings is not applicable; regional encryption defaults and referenced snapshots are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An EBS mapping in the default template lacks Encrypted=true.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_default_ebs",
      "predicate_source_sha256": "2a03fbab5d24a5aba012d1616076157c38da55157fe98e96fec4747cd826514c",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_any_version_imdsv2": {
    "description_base_sha256": "94285d7f320e0a188f22ae9748c50febda84bc9135a69391d96122883ae70d1a",
    "description_fields": {
      "description": "Checks every collected version for required tokens on enabled metadata or an explicitly disabled endpoint."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review selectable versions and update intended consumers to suitable metadata settings.",
      "steps": [
        "Review selectable versions and update intended consumers to suitable metadata settings."
      ],
      "caveats": [
        "Omitted or unrecognized metadata settings remain undetermined; the source does not resolve inheritance."
      ],
      "cli": [],
      "references": [
        {
          "title": "Amazon EC2 read-only API reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "A launch-template version explicitly enables metadata with optional tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_versions_imds",
      "predicate_source_sha256": "b5e3bf6e17c07575efcc0bfc0e0bb7d4bb08d4cebd1d4f61762a4cbc2e725244",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_no_public_ip": {
    "description_base_sha256": "a12915acc070793f4178bfeadaf82fd9a5505c111c77ee97cc18d8a35963b0b2",
    "description_fields": {
      "description": "Looks for AssociatePublicIpAddress=true in any template-version network interface."
    },
    "remediation_base_sha256": "0e326d187d3dc9cdafcdfb6ef3f04d264a0a90c841ad0ec1273735ea6da93cc7",
    "remediation_fields": {
      "summary": "Remove unnecessary automatic public IPv4 assignment from intended launch versions.",
      "steps": [
        "Remove unnecessary automatic public IPv4 assignment from intended launch versions."
      ],
      "caveats": [
        "Existing ENI references remain undetermined; omission does not resolve subnet public-IP defaults."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A template version declares automatic public IPv4 assignment.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_public_ip",
      "predicate_source_sha256": "8332f08efa39fe32e335dc47c20ffe0f09dcc378174d6d4e2cc44ed6fc981fc0",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.ec2.launch_template_instances_no_public_ip": {
    "description_base_sha256": "d09c81011739a1f2d324fd5eb041b5d40c3d057c49e873c7a372e18d7a520d00",
    "description_fields": {
      "description": "Joins instances by launch-template ID tag and reads their returned launch interface data."
    },
    "remediation_base_sha256": "ad1a57d24e2d0f23aed9fed4712bb7c54b7121f2a84147332863f44f9b9c58f5",
    "remediation_fields": {
      "summary": "Review unnecessary public-IP assignment in the affected launch configuration and consumers.",
      "steps": [
        "Review unnecessary public-IP assignment in the affected launch configuration and consumers."
      ],
      "caveats": [
        "Templates without tagged instances are not applicable; this is not the instance\u2019s effective address or route."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A tagged instance\u2019s returned launch data enables public IPv4 assignment.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ec2_launch_template",
      "predicate_qualname": "lt_instances_public",
      "predicate_source_sha256": "ce2e2aa97441112491b38b9cb10d6c6c83fd9efadc147bd7651a695711286162",
      "closure": {}
    },
    "batch": "ec2-ebs"
  },
  "aws.claude_a.s3.bucket_public_access_block_all": {
    "batch": "s3-native18",
    "description_base_sha256": "34d492d46f74bbc6196a771358c422ef06a4b78b00e0ceefc46b7143e1eb1abd",
    "description_fields": {
      "description": "Reads all four bucket-level Block Public Access flags and requires true for each."
    },
    "remediation_base_sha256": "4d9812c555502bb38dd9032abc22be62ebb5d87cd6f66e30b33d972011ae7959",
    "remediation_fields": {
      "summary": "Enable the intended bucket-level public-access protections without breaking deliberate public content.",
      "steps": [
        "Enable the intended bucket-level public-access protections without breaking deliberate public content."
      ],
      "caveats": [
        "Account-level protection is not combined by this bucket-only baseline; a false flag does not prove public data."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one bucket-level Block Public Access flag is false.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "bucket_all",
      "predicate_source_sha256": "b282da92bab0948a2ae57caa12238bd0031c174b0322e2efb6e6b7f611637f71",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_bucket_level_public_access_block": {
    "batch": "s3-native18",
    "description_base_sha256": "01b7799bd8c1cd151b27fc41b25f43d1e4c1deb6892fa3760d07e58ad4a74254",
    "description_fields": {
      "description": "Requires IgnorePublicAcls and RestrictPublicBuckets at either bucket or account level."
    },
    "remediation_base_sha256": "867d9280c9c61c7cf8887d97278cbccd5685eee02ac7dfa5de56fc45094271ad",
    "remediation_fields": {
      "summary": "Configure the intended protections at the appropriate bucket or account scope.",
      "steps": [
        "Configure the intended protections at the appropriate bucket or account scope."
      ],
      "caveats": [
        "This checks two protective flags, not actual object access or all four public-block settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Neither modeled bucket nor account configuration provides both required public-access flags.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_bucket_level",
      "predicate_source_sha256": "7ad2bac6eaaadac09a8bccb2348a8d83c921f8becd53c8468b47e8d78a540f72",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_kms_encryption": {
    "batch": "s3-native18",
    "description_base_sha256": "19ffe73b791913aca4bee858066e9f636e385c8e3c4e85d21be33fd3852b6305",
    "description_fields": {
      "description": "Reads the first default-encryption rule and accepts aws:kms or aws:kms:dsse."
    },
    "remediation_base_sha256": "7fb94584bcbadd4316d7cadb7c5c88a441789563edf49457c4bc90d308aa841f",
    "remediation_fields": {
      "summary": "If KMS encryption is required, configure the supported default and review existing objects separately.",
      "steps": [
        "If KMS encryption is required, configure the supported default and review existing objects separately."
      ],
      "caveats": [
        "SSE-S3 is encryption too; the default does not establish existing-object encryption or a customer-managed key."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The first default-encryption rule is absent or does not select SSE-KMS/DSSE-KMS.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_kms",
      "predicate_source_sha256": "431de4565b88a34229d949978f8e35efa705b95a180fc34d075c65232ea06474",
      "closure": {}
    }
  },
  "aws.claude_a.s3.replication_rule_enabled": {
    "batch": "s3-native18",
    "description_base_sha256": "a423600249fd1056d84bb97ed406edf8977bbcc1c458b3c594f286077ba1fc74",
    "description_fields": {
      "description": "Looks for any replication rule with Status=Enabled."
    },
    "remediation_base_sha256": "7e020ef759cbf7b533c12c60b6e4680f322df1eb408f0a739b72e234d23cb694",
    "remediation_fields": {
      "summary": "Configure replication only where the recovery or distribution design needs it.",
      "steps": [
        "Configure replication only where the recovery or distribution design needs it."
      ],
      "caveats": [
        "The rule destination Region, delivery and recovery outcome are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled replication rule is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "replication_enabled",
      "predicate_source_sha256": "140c052f8c4a4bd91c008b01084b5b8d41548b4f1e4e77f8cb7a1730fb8fea8d",
      "closure": {}
    }
  },
  "aws.claude_a.s3.lifecycle_rule_enabled": {
    "batch": "s3-native18",
    "description_base_sha256": "90502b777aace7f3f7ac45918df90279e2c36c1c964219cd7efa8cc2b1744d72",
    "description_fields": {
      "description": "Looks for any lifecycle rule with Status=Enabled."
    },
    "remediation_base_sha256": "f73fe30b00d68adb53f7effd9cd291bcaaa28b24680df1047663e051236ef12a",
    "remediation_fields": {
      "summary": "Configure appropriate lifecycle transitions or expiry where needed, preserving required retained data.",
      "steps": [
        "Configure appropriate lifecycle transitions or expiry where needed, preserving required retained data."
      ],
      "caveats": [
        "A missing lifecycle rule is not evidence of public data or failed recovery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled lifecycle rule is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "lifecycle",
      "predicate_source_sha256": "1223ce97bb015cfbf64e46afc0ff5795c98f0c3ec0b2ce633cd791d91207556e",
      "closure": {}
    }
  },
  "aws.claude_a.s3.versioning_and_lifecycle": {
    "batch": "s3-native18",
    "description_base_sha256": "8c59263ea4756cfcf43201a95ce7a58363164af7028bea350bdfdd13a83a6e98",
    "description_fields": {
      "description": "For version-enabled buckets, looks for any enabled lifecycle rule."
    },
    "remediation_base_sha256": "ef1b74a411c19e41c805838ff6369e636ea623f071ceaa6ed3828500479d6d88",
    "remediation_fields": {
      "summary": "Configure lifecycle management suitable for the retained object versions.",
      "steps": [
        "Configure lifecycle management suitable for the retained object versions."
      ],
      "caveats": [
        "Other versioning states are not applicable; retention adequacy and recovery are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The version-enabled bucket has no enabled lifecycle rule.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "versioning_lifecycle",
      "predicate_source_sha256": "b417c6684ce24619b04496e3d841d3f5baab400c4c34510a62da0c74ac1143cf",
      "closure": {}
    }
  },
  "aws.claude_a.s3.object_lock_configured": {
    "batch": "s3-native18",
    "description_base_sha256": "50d60d129e1d52446eef252337268bc5f54dee05ea0cec462b330dee543bf394",
    "description_fields": {
      "description": "Checks whether an Object Lock configuration is returned."
    },
    "remediation_base_sha256": "76e442a0f3092061ed41fb5546c12bd5d01c93e42cf7eafd3d6b6934cba5e318",
    "remediation_fields": {
      "summary": "If immutable retention is required, configure supported Object Lock and suitable retention safely.",
      "steps": [
        "If immutable retention is required, configure supported Object Lock and suitable retention safely."
      ],
      "caveats": [
        "Configuration presence does not validate retention periods, legal holds or actual object immutability."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No Object Lock configuration is returned for the bucket.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "object_lock",
      "predicate_source_sha256": "96caf5b77a25c99e2dae04d86a6e80bb39d88dfcaf5f00af7fd655b249fdb743",
      "closure": {}
    }
  },
  "aws.claude_a.s3.event_notifications": {
    "batch": "s3-native18",
    "description_base_sha256": "ff476349500368b4bdb7024c42a84d79902a686d89f1884311a21a873fee66fd",
    "description_fields": {
      "description": "Looks for nonempty topic, queue or Lambda notification configuration, or a present EventBridge configuration."
    },
    "remediation_base_sha256": "b3a6cd4bdb4606e05994c9091f2af87b8f87de8f79923b82429fcccea241215a",
    "remediation_fields": {
      "summary": "Configure event notifications only for the integrations that need them.",
      "steps": [
        "Configure event notifications only for the integrations that need them."
      ],
      "caveats": [
        "Configuration presence does not prove event delivery or destination authorization."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No recognized S 3 event-notification configuration is declared.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "notifications",
      "predicate_source_sha256": "125ee22fcdf1336f417c96dc75421232f0c3d950da182c8630a73d1ff7da67a0",
      "closure": {}
    }
  },
  "aws.claude_a.s3.acls_prohibit_user_access": {
    "batch": "s3-native18",
    "description_base_sha256": "8ed5e8f8b4e5daf6c2857dec25cb5f7f821656f835f1adf5190fff743ea2f9ae",
    "description_fields": {
      "description": "Accepts BucketOwnerEnforced; otherwise compares canonical ACL grantee IDs with the owner ID."
    },
    "remediation_base_sha256": "42f87797ff977f76b2f6414421d2963be09722bf9ff96d7861392fae93fbc6bb",
    "remediation_fields": {
      "summary": "Review non-owner ACL grants and migrate intended readers before removing unnecessary grants.",
      "steps": [
        "Review non-owner ACL grants and migrate intended readers before removing unnecessary grants."
      ],
      "caveats": [
        "URI group grants and effective public-access blocking are not evaluated by this particular predicate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A canonical-user ACL grant identifies a principal other than the bucket owner.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "acl_users",
      "predicate_source_sha256": "34e34bbc5b68d0f7587b250180a170366674dfe75a9cbd1cce7c8590c075a122",
      "closure": {}
    }
  },
  "aws.claude_a.s3.no_authenticated_users_acl": {
    "batch": "s3-native18",
    "description_base_sha256": "3954f7c63312d003bce9c34c680d195ad2d858631ee59f3270fcc02de2e20f79",
    "description_fields": {
      "description": "Looks for any bucket ACL grant to the global AuthenticatedUsers group."
    },
    "remediation_base_sha256": "3617779ac9dac42297cf544e91858d3bd53a309fc3e84b1db101229a34e2a988",
    "remediation_fields": {
      "summary": "Remove unnecessary AuthenticatedUsers grants after preserving intended client access.",
      "steps": [
        "Remove unnecessary AuthenticatedUsers grants after preserving intended client access."
      ],
      "caveats": [
        "AuthenticatedUsers spans AWS accounts; Block Public Access and ACL-disablement effects are not evaluated here."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket ACL grants a permission to the global AuthenticatedUsers group.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "no_auth_users",
      "predicate_source_sha256": "c22ed95451ba2dd78ea9212224222228cd174812afa0a43acbe62a8fc6236924",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_acl_disabled": {
    "batch": "s3-native18",
    "description_base_sha256": "48033bb932737a75493d25d08e4610a4f489af32dd3ca9a93269992eacce2380",
    "description_fields": {
      "description": "Reads the first Object Ownership rule and checks for BucketOwnerEnforced."
    },
    "remediation_base_sha256": "c524f468544bc7a5c3a0a96b34bbade133926e50d2c329128616c0cd685dcf1f",
    "remediation_fields": {
      "summary": "If ACLs are unnecessary, migrate intended permissions before enabling BucketOwnerEnforced.",
      "steps": [
        "If ACLs are unnecessary, migrate intended permissions before enabling BucketOwnerEnforced."
      ],
      "caveats": [
        "Other ownership models can be intentional; the absence of this setting does not establish public access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket does not declare BucketOwnerEnforced in its first ownership rule.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_acl_disabled",
      "predicate_source_sha256": "ba3c5deeabdb1107cddf5e1c055919128929e98109aa8ee2e0e84d3f147e50ef",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_public_list_acl": {
    "batch": "s3-native18",
    "description_base_sha256": "8bfa74a032d84d69efd1b35d740b7d07c082829709439beb0bb255aef649d746",
    "description_fields": {
      "description": "Looks for AllUsers or AuthenticatedUsers ACL grants of FULL_CONTROL, READ or READ_ACP, unless the modeled bucket/account blocking flags mitigate them."
    },
    "remediation_base_sha256": "7d97ee07cd6eec7c1c82ac5df7b04c2638c245e16b0939bdb83e3ec18d308e4f",
    "remediation_fields": {
      "summary": "Remove unnecessary public-group ACL grants after preserving intended access.",
      "steps": [
        "Remove unnecessary public-group ACL grants after preserving intended access."
      ],
      "caveats": [
        "READ_ACP concerns ACL visibility, not object reads; WRITE_ACP concerns ACL changes. No object or bucket access is attempted."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public-group ACL grant matches FULL_CONTROL, READ or READ_ACP without the modeled blocking mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "_public_case.<locals>.evaluate",
      "predicate_source_sha256": "5aaa453ca4a2da6238edeebeb55eb905a56e6f80e67a650d480ead28d36a34ac",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_public_write_acl": {
    "batch": "s3-native18",
    "description_base_sha256": "11ec9b5461313bf67e3b386a605e1ff7c9c0f5c6bf226123196db666c9756154",
    "description_fields": {
      "description": "Looks for AllUsers or AuthenticatedUsers ACL grants of FULL_CONTROL, WRITE or WRITE_ACP, unless the modeled bucket/account blocking flags mitigate them."
    },
    "remediation_base_sha256": "4e91f5e40616006915a6ba6bab89fef6496c045326cde67fae0ede880093bcc5",
    "remediation_fields": {
      "summary": "Remove unnecessary public-group ACL grants after preserving intended access.",
      "steps": [
        "Remove unnecessary public-group ACL grants after preserving intended access."
      ],
      "caveats": [
        "READ_ACP concerns ACL visibility, not object reads; WRITE_ACP concerns ACL changes. No object or bucket access is attempted."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A public-group ACL grant matches FULL_CONTROL, WRITE or WRITE_ACP without the modeled blocking mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "_public_case.<locals>.evaluate",
      "predicate_source_sha256": "5aaa453ca4a2da6238edeebeb55eb905a56e6f80e67a650d480ead28d36a34ac",
      "closure": {}
    }
  },
  "aws.claude_a.s3.policy_no_cross_account_permission_changes": {
    "batch": "s3-native18",
    "description_base_sha256": "4480dd451914f8d18dc15be020122974080af3f18fcff3e339eedc8e268d1bcb",
    "description_fields": {
      "description": "Matches external AWS principals with the five exact listed bucket-permission-change actions."
    },
    "remediation_base_sha256": "a23b9281926f53c26465b87c67c95718f87f77494f0fb695a1beb41fc3776009",
    "remediation_fields": {
      "summary": "Remove or appropriately constrain unnecessary external permission-management grants.",
      "steps": [
        "Remove or appropriately constrain unnecessary external permission-management grants."
      ],
      "caveats": [
        "Action wildcards are not expanded; conditions, resource scope and effective authorization are not resolved."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The policy declares an external principal Allow for a listed bucket-permission-change action.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "cross_account_changes",
      "predicate_source_sha256": "42b97742db30756e4061fd062d36cdc979695aae9a839b8f031e2f41ff7bcc1e",
      "closure": {}
    }
  },
  "aws.claude_a.s3.perimeter_policy_not_public": {
    "batch": "s3-native18",
    "description_base_sha256": "98245bf5c5ef022debdefd737dce642d825f9a3df5b90cbb45c98e48c95acc01",
    "description_fields": {
      "description": "Applies the bounded perimeter-policy matcher to stored Allow principals and recognized condition forms."
    },
    "remediation_base_sha256": "79bc7e89e5b1fc39c55dc7524cf65a1099e4dd01715869c9787c0deb4cfa1ce5",
    "remediation_fields": {
      "summary": "Review unnecessary public principals and apply suitable intended account or organization restrictions.",
      "steps": [
        "Review unnecessary public principals and apply suitable intended account or organization restrictions."
      ],
      "caveats": [
        "No policy is not applicable; Block Public Access, denies and effective object access are not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored policy contains an Allow classified public by the bounded perimeter matcher.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "perimeter_policy",
      "predicate_source_sha256": "7bf25fb4bbd5b042a842a8fc4b3d3cb4c31ba2596fb94a782c2a10f48d96d54d",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_cross_account_policy": {
    "batch": "s3-native18",
    "description_base_sha256": "c6ed90f4462c4ad652cf6984cc388995153f08dc7332f81b2d06f4447cbbd212",
    "description_fields": {
      "description": "Applies the reviewed public-policy matcher with no trusted external accounts to bucket policy statements."
    },
    "remediation_base_sha256": "e5750e77cffacccdf1a3f1af032ed72581718aff21ac0f67a45aabfb08966d4d",
    "remediation_fields": {
      "summary": "Review external grants and remove or constrain unnecessary access while preserving intended sharing.",
      "steps": [
        "Review external grants and remove or constrain unnecessary access while preserving intended sharing."
      ],
      "caveats": [
        "Trusted-account exceptions are not configured; the result is not independent proof of effective access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket policy matcher identifies an external or public Allow.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_cross_account",
      "predicate_source_sha256": "9686ec985825f6b5ff614c79fae5df264f3f22b5d440b83a216bdcc9208370b1",
      "closure": {}
    }
  },
  "aws.claude_a.s3.prowler_policy_public_write": {
    "batch": "s3-native18",
    "description_base_sha256": "c1cbdb2b1a8f77decf16c18f46bddc12e48c06371c4210149ac5cef35e4ca14b",
    "description_fields": {
      "description": "Matches listed public-write policy actions unless bucket or account RestrictPublicBuckets is true."
    },
    "remediation_base_sha256": "77b113a271bb0cb407ac695ad914f01095e5c1c1df94c9d109fe3b1094988ea5",
    "remediation_fields": {
      "summary": "Remove unintended public-write grants or apply suitable protective restrictions.",
      "steps": [
        "Remove unintended public-write grants or apply suitable protective restrictions."
      ],
      "caveats": [
        "No object writes are performed; effective resource scope, denies and application intent require separate review."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The modeled policy permits public write without either RestrictPublicBuckets mitigation.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "prowler_public_write",
      "predicate_source_sha256": "0ba09cad81be90bd960d10d0ebae48536f2abee13fa28ccf768d04b13954972d",
      "closure": {}
    }
  },
  "aws.claude_a.s3.access_point_public_access_block": {
    "batch": "s3-native18",
    "description_base_sha256": "2b7aa4c073e3d54fadaa1c71fe253e2251185452ec02dfa6c0940ee0af8bc463",
    "description_fields": {
      "description": "Reads all four access-point Block Public Access flags and requires true for each."
    },
    "remediation_base_sha256": "7569ac2194ebd042fc08ffd655cebccb3c8ad5333bda1d21f86180b8b8a6669f",
    "remediation_fields": {
      "summary": "If stronger blocking is needed, plan a supported access-point replacement without disrupting required clients.",
      "steps": [
        "If stronger blocking is needed, plan a supported access-point replacement without disrupting required clients."
      ],
      "caveats": [
        "A known false flag proves this baseline failure; it does not establish a public bucket or successful access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one access-point Block Public Access flag is false.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "s3_access_point",
      "predicate_qualname": "access_point",
      "predicate_source_sha256": "8aa1967c7d5a7331b9f7844f7a75c53cdda668b85732b9e8f0bf0378968a12ad",
      "closure": {}
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_management_level_access": {
    "batch": "instance-role17",
    "description_base_sha256": "680e846dbf114799e4959d0d8d10feea8937d7e12d8a625fe2fc8e174c89ee8a",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed IAM management-level access action."
    },
    "remediation_base_sha256": "692e7918b6fefd864f594ad488fa0a7a231bee12b3a624d0f879f281dd96790c",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed IAM management-level access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:attachgrouppolicy",
          "iam:attachrolepolicy",
          "iam:attachuserpolicy",
          "iam:createpolicy",
          "iam:createpolicyversion",
          "iam:deleteaccountpasswordpolicy",
          "iam:deletegrouppolicy",
          "iam:deletepolicy",
          "iam:deletepolicyversion",
          "iam:deleterolepermissionsboundary",
          "iam:deleterolepolicy",
          "iam:deleteuserpermissionsboundary",
          "iam:deleteuserpolicy",
          "iam:detachgrouppolicy",
          "iam:detachrolepolicy",
          "iam:detachuserpolicy",
          "iam:putgrouppolicy",
          "iam:putrolepermissionsboundary",
          "iam:putrolepolicy",
          "iam:putuserpermissionsboundary",
          "iam:putuserpolicy",
          "iam:setdefaultpolicyversion",
          "iam:updateassumerolepolicy"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_data_destruction_access": {
    "batch": "instance-role17",
    "description_base_sha256": "180394ca31c7d771c8bfe4080e805454a9217028a270614ab83cfae9dfa3b3e8",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed data destruction access action."
    },
    "remediation_base_sha256": "650f81d38aff07f2e1d787652251c700711f67e23c56567e964e618280286c1e",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed data destruction access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "s3:deletebucket",
          "rds:deletedbcluster",
          "rds:deletedbinstance",
          "rds:deletedbsnapshot",
          "rds:deletedbclustersnapshot",
          "rds:deleteglobalcluster",
          "ec2:deletesnapshot",
          "ec2:deletevolume"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_database_management_write_access": {
    "batch": "instance-role17",
    "description_base_sha256": "c2f9f58fb1581d4f2c49d8af91faa075655759ace74c142cd108a06dec1fa2fc",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed database management write access action."
    },
    "remediation_base_sha256": "b4c3fe8287498945e793cb268f85f9e6cb0b4a93711fee367a4057a9b881480f",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed database management write access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "rds:modifydbcluster",
          "rds:modifydbclusterendpoint",
          "rds:modifydbinstance",
          "rds:modifydbsnapshot",
          "rds:modifyglobalcluster",
          "dynamodb:updateitem",
          "dynamodb:updatetable",
          "memorydb:updatecluster",
          "neptune-db:resetdatabase",
          "neptune-db:writedataviaquery",
          "docdb-elastic:updatecluster",
          "elasticache:modifycachecluster",
          "cassandra:alter",
          "cassandra:modify",
          "qldb:executestatement",
          "qldb:partiqlupdate",
          "qldb:sendcommand",
          "qldb:updateledger",
          "redshift:modifycluster",
          "redshift:modifyclustersnapshot",
          "redshift:modifyendpointaccess",
          "timestream:updatedatabase",
          "timestream:updatetable",
          "timestream:writerecords"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_privilege_escalation_risk_access": {
    "batch": "instance-role17",
    "description_base_sha256": "7fed23d46942e48cd8f6eb3192e3dc0e5859e22f68a0e9ac0263ad18e8e13e37",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed privilege escalation risk access action."
    },
    "remediation_base_sha256": "951971f5cf49c4d3c547b47c1bc52ca80800e1e11f56a78c389916dfaa3a9b1d",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed privilege escalation risk access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:createpolicy",
          "iam:createpolicyversion",
          "iam:setdefaultpolicyversion",
          "iam:passrole",
          "iam:createaccesskey",
          "iam:createloginprofile",
          "iam:updateloginprofile",
          "iam:attachuserpolicy",
          "iam:attachgrouppolicy",
          "iam:attachrolepolicy",
          "iam:putuserpolicy",
          "iam:putgrouppolicy",
          "iam:putrolepolicy",
          "iam:addusertogroup",
          "iam:updateassumerolepolicy"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_group_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_base_sha256": "30e0d04f96ff82791880f9ee1029c13c97b91f4e9dfe286c918b4e1cae769173",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_base_sha256": "3161d1ee1feed7b233279697d2e421c4f9331dcbf85c8ab116c4e8bdaa6eb46c",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new group creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:creategroup",
          "iam:attachgrouppolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_role_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_base_sha256": "de6832f24b27d67ea91c58570722cad9ad85d15cae3ea7a2816bcec809d2cd26",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_base_sha256": "82ee515fc0474dd9bd477776993895f3592db2100d6503264f45263beca3fc76",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new role creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:createrole",
          "iam:attachrolepolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_new_user_creation_with_attached_policy_access": {
    "batch": "instance-role17",
    "description_base_sha256": "0df48dfc56c7a19c388c3765da6a2309de64ffc0d4a71f7c178786ad307084d3",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_base_sha256": "f4a25f83331ebd75dc542846561e443778740d5aa99ad566f0ce0d0d9ffeab27",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed new user creation with attached policy access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:createuser",
          "iam:attachuserpolicy"
        ],
        "all_of": true
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_write_access_to_resource_based_policies": {
    "batch": "instance-role17",
    "description_base_sha256": "48b62c7eca4457479066063ce9c8698e5ff4604cb1a9d6e715d011e7a81acc22",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed write access to resource-based policies action."
    },
    "remediation_base_sha256": "4d78cb199824c01256c60384b6ede9ce3f812ec73b12e0563d96e589e3efdfa7",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed write access to resource-based policies action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "ecr:setrepositorypolicy",
          "serverlessrepo:putapplicationpolicy",
          "backup:putbackupvaultaccesspolicy",
          "elasticfilesystem:putfilesystempolicy",
          "glacier:setvaultaccesspolicy",
          "secretsmanager:putresourcepolicy",
          "events:putpermission",
          "mediastore:putcontainerpolicy",
          "glue:putresourcepolicy",
          "ses:putidentitypolicy",
          "lambda:addpermission",
          "lambda:addlayerversionpermission",
          "s3:putbucketpolicy",
          "s3:putbucketacl",
          "s3:putobject",
          "s3:putobjectacl",
          "kms:creategrant",
          "kms:putkeypolicy",
          "es:updateelasticsearchdomainconfig",
          "sns:addpermission",
          "sqs:addpermission"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access": {
    "batch": "instance-role17",
    "description_base_sha256": "07b143cf7d546861947e5c657b1b19d03a94fbed78149442f6c4e07ec88fdbe9",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed KMS decrypt / secret value access action."
    },
    "remediation_base_sha256": "7b32110ac73a91072ab1f907cfaf3b02c3d52675649bd14ba04c125f7494a156",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed KMS decrypt / secret value access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "secretsmanager:getsecretvalue",
          "kms:decrypt"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_destruction_rds_access": {
    "batch": "instance-role17",
    "description_base_sha256": "847617f3b0fb26403b6346b93e66ea88b36b0acb0dadeebbc42f8fb36f3b430f",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed RDS Data API statement execution access action."
    },
    "remediation_base_sha256": "6bef62d419b79fe258d41e5795c705891ca56bb37fe347b8f6478483fc9405fe",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed RDS Data API statement execution access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "rds-data:executestatement",
          "rds-data:batchexecutestatement"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_cloud_log_tampering_access": {
    "batch": "instance-role17",
    "description_base_sha256": "70c8a4518a757ee6938e5c897a8b2945e3694c7a6a92efc272c93fa2956e0d4b",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed cloud log tampering access action."
    },
    "remediation_base_sha256": "500362e40582c9049232baceef6e624f68326e989ea8e2339f3a8422b5453da6",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed cloud log tampering access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "cloudtrail:deletetrail",
          "cloudtrail:puteventselectors",
          "cloudtrail:stoplogging",
          "ec2:deleteflowlogs",
          "s3:putbucketlogging",
          "logs:deletelogstream",
          "logs:deleteloggroup",
          "waf:deleteloggingconfiguration",
          "waf:putloggingconfiguration"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_alter_critical_s3_permissions_configuration": {
    "batch": "instance-role17",
    "description_base_sha256": "566343a2c577c5d6bfd1cd2ec89f085d869ed0ae709213352cc22029808eae77",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed alter critical S3 permissions configuration action."
    },
    "remediation_base_sha256": "852fe6be5f731d8e7a67d78ed1ddc84743f816213b1e1092a413ee5f404fac8f",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed alter critical S 3 permissions configuration action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "s3:putobjectretention",
          "s3:putlifecycleconfiguration",
          "s3:putbucketpolicy",
          "s3:putbucketversioning"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_write_permission_on_critical_s3_configuration": {
    "batch": "instance-role17",
    "description_base_sha256": "8d771c05c01e512d32ef020288ae259f55816bf40944ea02666ad331e35e490e",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed write permission on critical S3 configuration action."
    },
    "remediation_base_sha256": "950604820d6794462c74c33f58631e562d92861131ad5e2bbd309fe926461755",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed write permission on critical S 3 configuration action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "s3:putobjectretention",
          "s3:putlifecycleconfiguration",
          "s3:putbucketpolicy",
          "s3:putbucketversioning"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_security_group_write_access": {
    "batch": "instance-role17",
    "description_base_sha256": "37ef947427f0d87d625f1885efd3c495fc0466b0a3a8a461b14b7886c2324e86",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed security group write access action."
    },
    "remediation_base_sha256": "90fee058e96f3b9a65091d0feb74849fcd3b837106b1d1dcfbc8ae506005e878",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed security group write access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "rds:createdbsecuritygroup",
          "rds:deletedbsecuritygroup",
          "rds:revokedbsecuritygroupingress",
          "ec2:authorizesecuritygroupegress",
          "ec2:authorizesecuritygroupingress",
          "ec2:createsecuritygroup",
          "ec2:deletesecuritygroup",
          "ec2:modifysecuritygrouprules",
          "ec2:revokesecuritygroupegress",
          "ec2:revokesecuritygroupingress",
          "elasticloadbalancing:applysecuritygroupstoloadbalancer",
          "elasticloadbalancing:setsecuritygroups",
          "redshift:authorizeclustersecuritygroupingress",
          "redshift:createclustersecuritygroup",
          "redshift:deleteclustersecuritygroup"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_defense_evasion_impact_of_aws_security_services_access": {
    "batch": "instance-role17",
    "description_base_sha256": "6579df231652d7dfc917f0b1d43e3c2a98c6b5bc5a444786a865ce35b98f0b6e",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed defense evasion of AWS security services access action."
    },
    "remediation_base_sha256": "f3899804dd973a1b6b4d2b7aae52bbae7ed0cd0baf8449bc14148ff90732295f",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed defense evasion of AWS security services access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "guardduty:updatedetector",
          "guardduty:deletedetector",
          "guardduty:deletemembers",
          "guardduty:updatefilter",
          "guardduty:deletefilter",
          "shield:disableapplicationlayerautomaticresponse",
          "shield:updateprotectiongroup",
          "shield:deletesubscription",
          "detective:disassociatemembership",
          "detective:deletemembers",
          "inspector:disable",
          "config:stopconfigurationrecorder",
          "config:deleteconfigurationrecorder",
          "config:deleteconfigrule",
          "config:deleteorganizationconfigrule",
          "cloudwatch:disablealarmactions",
          "cloudwatch:disableinsightrules"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_role_with_elastic_ip_hijacking_access": {
    "batch": "instance-role17",
    "description_base_sha256": "1b6644121ca3382221f4ec0b390dc20792c38721722e124811278b66df4797ed",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for a listed Elastic IP hijacking access action."
    },
    "remediation_base_sha256": "e50d72c059da53b0b6e22dbbded3376dd47c08644c3ee98dc4375010746b265d",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant a listed Elastic IP hijacking access action on all resources.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "ec2:disassociateaddress",
          "ec2:enableaddresstransfer"
        ],
        "all_of": false
      }
    }
  },
  "aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access": {
    "batch": "instance-role17",
    "description_base_sha256": "7676d10726648eb321bd5d07d51afd6515daa0e5745dce6c05e4893d488c1d07",
    "description_fields": {
      "description": "Joins the instance profile to role identity policies and boundaries, looking for the complete listed action combination."
    },
    "remediation_base_sha256": "646d72e834aaebb26b2bdc72b7dc0f505d3129f6da037706d9025a9bb9cfdb7d",
    "remediation_fields": {
      "summary": "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions.",
      "steps": [
        "Narrow unnecessary global-resource grants in the attached role while preserving required workload permissions."
      ],
      "caveats": [
        "Definite grants require unconditional global resources and compatible boundaries. Unresolved conditions or denies remain undetermined; SCPs and session policies are not evaluated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The attached instance-role policies grant the complete listed iam:PassRole with Lambda create and invoke function access combination.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_install.<locals>.evaluate",
      "predicate_source_sha256": "afd7d0a90a87f72481d9ba9d48e2343055be10f675c4aa4c0a0d63d054fde12f",
      "closure": {
        "actions": [
          "iam:passrole",
          "lambda:createfunction",
          "lambda:invokefunction"
        ],
        "all_of": true
      }
    }
  },
  "aws.c2b.lambda.invoke_cloudtrail_logged": {
    "batch": "managed-services30",
    "description_base_sha256": "a0462bf826b1d9a4e6a155cc3cc2b04282a9007bdfa01b46b3565bf48be4da0c",
    "description_fields": {
      "description": "Matches collected CloudTrail selectors containing the function ARN, the Lambda ARN prefix or an advanced Lambda resource-type selector."
    },
    "remediation_base_sha256": "d138574d39cc7b1fcb19f648567e5a7f2feff13bee0e7862c2771278ea10d141",
    "remediation_fields": {
      "summary": "Configure the intended Lambda data-event selectors and verify actual event delivery.",
      "steps": [
        "Configure the intended Lambda data-event selectors and verify actual event delivery."
      ],
      "caveats": [
        "Trail logging state, other advanced-selector restrictions and delivered Invoke events are not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No collected trail selector matches the function under the bounded Lambda selector rules.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_invoke_trail",
      "predicate_source_sha256": "85f4faa1e0bb718cb7d51b81cc1fec62d29c99bcf0dbbae0db34892c69592fc7",
      "closure": {}
    }
  },
  "aws.c2b.lambda.url_cors_no_wildcard": {
    "batch": "managed-services30",
    "description_base_sha256": "15fd6d93d1cd5fc0402a837126ebc5193fc66e1c6c3433af6ed806d8c47e6d91",
    "description_fields": {
      "description": "For function URLs, checks whether CORS AllowOrigins contains the literal wildcard."
    },
    "remediation_base_sha256": "3a56cc98cf4b95880f561551d7bde51d6cc5c870449407a936e3be85fcf921ae",
    "remediation_fields": {
      "summary": "If every browser origin does not need access, allow only intended web clients.",
      "steps": [
        "If every browser origin does not need access, allow only intended web clients."
      ],
      "caveats": [
        "No URL is not applicable; CORS is a browser policy, not authentication or a network perimeter."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function URL CORS allowlist contains a wildcard origin.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_cors",
      "predicate_source_sha256": "91f20429b3938391f18f74b717fbcefca45869e3853921f8dfb7703a21bf58ba",
      "closure": {}
    }
  },
  "aws.c2b.lambda.no_cross_account_layers": {
    "batch": "managed-services30",
    "description_base_sha256": "6fcd7f351142a2675d6754ebdb21cf330121d0ef9e5c7b307e1408a3389bf8a1",
    "description_fields": {
      "description": "Compares each declared layer ARN account with the audited account."
    },
    "remediation_base_sha256": "fab26ffb9f45550c6b1c0c3639a7f6b6134081a9eadc6b2faf2f50a729029795",
    "remediation_fields": {
      "summary": "Review external layer publishers and retain only the dependencies the workload trusts.",
      "steps": [
        "Review external layer publishers and retain only the dependencies the workload trusts."
      ],
      "caveats": [
        "Cross-account layers can be intentional vendor dependencies; ownership alone does not establish malicious code."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function references a layer owned by another AWS account.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_layers",
      "predicate_source_sha256": "8f9b790164854e37b2d89e88058aa50a2b4bcea08cc960d9a65969b5635555f1",
      "closure": {}
    }
  },
  "aws.c2b.lambda.runtime_not_obsolete": {
    "batch": "managed-services30",
    "description_base_sha256": "a4486789b30d3441e1ab074c171099d667009222c7bd5300a49fc673419ca61a",
    "description_fields": {
      "description": "Checks whether the Runtime value belongs to the pinned obsolete-runtime list."
    },
    "remediation_base_sha256": "cd42482e5a422ed31c3335786f0a18ec8b49da341c94c79adb9fbfaaa81f63b9",
    "remediation_fields": {
      "summary": "Review current runtime support and migrate obsolete runtimes with compatibility testing.",
      "steps": [
        "Review current runtime support and migrate obsolete runtimes with compatibility testing."
      ],
      "caveats": [
        "Functions without Runtime are not applicable; this is not a live current-support or code-vulnerability assessment."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function runtime belongs to the pinned obsolete-runtime list.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_runtime",
      "predicate_source_sha256": "42868cb98651444d598f3df1d25a53a769be9a7fa8a0accd90895441064483da",
      "closure": {}
    }
  },
  "aws.c2b.ecs.no_credential_named_env_vars": {
    "batch": "managed-services30",
    "description_base_sha256": "991d84664ba35b854b01a7ea271e40964dfda4591ac02e734a5ae7d44a5f7cc2",
    "description_fields": {
      "description": "Checks plain container environment-variable names against the fixed AWS credential-name list."
    },
    "remediation_base_sha256": "009a12d6af7796e0007fbbc3d7f49c7504170be606091280795fe008fb4571d0",
    "remediation_fields": {
      "summary": "Use a suitable task role or secret-reference mechanism for actual credentials.",
      "steps": [
        "Use a suitable task role or secret-reference mechanism for actual credentials."
      ],
      "caveats": [
        "Values are never read; a name match does not prove that a real secret is present or leaked."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A plain environment variable uses a listed AWS credential-related name.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ecs_env_names",
      "predicate_source_sha256": "f29f0c00e1358145251c9d4eb8f9c8d764c02cc4dacc7102377a5afc3084942e",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_insights": {
    "batch": "managed-services30",
    "description_base_sha256": "9ba11a8ea04a66ee9bd34b869bf16ceb2069db4b9bb7ac562df2fe644696d1d7",
    "description_fields": {
      "description": "Looks for any containerInsights setting with value enabled or enhanced."
    },
    "remediation_base_sha256": "86d7ae1a66063ae30160bbcf0400a97f798614997d16f52aade4f7b660ff7c05",
    "remediation_fields": {
      "summary": "Enable intended Container Insights coverage when this is the chosen monitoring tool.",
      "steps": [
        "Enable intended Container Insights coverage when this is the chosen monitoring tool."
      ],
      "caveats": [
        "Alternative monitoring and telemetry delivery are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No enabled or enhanced Container Insights setting is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_insights",
      "predicate_source_sha256": "a3d0cf1b4cb69eeedd7136790b63b1c59b7cf1578349cbad0a6eba835c17bf8f",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_insights_setting": {
    "batch": "managed-services30",
    "description_base_sha256": "ec9834006c300ef1cbe3c1ffad125a2d2d886ab026edd716a3e6fe2022b854d5",
    "description_fields": {
      "description": "Requires nonempty containerInsights settings whose values are enabled or enhanced."
    },
    "remediation_base_sha256": "133875e7303325eee39f6daf3ada92ecd18799959f4fa957c18cb548240a7188",
    "remediation_fields": {
      "summary": "Configure the intended Container Insights mode where required.",
      "steps": [
        "Configure the intended Container Insights mode where required."
      ],
      "caveats": [
        "Missing source facts remain undetermined; an enabled declaration does not prove telemetry delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Container Insights settings are absent or include a value other than enabled or enhanced.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_insights_setting",
      "predicate_source_sha256": "54fb8000cf3229dadcbc08c23b4878490977083e90c8ddac151ac2d895de0883",
      "closure": {}
    }
  },
  "aws.c2b.ecs.cluster_has_active_services": {
    "batch": "managed-services30",
    "description_base_sha256": "d6b3486cef54acedf5efa91b4799cbd53d7a7665eed2ceadfe82df0f222e1a87",
    "description_fields": {
      "description": "Reads activeServicesCount and flags zero or fewer."
    },
    "remediation_base_sha256": "f621606316667c7b723adc377922be3606a3a0125968358c06ab69d5a496e7b8",
    "remediation_fields": {
      "summary": "Review whether the cluster intentionally has no services; retire it only after checking other workloads.",
      "steps": [
        "Review whether the cluster intentionally has no services; retire it only after checking other workloads."
      ],
      "caveats": [
        "Standalone tasks can be intentional; no-service count alone is not a security weakness."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster reports no active services.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_active",
      "predicate_source_sha256": "82c6204ae0b464a60a6c264338c99c9191305449e4b83b964fc7ba3371b8d36b",
      "closure": {}
    }
  },
  "aws.c2b.ecs.cluster_has_registered_instances": {
    "batch": "managed-services30",
    "description_base_sha256": "56a59a084048ad1d6d597a1903c78daa9f8c529717be199be18241f3515b2b49",
    "description_fields": {
      "description": "Accepts positive registration count; otherwise resolves cluster-matched service and task capacity demand."
    },
    "remediation_base_sha256": "9509dd3327c902ce36a3c8157f7450b413fd799c6c11b6b2ae53e5e8fc437d15",
    "remediation_fields": {
      "summary": "For proved EC 2 workload demand, investigate missing container-instance registration.",
      "steps": [
        "For proved EC 2 workload demand, investigate missing container-instance registration."
      ],
      "caveats": [
        "Fargate-only workloads are not applicable; unresolved capacity is undetermined and positive registration is not readiness proof."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster has no registered instances despite declared EC 2 workload demand.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_registered",
      "predicate_source_sha256": "e9452be7d065237bfdbe97f639befed8bbd716dba650a5cac658617e43d34150",
      "closure": {}
    }
  },
  "aws.c2b.ecs.container_instance_agents_connected": {
    "batch": "managed-services30",
    "description_base_sha256": "00bb92c69f37b1fe7cca4e59e34a8f608b1c5986ffc58691f32c0b9436c77ce2",
    "description_fields": {
      "description": "For clusters with registered instances, checks active matching container-instance agentConnected flags."
    },
    "remediation_base_sha256": "4b6fc60c855011971a0f47664d370dfc12ae047eb314bc65cfacb83ee0aaa57a",
    "remediation_fields": {
      "summary": "Restore intended agent connectivity and investigate stale registrations safely.",
      "steps": [
        "Restore intended agent connectivity and investigate stale registrations safely."
      ],
      "caveats": [
        "Zero registered instances is not applicable; this report does not independently test host or agent health."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An active container instance reports its ECS agent disconnected.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ecs_agents",
      "predicate_source_sha256": "b903fee9d4784a7875c01a62bfb2040087c165a9f8df963cb06ba055d11d5984",
      "closure": {}
    }
  },
  "aws.c2b.eks.endpoint_not_public": {
    "batch": "managed-services30",
    "description_base_sha256": "785c86cb1fe955ebb055d509b5ba06ad86e73604066a2c025f9ee16109527ae3",
    "description_fields": {
      "description": "Reads the EKS endpointPublicAccess flag without considering authorized CIDRs."
    },
    "remediation_base_sha256": "56aff0a0124d582db2a5ba2e4efe30a0c2b2f212bba1c992512169854bd65520",
    "remediation_fields": {
      "summary": "Use a private endpoint if the intended administration model requires it; otherwise review allowed public sources.",
      "steps": [
        "Use a private endpoint if the intended administration model requires it; otherwise review allowed public sources."
      ],
      "caveats": [
        "A CIDR-restricted public endpoint also fails this private-only preference; authentication and effective reachability are not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS API endpoint is declared public.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_public",
      "predicate_source_sha256": "c7b25104480facde34469c7715976d9cdfe69b69fdd10a22e1ecceeedc7dfc31",
      "closure": {}
    }
  },
  "aws.c2b.eks.single_security_group": {
    "batch": "managed-services30",
    "description_base_sha256": "219b857e3ee3044fb7f619592b4800560455e31caceb7fde795d051bf207ad33",
    "description_fields": {
      "description": "Counts additional securityGroupIds and flags more than one."
    },
    "remediation_base_sha256": "bdff034bb91b3555b85909f090b83097f163b68ab7561b8366955a2f76232d7e",
    "remediation_fields": {
      "summary": "Keep only the additional groups needed by the intended cluster network design.",
      "steps": [
        "Keep only the additional groups needed by the intended cluster network design."
      ],
      "caveats": [
        "Additional groups can be intentional; count does not assess rules or Kubernetes NetworkPolicy."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS cluster declares more than one additional security group.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_sgs",
      "predicate_source_sha256": "5bd9f49fbac4e4d5f430e9d3531933112b832378329c7756a3da362bf2be2ad9",
      "closure": {}
    }
  },
  "aws.c2b.eks.version_at_least_1_19": {
    "batch": "managed-services30",
    "description_base_sha256": "9e07bd5fe2a585e4abd8b6f9423a45cf1db8ac78cbf347714c970965372879c6",
    "description_fields": {
      "description": "Parses the Kubernetes major/minor version and compares it with the pinned 1.19 floor."
    },
    "remediation_base_sha256": "834da9123443ba4cbd2cd673bf042efd7d15478c04d1ed1248a6c282948778a2",
    "remediation_fields": {
      "summary": "Review current EKS support and upgrade unsupported workloads through an appropriate plan.",
      "steps": [
        "Review current EKS support and upgrade unsupported workloads through an appropriate plan."
      ],
      "caveats": [
        "Passing this historical floor does not establish current EKS support or complete patch coverage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Kubernetes version is below the pinned 1.19 floor.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_119",
      "predicate_source_sha256": "25c940a0d81d6a7f7a52cc6a4a7b419000f6a93a4a1c135e1664097ac05b5593",
      "closure": {}
    }
  },
  "aws.c2b.eks.version_at_least_1_28": {
    "batch": "managed-services30",
    "description_base_sha256": "fd62387c05aaf76952e24ce338685859f094713541355d7009ee880757bb24f7",
    "description_fields": {
      "description": "Parses the Kubernetes major/minor version and compares it with the pinned 1.28 floor."
    },
    "remediation_base_sha256": "20c1291bfd0186622ee6a0d0bbae95421e9db5ea84bfc7e382667921ecdd6c07",
    "remediation_fields": {
      "summary": "Review current EKS support and upgrade unsupported workloads through an appropriate plan.",
      "steps": [
        "Review current EKS support and upgrade unsupported workloads through an appropriate plan."
      ],
      "caveats": [
        "Passing this fixed floor does not establish current EKS support or complete patch coverage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Kubernetes version is below the pinned 1.28 floor.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_128",
      "predicate_source_sha256": "55e5d8160fc159864612027cd01645e0d07064d03f3b4d9548d36d34adc6a0e5",
      "closure": {}
    }
  },
  "aws.c2b.eks.deletion_protection": {
    "batch": "managed-services30",
    "description_base_sha256": "78725ef079c946af50f827f17df2c33ce4ae91021d92020bf96676706cd4e858",
    "description_fields": {
      "description": "Reads the deletionProtection flag and flags explicit false."
    },
    "remediation_base_sha256": "f3f50c6675c1fde72ba5e454166d9f34e711d738bd0b932fb7c63dce35ddd19e",
    "remediation_fields": {
      "summary": "Enable deletion protection where accidental cluster deletion must be prevented.",
      "steps": [
        "Enable deletion protection where accidental cluster deletion must be prevented."
      ],
      "caveats": [
        "Missing fields remain undetermined; deletion protection is not a backup or availability guarantee."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "EKS cluster deletion protection is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_deletion",
      "predicate_source_sha256": "2c77217c164d49c1ea72954f98423671b656c6e79c3f01c21ace27a545023694",
      "closure": {}
    }
  },
  "aws.c2b.eks.secrets_encryption_configured": {
    "batch": "managed-services30",
    "description_base_sha256": "ff0979c26c082ffaef3ea5f67d7ec7b9c7f690e4896b945667748c1888a224fe",
    "description_fields": {
      "description": "Checks whether encryptionConfig contains any entries."
    },
    "remediation_base_sha256": "946d6632bbb2b51b1f445876c0951f1cd0252809479cc9f9a20ddd4433c6d795",
    "remediation_fields": {
      "summary": "If dedicated envelope keys are required, configure an appropriate supported key and preserve access.",
      "steps": [
        "If dedicated envelope keys are required, configure an appropriate supported key and preserve access."
      ],
      "caveats": [
        "The check ignores Kubernetes version and provider-default encryption; absence is not evidence of plaintext secrets."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No explicit EKS encryptionConfig entry is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_kms",
      "predicate_source_sha256": "76cd4f64fb5a2b2799bba34b304887b09abaec0173a2d6cdb3206bf618a2cabc",
      "closure": {}
    }
  },
  "aws.c2b.eks.cluster_security_group_present": {
    "batch": "managed-services30",
    "description_base_sha256": "d1f8e1453df6a7b8bd797589d29b279bc1a8520aa84ffbfddb0d0e8a1fbfe4de",
    "description_fields": {
      "description": "Validates the observed cluster security-group ID; missing modern IDs remain undetermined."
    },
    "remediation_base_sha256": "39baf802ab5f73106b94dc2a6684686ad15398eb2a1e995d002a765c6ff5eb14",
    "remediation_fields": {
      "summary": "Inspect the reported cluster group association if its metadata is unresolved.",
      "steps": [
        "Inspect the reported cluster group association if its metadata is unresolved."
      ],
      "caveats": [
        "Legacy pre-boundary groups are not applicable; this presence check has no failing outcome and does not evaluate Kubernetes NetworkPolicy."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The cluster security-group presence is unverified.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_cluster_sg",
      "predicate_source_sha256": "835716e51c8cd76b394c107d246dbba2279d2c1ba7bc716d13ffa9f3355bad1c",
      "closure": {}
    },
    "no_fail_outcome": true
  },
  "aws.c2b.autoscaling.multiple_az": {
    "batch": "managed-services30",
    "description_base_sha256": "a7cc25e5405490862622d637f490aabba8c20c2a41cc1134989275cf9a289684",
    "description_fields": {
      "description": "Counts declared AvailabilityZones and requires at least two."
    },
    "remediation_base_sha256": "6dada8a6fad3e6be8a5bbce6c2479654fcdbcfb474fefe60ca2f7604a78a28c7",
    "remediation_fields": {
      "summary": "Use multiple Availability Zones where the intended availability requirements need them.",
      "steps": [
        "Use multiple Availability Zones where the intended availability requirements need them."
      ],
      "caveats": [
        "Zone declarations do not establish balanced capacity or actual outage resistance."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Auto Scaling group declares fewer than two Availability Zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_az",
      "predicate_source_sha256": "9834d279b2c5078c846beaa3b6dfcb9319aedefc86a4f1aa0ce9d593e05cac87",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.uses_launch_template": {
    "batch": "managed-services30",
    "description_base_sha256": "40210f3c958d73693be5a9d7e10c662be8cd21f051445376022efd1e240c26af",
    "description_fields": {
      "description": "Checks for a nonempty direct or mixed-instances launch-template declaration."
    },
    "remediation_base_sha256": "6f03bc293ed05185acb7a649197983f893765a26465d02e0b907fba6baa853cf",
    "remediation_fields": {
      "summary": "Use the intended supported launch-template design when migrating legacy launch configurations.",
      "steps": [
        "Use the intended supported launch-template design when migrating legacy launch configurations."
      ],
      "caveats": [
        "Template presence does not validate version selection or secure launch settings."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No direct or mixed-instances launch-template declaration is present.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_lt",
      "predicate_source_sha256": "4e1ece0007c8fb6972963a9adf6f0eff03ec0dbcf3d3eb8cb7e3d89a6654bdbb",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.capacity_rebalance": {
    "batch": "managed-services30",
    "description_base_sha256": "041b89c71111ba9d39e5b2485686bf2eb03a2b71502de43cb0db68912e7ba984",
    "description_fields": {
      "description": "For groups declaring both classic load balancers and target groups, reads CapacityRebalance."
    },
    "remediation_base_sha256": "5c05794d8753b96108a1cb1bcb06cc8d5f8beb67998d9f2e483a3804e76199de",
    "remediation_fields": {
      "summary": "Enable capacity rebalancing if required by the intended Spot-capacity design.",
      "steps": [
        "Enable capacity rebalancing if required by the intended Spot-capacity design."
      ],
      "caveats": [
        "Groups without both balancer types are not applicable under this source criterion; replacement behavior is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The applicable Auto Scaling group does not enable CapacityRebalance.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_rebalance",
      "predicate_source_sha256": "28c0a274464c31ddf7e5f50a5e78706fd8905d839141986fcb157917b0f1ee6b",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.instance_types_per_az": {
    "batch": "managed-services30",
    "description_base_sha256": "f9e7662b36b75abe126022a306280c712bd63fc197d1999aa51762e13fed4b54",
    "description_fields": {
      "description": "Groups current instances by Availability Zone and requires several zones with at least two instance types each."
    },
    "remediation_base_sha256": "0d6cedb3afafc6d9cb2ff90934b84c5944f1d1efd9053f942cffcd585005303f",
    "remediation_fields": {
      "summary": "Choose suitable capacity diversification for the intended workload and availability goals.",
      "steps": [
        "Choose suitable capacity diversification for the intended workload and availability goals."
      ],
      "caveats": [
        "Empty instance lists are not applicable; observed diversity is not a guarantee of future capacity."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Current group membership does not provide multiple instance types in every one of several zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_types",
      "predicate_source_sha256": "48cb337907b205284caae04cdd129ac987fe937234942cdc8c2d46bc8a1e52d0",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.mixed_policy_multiple_types": {
    "batch": "managed-services30",
    "description_base_sha256": "f07053bba6bdea91954df5ede261b4b1e243d523c56b217400e89dd94ec81bea",
    "description_fields": {
      "description": "Counts distinct explicit InstanceType overrides and requires at least two."
    },
    "remediation_base_sha256": "be83ad7b40e99aa7fbfde155d142645a20ba48f0254a3cd177e9e3b3ed32e38e",
    "remediation_fields": {
      "summary": "Configure appropriate instance-type diversification where required.",
      "steps": [
        "Configure appropriate instance-type diversification where required."
      ],
      "caveats": [
        "Attribute-based selection remains undetermined; this does not evaluate the number of Availability Zones."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The mixed-instances overrides declare fewer than two distinct instance types.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_mixed",
      "predicate_source_sha256": "28379339f562efdd25f03e4745026526c28d37cad1929b54551363640c6b0285",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.no_suspended_processes": {
    "batch": "managed-services30",
    "description_base_sha256": "aa40c4405dba2bd6132cf291c6a17f8b1be5705cd4e07853da660616ca5d5646",
    "description_fields": {
      "description": "Checks whether SuspendedProcesses contains any entries."
    },
    "remediation_base_sha256": "b0a3d30c7ffe1eaff7eb7b95b450cd48ddf89efb58bf6bf025b5eaa8de229c28",
    "remediation_fields": {
      "summary": "Review intentional maintenance before resuming required scaling processes.",
      "steps": [
        "Review intentional maintenance before resuming required scaling processes."
      ],
      "caveats": [
        "Suspension can be intentional maintenance; no failed scaling event is demonstrated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one Auto Scaling process is suspended.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_suspended",
      "predicate_source_sha256": "fa870cac98a7c1d6156474e244538fb364d214776357cf2b2b86a580d975df1f",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.tags_propagate": {
    "batch": "managed-services30",
    "description_base_sha256": "e9d37e308ed8faa65b1f1f78432662d36585b605a5c338ce98e565a5d4e542b9",
    "description_fields": {
      "description": "Checks declared tags for PropagateAtLaunch=false."
    },
    "remediation_base_sha256": "6b27d5e6e37f8478a8d622b12c2287d3fb25cf881580ba2765c57a0cd5ff311e",
    "remediation_fields": {
      "summary": "Propagate tags where intended for inventory or policy, preserving deliberate exceptions.",
      "steps": [
        "Propagate tags where intended for inventory or policy, preserving deliberate exceptions."
      ],
      "caveats": [
        "No tags passes this preference; tag propagation is not a standalone security boundary."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A group tag is configured not to propagate at launch.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_tags",
      "predicate_source_sha256": "61b21da3ed23e59818d798cd0da00e69fabe6f334201752515e1876ba39f9b5a",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.group_lc_imdsv2": {
    "batch": "managed-services30",
    "description_base_sha256": "4873ff9c2249a6d3866ab6db50a1f93557c91eee2226aca2aaabe0197dda7972",
    "description_fields": {
      "description": "Joins the named launch configuration, requiring tokens unless its metadata endpoint is disabled."
    },
    "remediation_base_sha256": "f6028d8b7311c6911523e3dfea0e278ab24d596346d34d9e29f9b173f81e7f77",
    "remediation_fields": {
      "summary": "Configure required IMDSv2 or disable unnecessary metadata access through the intended launch settings.",
      "steps": [
        "Configure required IMDSv2 or disable unnecessary metadata access through the intended launch settings."
      ],
      "caveats": [
        "Groups without launch configurations are not applicable; unset token inheritance remains undetermined. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. A group using a launch template is NOT_APPLICABLE to this launch-configuration-specific check."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The group launch configuration does not require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "asg_lc_imds",
      "predicate_source_sha256": "0eea93e83165d7ff50ea2151adc0afb005e7d5c6f85cda677159d339d0126a99",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.lc_imdsv2_required": {
    "batch": "managed-services30",
    "description_base_sha256": "4d6e8ba3a084ce9cfae383e2b67d037aca43374287c4a499e534348d5ec20427",
    "description_fields": {
      "description": "Reads launch-configuration metadata HttpTokens and requires required."
    },
    "remediation_base_sha256": "02f9a16927d5951a7448ebeaf694b6a877c37b83e3482cfab38c74bb3a2af08e",
    "remediation_fields": {
      "summary": "Use a suitable replacement launch configuration or template with intended IMDSv2 requirements.",
      "steps": [
        "Use a suitable replacement launch configuration or template with intended IMDSv2 requirements."
      ],
      "caveats": [
        "Unset account-default inheritance remains undetermined; a disabled endpoint does not satisfy this explicit-token preference. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. Moving a group to a launch template does not change this resource finding on the old launch configuration."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The launch configuration explicitly does not require IMDSv2 tokens.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "launch_configuration",
      "predicate_qualname": "lc_imds",
      "predicate_source_sha256": "4b1419f9fc0d9aeb17c1e9a8462c18c9286728260b6f204834fc8f7e32296e9b",
      "closure": {}
    }
  },
  "aws.c2b.autoscaling.lc_hop_limit": {
    "batch": "managed-services30",
    "description_base_sha256": "7338cc5e7f3dd305f8ff5796c7f19505336342c425511d3fdf37f9d0a41db4ca",
    "description_fields": {
      "description": "Flags a declared metadata response hop limit greater than one; omission uses the source\u2019s default acceptance."
    },
    "remediation_base_sha256": "7acb341f0f6f207acdfc56080f0f98179746ec8b8bec5b5c9c76af2c77a0114d",
    "remediation_fields": {
      "summary": "Use a hop limit appropriate for the workload\u2019s container or network-hop requirements.",
      "steps": [
        "Use a hop limit appropriate for the workload\u2019s container or network-hop requirements."
      ],
      "caveats": [
        "Containerized workloads can need a higher hop limit; the value alone does not prove a metadata-exposure path. Launch configurations are immutable: migrate to a pinned reviewed template version and use an instance refresh to replace existing group instances. Moving a group to a launch template does not change this resource finding on the old launch configuration."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The launch configuration metadata response hop limit exceeds one.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "launch_configuration",
      "predicate_qualname": "lc_hop",
      "predicate_source_sha256": "031773c8bc25fc23aeda1016826fdd97a01939a977d812c6ac8b2a87e8719086",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.stream_logs": {
    "batch": "managed-services30",
    "description_base_sha256": "3138f256b204e963db5cb55700e91072fb8857e3edf04d57e294cb84deba2155",
    "description_fields": {
      "description": "Reads the StreamLogs option in the CloudWatch log configuration namespace and looks for true."
    },
    "remediation_base_sha256": "697e64b3cef1c26a38e65c8cbe56343f615c7573c41a0444c94b59c747c20a37",
    "remediation_fields": {
      "summary": "Configure intended log streaming and verify the destination receives the required records.",
      "steps": [
        "Configure intended log streaming and verify the destination receives the required records."
      ],
      "caveats": [
        "Unreported options remain undetermined; delivery, retention and alternative logging are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare StreamLogs=true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_logs",
      "predicate_source_sha256": "7ff30465dab941cb14206e2ce161496895ffef5900f5bd1d64dca5900e515f18",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.managed_updates": {
    "batch": "managed-services30",
    "description_base_sha256": "400005e8c2f942770f5075c317034d0d508875e5c0d1b928a191c705f70698ff",
    "description_fields": {
      "description": "Reads ManagedActionsEnabled in the managed-actions namespace and looks for true."
    },
    "remediation_base_sha256": "ce9989ab5bde5e905d33791859f07245f40d8926648cb029fb74620f0602f827",
    "remediation_fields": {
      "summary": "Enable managed updates if they match the intended platform-maintenance process.",
      "steps": [
        "Enable managed updates if they match the intended platform-maintenance process."
      ],
      "caveats": [
        "Configuration does not prove updates installed; a controlled manual process can be intentional."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare managed platform actions enabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_managed",
      "predicate_source_sha256": "d6503240b1bb956437e75f3a07f8e5e8f55aaf688da031d1f949765c4979cb13",
      "closure": {}
    }
  },
  "aws.c2b.elasticbeanstalk.enhanced_health": {
    "batch": "managed-services30",
    "description_base_sha256": "29ebba458fea1b442338a1537604a00869ae3540c1b527f749398db09172903d",
    "description_fields": {
      "description": "Reads the health-reporting SystemType option and requires enhanced."
    },
    "remediation_base_sha256": "d609c5d2b51881a0c25f3be30c69ed36b59ab3290ac62754f659ead6095324f2",
    "remediation_fields": {
      "summary": "Enable enhanced health reporting if it fits the intended monitoring design.",
      "steps": [
        "Enable enhanced health reporting if it fits the intended monitoring design."
      ],
      "caveats": [
        "Reporting mode does not demonstrate application health or an absence of other monitoring."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The environment does not declare enhanced health reporting.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "eb_health",
      "predicate_source_sha256": "7e0966332d55019943bb97916e9a03f9d0044ee79bc0155499a372417b038d1b",
      "closure": {}
    }
  },
  "aws.b.fsx.openzfs_multi_az": {
    "batch": "filesystem22",
    "description_base_sha256": "6bda2c1d6a6f4c6e36b0872b5c339644f04930ef65fe228bf21ace8c8e7ef61a",
    "description_fields": {
      "description": "For OPENZFS filesystems, compares OpenZFSConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_base_sha256": "74746baf62c518447e93a32dff57a7fde3b2224d9042be51935abd0fe3af9e55",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The OPENZFS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "predicate_source_sha256": "c81d9eca81a8d1fc8939de5014f483374c4829eea5e2d948e77023ca478594c8",
      "closure": {
        "configuration": "OpenZFSConfiguration",
        "eligible": "OPENZFS",
        "passing": [
          "MULTI_AZ_1"
        ]
      }
    }
  },
  "aws.b.fsx.netapp_ontap_multi_az": {
    "batch": "filesystem22",
    "description_base_sha256": "6b1bcc06d2654ef3a18f5d81b3920b2e976e9a9077075143ee1e1b4706b54cb9",
    "description_fields": {
      "description": "For ONTAP filesystems, compares OntapConfiguration.DeploymentType with MULTI_AZ_1, MULTI_AZ_2."
    },
    "remediation_base_sha256": "007e42d17baffd5271fc1553f9dd5d79f38b6afda8601bed711fed76788c4c17",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ONTAP deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "predicate_source_sha256": "c81d9eca81a8d1fc8939de5014f483374c4829eea5e2d948e77023ca478594c8",
      "closure": {
        "configuration": "OntapConfiguration",
        "eligible": "ONTAP",
        "passing": [
          "MULTI_AZ_1",
          "MULTI_AZ_2"
        ]
      }
    }
  },
  "aws.b.fsx.windows_multi_az": {
    "batch": "filesystem22",
    "description_base_sha256": "b15a9d5df7d1d77218c04b43aa2034606f4774ec4d78d5250808a0e602aa51f7",
    "description_fields": {
      "description": "For WINDOWS filesystems, compares WindowsConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_base_sha256": "672a20267c25f547e5811194ee0a768d118a9a140434c5f5884b749331313353",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The WINDOWS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_deployment.<locals>.evaluate",
      "predicate_source_sha256": "c81d9eca81a8d1fc8939de5014f483374c4829eea5e2d948e77023ca478594c8",
      "closure": {
        "configuration": "WindowsConfiguration",
        "eligible": "WINDOWS",
        "passing": [
          "MULTI_AZ_1"
        ]
      }
    }
  },
  "aws.b.fsx.openzfs_copy_backup_and_volume_tags": {
    "batch": "filesystem22",
    "description_base_sha256": "f823800971ddbdc796fbb4064338ea497d8df84fb627be33ff7254f19c3d6526",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToBackups and CopyTagsToVolumes and requires enabled."
    },
    "remediation_base_sha256": "d49c4e23511e9f8a8d8eb88e78b09980dd70d818f0c461b1cfdabd41fc70e0a5",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups and volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups and volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups and volumes is not fully enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "zfs_tags",
      "predicate_source_sha256": "c3ede5770cb23de7727c4c461d59d98de35bd65901b260d3dc9e3cdea14502fa",
      "closure": {}
    }
  },
  "aws.b.fsx.lustre_copy_backup_tags": {
    "batch": "filesystem22",
    "description_base_sha256": "f80048a16f4050d5b1f45b0cb1365ed3010c3682463eb77b92b1209c764136a0",
    "description_fields": {
      "description": "For Lustre, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_base_sha256": "d7e67fcdefc1d062072566898f558ae51753d9b780a2368592b7b0acdc5c6750",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "lustre_tags",
      "predicate_source_sha256": "b3c78d5027c76306358625649d11a6275db8bc4995387f1318f2594e4827d51b",
      "closure": {}
    }
  },
  "aws.cb.fsx.copy_tags_to_backups": {
    "batch": "filesystem22",
    "description_base_sha256": "d8c2a9a29a27596a1ad5f76bf1c1302b595b9d04584cb5f95c7daebc5ff9c108",
    "description_fields": {
      "description": "For supported FSx types, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_base_sha256": "6a6169a5169eb3e047021f90ebf17bac18a92de9404d05021a0a857ef66277f3",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_copy_backups",
      "predicate_source_sha256": "67fdd934a280a8c9d22066673e7e514bb9b6ec461c6e8c24531d1ca2ef2a7454",
      "closure": {}
    }
  },
  "aws.cb.fsx.copy_tags_to_volumes": {
    "batch": "filesystem22",
    "description_base_sha256": "fb3a4876f398305194de16a582963020281a0894b7aff7d8fbd3ab669a32d25a",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToVolumes and requires enabled."
    },
    "remediation_base_sha256": "6fa4f30750e8286644bebdc0bcc2f460dfac3c028df8a98785875b4acd8b328a",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required volumes is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_copy_volumes",
      "predicate_source_sha256": "7e9a69c577d023e8dbd0e3e1199697bb0c5bf576ae884e3054acbc83ab303214",
      "closure": {}
    }
  },
  "aws.cb.fsx.openzfs_copy_tags_backups_and_volumes": {
    "batch": "filesystem22",
    "description_base_sha256": "5ac122fd41bfbcbe65b4715a1c8bdf71dc4cfcfc1c7cf807d3455c187de679c1",
    "description_fields": {
      "description": "For OpenZFS, reads CopyTagsToBackups and CopyTagsToVolumes and requires enabled."
    },
    "remediation_base_sha256": "601c9bae54864077887a7795a4e8f79189437f02ff07b9a64ff744ce58b60c61",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups and volumes where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups and volumes where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups and volumes is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_openzfs_both",
      "predicate_source_sha256": "d02730d19287638459249532c20992d0760c514041b7f75d8710b74bc8bb22a6",
      "closure": {}
    }
  },
  "aws.cb.fsx.lustre_copy_tags_to_backups": {
    "batch": "filesystem22",
    "description_base_sha256": "d38b8508850809eb1ba37128f7ff1b8ccb9aa7a7b44a02987e8b2c11b86cc82d",
    "description_fields": {
      "description": "For Lustre, reads CopyTagsToBackups and requires enabled."
    },
    "remediation_base_sha256": "becda45ba031c1dffcc6dac5caaae16b1539b31c5dc2b48e5e90e95a2d8d5456",
    "remediation_fields": {
      "summary": "Propagate intended ownership and classification tags to backups where needed.",
      "steps": [
        "Propagate intended ownership and classification tags to backups where needed."
      ],
      "caveats": [
        "Other filesystem types are not applicable; tag copying does not demonstrate backup completeness or data protection."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Tag copying to the required backups is not fully enabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_lustre_tags",
      "predicate_source_sha256": "b2a4394f1a26e11b8eec70ad54781a6d4abb8af542b05385c3a320b271ac1803",
      "closure": {}
    }
  },
  "aws.cb.fsx.ontap_multi_az": {
    "batch": "filesystem22",
    "description_base_sha256": "a80605784693db9d167ffdb8223004e1583ba6c5e8520ccfce12ee210a7f038f",
    "description_fields": {
      "description": "For ONTAP filesystems, compares OntapConfiguration.DeploymentType with MULTI_AZ_1, MULTI_AZ_2."
    },
    "remediation_base_sha256": "945798ae85370c0b89521e43ad8fb198dfbb0077f2d7b0a009aa6eece9b7658b",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ONTAP deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "predicate_source_sha256": "bfc6e8f0a0b56743c088c9fa4d157fba75eed13fd1709cf3066d737bdb8b5ea3",
      "closure": {
        "allowed": [
          "MULTI_AZ_1",
          "MULTI_AZ_2"
        ],
        "config": "OntapConfiguration",
        "fstype": "ONTAP"
      }
    }
  },
  "aws.cb.fsx.openzfs_multi_az": {
    "batch": "filesystem22",
    "description_base_sha256": "333ded3f68fd954f5ec9ea4dff6642ce7675b35aa3958827016737401dcb8c54",
    "description_fields": {
      "description": "For OPENZFS filesystems, compares OpenZFSConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_base_sha256": "4ade94b81a84e3a975ab2ed8da292b733d1b9dc99cae2583926ae59222a76e38",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The OPENZFS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "predicate_source_sha256": "bfc6e8f0a0b56743c088c9fa4d157fba75eed13fd1709cf3066d737bdb8b5ea3",
      "closure": {
        "allowed": [
          "MULTI_AZ_1"
        ],
        "config": "OpenZFSConfiguration",
        "fstype": "OPENZFS"
      }
    }
  },
  "aws.cb.fsx.windows_multi_az_deployment": {
    "batch": "filesystem22",
    "description_base_sha256": "3e80a04d0b7e90b24f3cd071d4fdaf38eca6cf3767cc902dae4cdb5b62302497",
    "description_fields": {
      "description": "For WINDOWS filesystems, compares WindowsConfiguration.DeploymentType with MULTI_AZ_1."
    },
    "remediation_base_sha256": "0167863a5a30599be648464f8e81f7fb70d78abb3eccd665481b7f1da9a2619c",
    "remediation_fields": {
      "summary": "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement.",
      "steps": [
        "Choose a supported deployment matching the workload\u2019s availability needs; plan migration safely when changes require replacement."
      ],
      "caveats": [
        "Other filesystem types are not applicable; this declaration does not test failover or a current outage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The WINDOWS deployment type is outside the source-selected Multi-AZ values.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "_multi.<locals>.evaluate",
      "predicate_source_sha256": "bfc6e8f0a0b56743c088c9fa4d157fba75eed13fd1709cf3066d737bdb8b5ea3",
      "closure": {
        "allowed": [
          "MULTI_AZ_1"
        ],
        "config": "WindowsConfiguration",
        "fstype": "WINDOWS"
      }
    }
  },
  "aws.cb.fsx.windows_multiple_subnets": {
    "batch": "filesystem22",
    "description_base_sha256": "b49a277e33a5da72dad27890f0980427ba59c924e00096e0090a8833379dae2d",
    "description_fields": {
      "description": "For FSx Windows filesystems, counts SubnetIds and requires more than one."
    },
    "remediation_base_sha256": "93b931c8268da6ed1e53a90cc7f70b551fcf34d4a1aaa8aaa7f8ea30262541cc",
    "remediation_fields": {
      "summary": "Use the appropriate supported multi-subnet design if the workload needs it.",
      "steps": [
        "Use the appropriate supported multi-subnet design if the workload needs it."
      ],
      "caveats": [
        "Other filesystem types are not applicable; subnet count alone does not prove separate Availability Zones."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Windows filesystem declares at most one subnet.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_windows_subnets",
      "predicate_source_sha256": "6ef79ecb9856796ef9bf4ad674337558810f76450b034cf87dac27571d3819a9",
      "closure": {}
    }
  },
  "aws.cb.fsx.protected_by_backup_plan": {
    "batch": "filesystem22",
    "description_base_sha256": "8ce905910f602a2fa463c74d3b34277fab54899586af869175f4fb92d4f56365",
    "description_fields": {
      "description": "Matches the filesystem ResourceARN to FSx entries in AWS Backup protected resources."
    },
    "remediation_base_sha256": "c804c4f8dbd08882d661e7591f390ee4c17567f4bffa736d34d84f9b22cd3c66",
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "Alternative backup mechanisms and successful restores are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The FSx filesystem has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "fsx_file_system",
      "predicate_qualname": "fsx_backup",
      "predicate_source_sha256": "99f71c39d89346c5a97920ef63dbc9215b9f544050bac0f9de0f6549cefecc04",
      "closure": {}
    }
  },
  "aws.c2b.efs.file_system_protected_resource": {
    "batch": "filesystem22",
    "description_base_sha256": "dfafc4e6cb41a4e31c942a7d491c21124ce50e598f3d28a114ba51758610cade",
    "description_fields": {
      "description": "Matches the EFS filesystem ARN to EFS entries in AWS Backup protected resources."
    },
    "remediation_base_sha256": "4acf227b1b8ef29c20e94db5b1557d865d0bd53cc77f5502c51182f2df5daeb9",
    "remediation_fields": {
      "summary": "Configure required backup protection and verify suitable recovery points.",
      "steps": [
        "Configure required backup protection and verify suitable recovery points."
      ],
      "caveats": [
        "This inventories protected resources, not every backup selection or actual restore outcome."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS filesystem has no matching AWS Backup protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_protected",
      "predicate_source_sha256": "4397f9c2f3690acc68ad8cf00c5b791ef6bbed9142fd38c660e0bcf8fefc7907",
      "closure": {}
    }
  },
  "aws.c2b.efs.backup_not_disabled": {
    "batch": "filesystem22",
    "description_base_sha256": "9b060006053724cf20b6228e104183948d8a78d8feb903ca27f8e29f8c9036ca",
    "description_fields": {
      "description": "Reads EFS BackupPolicy.Status and flags DISABLED, DISABLING or confirmed policy absence."
    },
    "remediation_base_sha256": "4fe219d22c9d64f75911df11225165f74065074976ddf2c48ca1b36b067f3544",
    "remediation_fields": {
      "summary": "Enable intended automatic backups if this is the required backup mechanism.",
      "steps": [
        "Enable intended automatic backups if this is the required backup mechanism."
      ],
      "caveats": [
        "ENABLING passes this transition criterion; unrecognized values remain undetermined and completed backups are not proven."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS automatic-backup policy is disabled, disabling or confirmed absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_backup_prowler",
      "predicate_source_sha256": "44c6c9f8aaa7e362030fd83c14c5fe57b1a6aaec16e4815979dcbf9ef79a6fa5",
      "closure": {}
    }
  },
  "aws.c2b.efs.automatic_backups_enabled": {
    "batch": "filesystem22",
    "description_base_sha256": "dcb8212370811a87179d79005c0e4cc8b000d867ea2a6bf083ed7c4cd817df2d",
    "description_fields": {
      "description": "Reads EFS BackupPolicy.Status and requires exactly ENABLED."
    },
    "remediation_base_sha256": "de511fa2baf165f7f3c254ab715162ec6385ddcbf2fa5da3b14e36b131527a1c",
    "remediation_fields": {
      "summary": "Enable required automatic backups and verify they reach the intended active state.",
      "steps": [
        "Enable required automatic backups and verify they reach the intended active state."
      ],
      "caveats": [
        "ENABLING fails this stricter state preference; unknown values remain undetermined and actual recovery is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EFS automatic-backup policy is absent or not in ENABLED state.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_backup_turbot",
      "predicate_source_sha256": "501e7899d4f7924b2368197b9406e27fc7c64e73906bf0f1ccbb07ad7a67a059",
      "closure": {}
    }
  },
  "aws.c2b.efs.policy_no_wildcard_allow": {
    "batch": "filesystem22",
    "description_base_sha256": "708527b52d83ebce81c7ac1c84d181dbdbfa99511174444db921e4425a2dfcf6",
    "description_fields": {
      "description": "Looks for stored EFS policy Allow statements with a wildcard principal."
    },
    "remediation_base_sha256": "74d74e6c5afedb3d6eaea9148e8efb30c1f9eeed7cbd6e34edb1ec036057f26b",
    "remediation_fields": {
      "summary": "Review broad principals and retain only the sharing required by the workload.",
      "steps": [
        "Review broad principals and retain only the sharing required by the workload."
      ],
      "caveats": [
        "Conditions are ignored by this exact check; no policy passes, and routing or effective client authorization is not established."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored EFS policy contains a wildcard-principal Allow.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_wildcard",
      "predicate_source_sha256": "3e4aff233f49ea9a74f6823d98ab348c18c3806344d4d85a1b08a2d5effe0f37",
      "closure": {}
    }
  },
  "aws.c2b.efs.policy_prohibit_public_access": {
    "batch": "filesystem22",
    "description_base_sha256": "6f15980d36681f408bd7c5c19c43c908ed93bd54950aa3392062cf6425b24ebd",
    "description_fields": {
      "description": "Applies the bounded perimeter matcher to stored EFS Allow statements and recognized restrictions."
    },
    "remediation_base_sha256": "fba856887880d5e40839fcc06556173da76885bcfd692e948d0d122176ca4ba6",
    "remediation_fields": {
      "summary": "Narrow unnecessary public principals using suitable workload-specific restrictions.",
      "steps": [
        "Narrow unnecessary public principals using suitable workload-specific restrictions."
      ],
      "caveats": [
        "No policy is not applicable; this is not proof of Internet reachability, successful mounts or actual file access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored EFS policy matcher identifies a public Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_public_x",
      "predicate_source_sha256": "47f86db12a8eb883a05296b6ddeee5243be4f1a9f6fe7dc621b823f5fa385a48",
      "closure": {}
    }
  },
  "aws.c2b.efs.multi_az_mount_targets": {
    "batch": "filesystem22",
    "description_base_sha256": "87c599882c073a99509dfabd4a0c802a7e62005ed8cdf8fcfa09d35c6f72a699",
    "description_fields": {
      "description": "Flags a declared One Zone identifier or, otherwise, one or fewer mount targets."
    },
    "remediation_base_sha256": "9c671a48cb68d723f45462ed96cb929b7a3e11f6daad54c68945433b31aef816",
    "remediation_fields": {
      "summary": "Use the appropriate supported regional storage and mount-target design where availability requires it.",
      "steps": [
        "Use the appropriate supported regional storage and mount-target design where availability requires it."
      ],
      "caveats": [
        "Mount-target count is not an independent proof of Availability Zone distribution or recovery readiness. A One Zone filesystem cannot accept another mount target in a different Availability Zone; use a Regional filesystem migration if that availability design is required."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The filesystem is One Zone or reports at most one mount target.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_multi_az",
      "predicate_source_sha256": "dad63a58947f44c73c292ce2faae9d525ef4259c3cf7bf3ffb96a2bc2ca12df5",
      "closure": {}
    }
  },
  "aws.c2b.efs.access_points_no_root_directory": {
    "batch": "filesystem22",
    "description_base_sha256": "9c02a07dfa18bf17a47907a5b1d693d86f1d9163d3dbd896468e5afa6aed6f8e",
    "description_fields": {
      "description": "Joins filesystem access points and flags RootDirectory.Path equal to /."
    },
    "remediation_base_sha256": "c998435a8b22e83dc55ca745c073e2f5aea46e98318f830cd017ad93c0d5abfc",
    "remediation_fields": {
      "summary": "If a narrower directory boundary is required, migrate consumers to an appropriately scoped access point.",
      "steps": [
        "If a narrower directory boundary is required, migrate consumers to an appropriately scoped access point."
      ],
      "caveats": [
        "No access points is not applicable; root-directory scope does not bypass POSIX or IAM authorization."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A filesystem access point declares the filesystem root as its root directory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_aps_root",
      "predicate_source_sha256": "d024a0397c9178f36f447d176518051e5ed8cfaa891a94de9e19215a31934b2b",
      "closure": {}
    }
  },
  "aws.c2b.efs.access_points_posix_user": {
    "batch": "filesystem22",
    "description_base_sha256": "264088ac8f2ef8d1390bc95c530a4e5575247fef39f5b40382e28c6106d1aeae",
    "description_fields": {
      "description": "Joins filesystem access points and checks for a nonempty PosixUser declaration."
    },
    "remediation_base_sha256": "25a70e9e4580f8a53d884f659b2a007601b15166fb409124997fb880aac567f9",
    "remediation_fields": {
      "summary": "Use an enforced suitable POSIX identity where the intended access-point design requires it.",
      "steps": [
        "Use an enforced suitable POSIX identity where the intended access-point design requires it."
      ],
      "caveats": [
        "No access points is not applicable; presence does not validate UID/GID values or effective file permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An access point does not declare a nonempty POSIX user configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "efs_aps_user",
      "predicate_source_sha256": "bfffb3256da42adb3d73fc8b204d7f72d5f2b91d70a16630992d671e26b74eb6",
      "closure": {}
    }
  },
  "aws.ec2.imdsv2": {
    "batch": "containers-serverless30",
    "description_base_sha256": "4a04721af19593a37401ac090fe4f0c6148557d7b0619dbbbe19d3447b1f6b3e",
    "description_fields": {
      "description": "Reads MetadataOptions and requires HttpTokens=required when HttpEndpoint is enabled."
    },
    "remediation_base_sha256": "d741946258261d39a593bc6f6d879e3cf7ca809ccfbaf87a96a3e87e7b89b768",
    "remediation_fields": {
      "summary": "Require IMDSv2 tokens or disable the metadata endpoint if unused.",
      "steps": [
        "Require IMDSv2 tokens or disable the metadata endpoint if unused."
      ],
      "caveats": [
        "Disabled metadata passes; unknown endpoint or token states remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The enabled instance metadata endpoint allows IMDSv 1 requests.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "aws_imds",
      "predicate_source_sha256": "a2b8ae60372b0cc6faa3960227d4e0c99d0e5490d194c5d9dc43365f4871bf27",
      "closure": {}
    }
  },
  "aws.s3.versioning": {
    "batch": "containers-serverless30",
    "description_base_sha256": "e65b86cea6c4bcdc34f04b33a1187c62d1c42bb08aa438a3e33b1a8f040da21c",
    "description_fields": {
      "description": "Reads Versioning.Status and requires Enabled."
    },
    "remediation_base_sha256": "b1e54a34a127f5dfcaedd5d1f2429f9daa3213fbc750ea78dd7222951f68c1ca",
    "remediation_fields": {
      "summary": "Enable versioning where object recovery requires it and set suitable retention.",
      "steps": [
        "Enable versioning where object recovery requires it and set suitable retention."
      ],
      "caveats": [
        "Versioning alone does not prove recovery readiness or prevent permanent deletion."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Bucket versioning is suspended or not enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "versioning",
      "predicate_source_sha256": "273b8ff07316a623b2b6fe2fec5680ba3e8f8e5215936a4725df7b17a35d400e",
      "closure": {}
    }
  },
  "aws.s3.access_logging": {
    "batch": "containers-serverless30",
    "description_base_sha256": "0cd5ede9a6ed443c38476e0e36e815770ff2df27a475fcc4b4cc65356472ab8e",
    "description_fields": {
      "description": "Checks whether Logging.LoggingEnabled declares a target bucket."
    },
    "remediation_base_sha256": "9574ad89196e0aa92717438f59ee54faf97337b949d7b12b5364551589ceba90",
    "remediation_fields": {
      "summary": "Configure server access logging when needed, or assess the intended alternative audit mechanism.",
      "steps": [
        "Configure server access logging when needed, or assess the intended alternative audit mechanism."
      ],
      "caveats": [
        "CloudTrail coverage and successful log delivery are separate checks."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The bucket has no server access logging configuration.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "logging",
      "predicate_source_sha256": "9bf1631af74eb190bf3e4bf2f605c6f58fa3f996495d35738e30425d3f2ff03a",
      "closure": {}
    }
  },
  "aws.eks.control_plane_logging": {
    "batch": "containers-serverless30",
    "description_base_sha256": "96b5ddabff27f79efecf26371b374a33dc388f3aea65f49fec748ac9b09ce345",
    "description_fields": {
      "description": "Collects enabled clusterLogging types and requires api, audit, authenticator, controllerManager and scheduler."
    },
    "remediation_base_sha256": "030774813523ee701a7a7411e92201b10cad35074552648bd1914788ec278643",
    "remediation_fields": {
      "summary": "Enable the missing control-plane log categories needed for investigation.",
      "steps": [
        "Enable the missing control-plane log categories needed for investigation."
      ],
      "caveats": [
        "This checks enabled category declarations, not delivery, retention or log completeness."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "One or more EKS control-plane log categories are disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "eks_logging",
      "predicate_source_sha256": "30cb7876d2cafdb098a0cae664739e4e4f26df0a9b5d666141deee385c66a0ce",
      "closure": {}
    }
  },
  "aws.lambda.vpc_configuration": {
    "batch": "containers-serverless30",
    "description_base_sha256": "d4ddc49cf3f88dc20a226f2dbeedbf65821a024a805310844e58ddd11755faef",
    "description_fields": {
      "description": "Reads VpcConfig.VpcId and requires a nonempty VPC identifier."
    },
    "remediation_base_sha256": "aea092fad29b1c8d13f93bad21a01070e68d6537e14ebc4dc01c8efab4da8eb4",
    "remediation_fields": {
      "summary": "Attach the function to a VPC if it needs private resources or controlled network egress.",
      "steps": [
        "Attach the function to a VPC if it needs private resources or controlled network egress."
      ],
      "caveats": [
        "A VPC is not required for every function; this does not prove exposure or deficient isolation."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda function does not declare a VPC attachment.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "nonempty.<locals>.evaluate",
      "predicate_source_sha256": "90a36866245362615a3c31c3dad2a5155028f7288d27fdbd978fc41d6a8f1fce",
      "closure": {
        "path": "VpcConfig.VpcId"
      }
    }
  },
  "aws.lambda.dead_letter_queue": {
    "batch": "containers-serverless30",
    "description_base_sha256": "315ffd60b01ef9a014a6e781d3e2dc914634c6948c1bef3ea687e5a7f8028250",
    "description_fields": {
      "description": "Checks for a nonempty DeadLetterConfig.TargetArn declaration."
    },
    "remediation_base_sha256": "1bc0d2ce853ddac9736a9ad580c435661ec41a02cf8e20320a8af36c45e9521c",
    "remediation_fields": {
      "summary": "Configure an appropriate failure destination if the function invocation model needs it.",
      "steps": [
        "Configure an appropriate failure destination if the function invocation model needs it."
      ],
      "caveats": [
        "This does not assess asynchronous destinations, queue permissions or successful message delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function does not declare a dead-letter target.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_dlq",
      "predicate_source_sha256": "0bb364c7e839c6fb6334f6bcaa23934a22ba0be9de220c26fd7cb6c69d267f9a",
      "closure": {}
    }
  },
  "aws.lambda.function_url_authentication": {
    "batch": "containers-serverless30",
    "description_base_sha256": "72b18420c370395194cc37321b25c67fdb5a8f3ce111428142dc96fc49c37e73",
    "description_fields": {
      "description": "For an existing function URL, compares AuthType with AWS_IAM."
    },
    "remediation_base_sha256": "35a5dd36731f2942e9338016afb9f799b31758a253c6ed2a4f8eee6de46151a4",
    "remediation_fields": {
      "summary": "Use IAM authentication or verify that anonymous access is intentional and appropriately constrained.",
      "steps": [
        "Use IAM authentication or verify that anonymous access is intentional and appropriately constrained."
      ],
      "caveats": [
        "No URL is not applicable; invocation policy and actual network reachability remain separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda function URL allows unauthenticated requests.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_url",
      "predicate_source_sha256": "16972bd8202c4dd9d5bd36d765b06057364684afb37f66859c67f06f1d94cbf4",
      "closure": {}
    }
  },
  "aws.b.ecs.no_privileged_containers": {
    "batch": "containers-serverless30",
    "description_base_sha256": "77ba29d9d9b22de9893e331169f981d3d095ca9cf94a82afdecca1509908319f",
    "description_fields": {
      "description": "Checks every container privileged flag, treating an omitted flag as false."
    },
    "remediation_base_sha256": "5314bafa7b6a9b870fa883054b1cc31cf32476be10366b8a6a64b84487349d2f",
    "remediation_fields": {
      "summary": "Remove privileged mode from containers that do not require host-level capabilities.",
      "steps": [
        "Remove privileged mode from containers that do not require host-level capabilities."
      ],
      "caveats": [
        "Malformed flags remain undetermined unless another container proves a failure."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one ECS container requests privileged mode.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "privileges",
      "predicate_source_sha256": "2549e9415c89418cd0e1b5fd7e2118b8619a6eb6a50a8d4d73de503f8ef2ccaa",
      "closure": {}
    }
  },
  "aws.b.ecs.some_logging_configuration": {
    "batch": "containers-serverless30",
    "description_base_sha256": "dc281c17f73f1114fbc439604f137b541662ef76e8b62ddee8c7e70430405ac0",
    "description_fields": {
      "description": "Checks whether at least one container declares a non-null logConfiguration object."
    },
    "remediation_base_sha256": "2bf2e151db71ee9639db072557a52f5a914237faed1329578d160a74676338b4",
    "remediation_fields": {
      "summary": "Configure suitable logging for the containers whose activity must be recorded.",
      "steps": [
        "Configure suitable logging for the containers whose activity must be recorded."
      ],
      "caveats": [
        "An empty object satisfies this presence check; sibling coverage, valid drivers and actual delivery are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No ECS container declares a logging configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "logging",
      "predicate_source_sha256": "0758a6fd715570be8851d5b5e2c6314b1857a6e6ec362ab25b1671895d1b0cb4",
      "closure": {}
    }
  },
  "aws.b.ecs.no_host_pid": {
    "batch": "containers-serverless30",
    "description_base_sha256": "d04680910ab0a52613017fe8556f9ac16224c05c3ddb5febe06ba18ff5701ef6",
    "description_fields": {
      "description": "Reads task pidMode and flags host."
    },
    "remediation_base_sha256": "5c87eb7bd60f1c95385ac4a6ecfc0a1d95b1738d19c873be8ba05a1ef27c5c8f",
    "remediation_fields": {
      "summary": "Use a scoped PID namespace unless host-process visibility is required.",
      "steps": [
        "Use a scoped PID namespace unless host-process visibility is required."
      ],
      "caveats": [
        "This is a namespace declaration; it does not establish actual host process access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The ECS task uses the host PID namespace.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "host_pid",
      "predicate_source_sha256": "b8cebc8dff6a5e8abd0c17452914e1458dbcbab42f9f0bf068c862f3decc9742",
      "closure": {}
    }
  },
  "aws.b.ecs.all_readonly_roots": {
    "batch": "containers-serverless30",
    "description_base_sha256": "6453d8c6129039e4cb887ab70734072d78bec4009228f46beb942c46303c8f97",
    "description_fields": {
      "description": "Requires readonlyRootFilesystem=true for every declared container."
    },
    "remediation_base_sha256": "abbf7be2111860f1669bad7b9e9700d08cab82078a2e4b1b1b022feb0ae38397",
    "remediation_fields": {
      "summary": "Make container root filesystems read-only where supported and place required writes on dedicated volumes.",
      "steps": [
        "Make container root filesystems read-only where supported and place required writes on dedicated volumes."
      ],
      "caveats": [
        "This checks task declarations, not actual write activity or every mounted volume."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one ECS container has a writable root filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "readonly_roots",
      "predicate_source_sha256": "00fca6c995ba1cd043ed8f4b0419989168e9c68296e09504d106a07f5ad1313a",
      "closure": {}
    }
  },
  "aws.b.ecs.declared_nonroot_users": {
    "batch": "containers-serverless30",
    "description_base_sha256": "22e2d070f5ebd128b0d9be59fc076f86e5369df78a3ae0204bd4a33c3aff1c53",
    "description_fields": {
      "description": "For proven Linux tasks, requires each container to declare a valid nonzero numeric UID."
    },
    "remediation_base_sha256": "7ec0457c9390b4797606d1415e1e771b70d5322069844d899a57037e9119e5b6",
    "remediation_fields": {
      "summary": "Declare a suitable non-root numeric UID and verify that application file permissions support it.",
      "steps": [
        "Declare a suitable non-root numeric UID and verify that application file permissions support it."
      ],
      "caveats": [
        "Inherited image users, named users and malformed values remain undetermined; runtime process identity is not measured."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "At least one Linux ECS container explicitly declares the root user.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "nonroot_users",
      "predicate_source_sha256": "0afb713d65fbc5246d909b8b7d46e11f1a7f8325c06a155575839be99990d911",
      "closure": {}
    }
  },
  "aws.b.ecs.host_network_nonprivileged": {
    "batch": "containers-serverless30",
    "description_base_sha256": "4d31e6e5bf1be2d1b9893b87f2b40fd51cd63285b3570c6043613fbcbff9a4f8",
    "description_fields": {
      "description": "For host-network Linux tasks, combines container privilege flags with valid non-root numeric UID declarations."
    },
    "remediation_base_sha256": "414b82445714d1d0d890f13976a38fe9a2263d10371690fe44df3c796a6d5f93",
    "remediation_fields": {
      "summary": "Remove unnecessary host-network privileges and configure suitable non-root container users.",
      "steps": [
        "Remove unnecessary host-network privileges and configure suitable non-root container users."
      ],
      "caveats": [
        "Other network modes are not applicable; unresolved user identities remain undetermined unless another failure is proven."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "A host-network Linux ECS container requests privilege or explicitly declares root.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "host_user",
      "predicate_source_sha256": "4cf5865075c94cd5966c0882b2640d225c2472d8cdae6ee087e262f78efc812e",
      "closure": {}
    }
  },
  "aws.cb.lambda.kms_key_configured": {
    "batch": "containers-serverless30",
    "description_base_sha256": "2f0c9eb8e56d73271dcef0ca1d0b71456a70b46c92d3fd69e58ea7a0ffb46a55",
    "description_fields": {
      "description": "Checks whether the function declares a nonempty KMSKeyArn."
    },
    "remediation_base_sha256": "076aba063029775eda018cda374a44cc76f1ddc38fcecdc1950a55d02b1b695d",
    "remediation_fields": {
      "summary": "Configure a customer-managed key if independent key control is required.",
      "steps": [
        "Configure a customer-managed key if independent key control is required."
      ],
      "caveats": [
        "The AWS-managed default may still encrypt environment variables; absence is not proof of plaintext storage."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function does not declare a customer-managed environment-encryption key.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_kms",
      "predicate_source_sha256": "a7da3af2b208717d77df56f25475af5496626251c94d1ffcbc2f4019313e6487",
      "closure": {}
    }
  },
  "aws.cb.lambda.logging_config_present": {
    "batch": "containers-serverless30",
    "description_base_sha256": "d62981e1ef56e9cfe1ba1eab5492e910f26fc7226cdde7e01af2506b51b9afab",
    "description_fields": {
      "description": "Checks that the collected LoggingConfig member is not null."
    },
    "remediation_base_sha256": "035c6f6ca1fec5d49376d03178cd531e2e3246270691c41173b622ac329b525e",
    "remediation_fields": {
      "summary": "Configure suitable function log format, levels and destination when required.",
      "steps": [
        "Configure suitable function log format, levels and destination when required."
      ],
      "caveats": [
        "An empty object passes this presence criterion; an unread member remains undetermined and delivery is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function returns an explicit null logging configuration.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_logging",
      "predicate_source_sha256": "a07084c3e45ac6640a29f89a53a4df13627de597af4153b17b548954d64b8e8b",
      "closure": {}
    }
  },
  "aws.cb.lambda.vpc_multiple_az": {
    "batch": "containers-serverless30",
    "description_base_sha256": "11e4efe09e9a9850aa4a810624d829c5e9a467e17bba419b2d054c40e15f2b02",
    "description_fields": {
      "description": "Joins VPC subnet identifiers to inventory and requires two distinct AvailabilityZoneId values."
    },
    "remediation_base_sha256": "10b1735e7b2831cd6e98f1cebc80a97ac50a7516dff01e07ee6a11b193cb2c15",
    "remediation_fields": {
      "summary": "Use subnets in multiple Availability Zones if the function availability requirements need it.",
      "steps": [
        "Use subnets in multiple Availability Zones if the function availability requirements need it."
      ],
      "caveats": [
        "Non-VPC functions are not applicable; missing referenced subnets remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The VPC-attached function spans fewer than two known Availability Zones.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_azs",
      "predicate_source_sha256": "217c686a090b31542cb8be3988b27063afa01f8b5c82be86395e1f7e31a2b737",
      "closure": {}
    }
  },
  "aws.cb.lambda.policy_no_wildcard_allow": {
    "batch": "containers-serverless30",
    "description_base_sha256": "95eae6942d5de4a49b3c0bdfe33c00393b4e53a1eefb30816f64f5ec9239642e",
    "description_fields": {
      "description": "Finds wildcard-principal Allow statements in the stored function policy, ignoring conditions."
    },
    "remediation_base_sha256": "fe48de388341256404d57c0bb0c7ba090c52fe9fe4e873023ff2cd415836f801",
    "remediation_fields": {
      "summary": "Review wildcard principals and retain only intended invocation access.",
      "steps": [
        "Review wildcard principals and retain only intended invocation access."
      ],
      "caveats": [
        "Conditions are ignored by this criterion; no policy passes and successful invocation is not demonstrated."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The function policy contains a wildcard-principal Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_public_c",
      "predicate_source_sha256": "4f3c1a1c4f59976f4e36237f6fb1aa251cb0315dc8321dcf70e92781e64a7f9e",
      "closure": {}
    }
  },
  "aws.cb.lambda.policy_prohibit_public_access_perimeter": {
    "batch": "containers-serverless30",
    "description_base_sha256": "8e5fd7929a47c6d54c50ce324eda960beb2824adddc1f8f9f718e16dc4ab8df9",
    "description_fields": {
      "description": "Applies the bounded public-principal matcher and recognized restrictions to stored policy Allow statements."
    },
    "remediation_base_sha256": "d461788d3e0ca11ffdf3e68a5aed3a5a50331937ca1e276ff1c45137a113a24f",
    "remediation_fields": {
      "summary": "Narrow unnecessary public principals or apply suitable supported restrictions.",
      "steps": [
        "Narrow unnecessary public principals or apply suitable supported restrictions."
      ],
      "caveats": [
        "No policy is not applicable; this does not probe invocation or prove complete effective permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The stored function policy matcher identifies a public Allow statement.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_public_x",
      "predicate_source_sha256": "a19c3e94e1ed9e9108d418c868c1c2955865b623ace2291c9072f5d7926b0fdc",
      "closure": {}
    }
  },
  "aws.cb.lambda.runtime_not_deprecated_list": {
    "batch": "containers-serverless30",
    "description_base_sha256": "ad8b7ef00b9d16d8b99939f1750a1ad2a42d3e9feea5c7843594ccb8bc81e065",
    "description_fields": {
      "description": "Compares managed Zip runtime deprecation dates with the captured scan date using the reviewed lifecycle snapshot."
    },
    "remediation_base_sha256": "7476731be9ba600d5a18951f1c577e7e6225cef9c0854d1b0812625f1d326101",
    "remediation_fields": {
      "summary": "Move the function to a supported runtime and validate application compatibility.",
      "steps": [
        "Move the function to a supported runtime and validate application compatibility."
      ],
      "caveats": [
        "Image and custom runtimes are not applicable; unlisted runtimes or expired lifecycle snapshots remain undetermined."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The managed Lambda runtime is deprecated at the captured scan date.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_runtime",
      "predicate_source_sha256": "8e2815a6cbd47af0e2f9f83c0cf9fc26d7eda6dd23f4debc77b9ac91a7741ba6",
      "closure": {}
    }
  },
  "aws.cb.lambda.cloudtrail_data_events": {
    "batch": "containers-serverless30",
    "description_base_sha256": "60b836d1d5f487e53b954b0a9114a1a5046aeda13ecf402c67f4c738d9bf86dc",
    "description_fields": {
      "description": "Requires an actively logging, region-covering trail with a Lambda Invoke selector matching this function ARN."
    },
    "remediation_base_sha256": "6752a52945f6eb57c4648e918359be3db4106d5e776aee4d97c13724d86d9d06",
    "remediation_fields": {
      "summary": "Add appropriate Lambda invocation data-event coverage to an active trail.",
      "steps": [
        "Add appropriate Lambda invocation data-event coverage to an active trail."
      ],
      "caveats": [
        "Unresolved trail status or selectors remain undetermined; delivery and retention are not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "No verified active trail covers this function invocation data events.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "lambda_trail",
      "predicate_source_sha256": "7002f81e015fcc9f7b4d4153a6debc12f3a13c79b78a32c82fdb1b437c30a56b",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_auto_snapshot": {
    "batch": "containers-serverless30",
    "description_base_sha256": "4810ecd683c61a8b4adcdc3f8e009ef926875b50c0a7edb0d9868d1edb0c55fa",
    "description_fields": {
      "description": "Checks for an AutoSnapshot add-on with status Enabled."
    },
    "remediation_base_sha256": "87378a0cd5960241018f23c3ccf32bedb831777191117a2415bda97096ef49d8",
    "remediation_fields": {
      "summary": "Enable automatic snapshots where this is the intended backup mechanism.",
      "steps": [
        "Enable automatic snapshots where this is the intended backup mechanism."
      ],
      "caveats": [
        "This does not inspect alternative backups, recovery-point completeness or successful restores."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance has no enabled automatic-snapshot add-on.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_snap",
      "predicate_source_sha256": "43953d5e7c00a574772959519c5674ec472f40e909c2452f7f9e63443b3f08bb",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_ipv6_disabled": {
    "batch": "containers-serverless30",
    "description_base_sha256": "296f59dbf92ca794522f22430608aafbe4e70dbfe36fd845aec7b44d69c08832",
    "description_fields": {
      "description": "Checks whether the instance declares any IPv6 addresses."
    },
    "remediation_base_sha256": "c1a19c8bdb586d074d091b049d679ad710c20b8469422d1a7b94026f944cafb0",
    "remediation_fields": {
      "summary": "Keep IPv6 only where required and restrict the intended IPv6 listeners appropriately.",
      "steps": [
        "Keep IPv6 only where required and restrict the intended IPv6 listeners appropriately."
      ],
      "caveats": [
        "An IPv6 address alone does not prove an open listener or public network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance declares IPv6 addresses.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_ipv6",
      "predicate_source_sha256": "70c32a30f0127c854504a959069d73ffcfcfcd83258305805f5f34b6f122ec15",
      "closure": {}
    }
  },
  "aws.cb.lightsail.instance_not_public": {
    "batch": "containers-serverless30",
    "description_base_sha256": "64c47c0376e4482a398691bba94bb43595e4bd2c52dae49273e3c4b6bc9e219e",
    "description_fields": {
      "description": "Requires both a public IP and a declared port range with accessType=public to flag the instance."
    },
    "remediation_base_sha256": "abbd62bc0dd2a009f503e8b141f7a85ad1d3455a06a95c792cd6c64e7c33c581",
    "remediation_fields": {
      "summary": "Review the public listeners and restrict only access that the workload does not need.",
      "steps": [
        "Review the public listeners and restrict only access that the workload does not need."
      ],
      "caveats": [
        "This checks declared port classifications, not packet reachability or application authentication."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail instance has a public IP and a publicly classified port range.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_public",
      "predicate_source_sha256": "e1a114a4729c7acb3c71373593325e9d4bb52798f87a735641878ab67ec472cf",
      "closure": {}
    }
  },
  "aws.cb.lightsail.ssh_rdp_http_world_closed": {
    "batch": "containers-serverless30",
    "description_base_sha256": "2c268f34835ab0f67d2208a6cb84289fa8b167ddc693c4c8c47be78afc928e1a",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 22, 80, 3389 and allow IPv4 or IPv6 world sources.",
      "pass_when": "No valid TCP interval containing 22, 80 or 3389 permits 0.0.0.0/0 or ::/0.",
      "fail_when": "A valid TCP interval containing 22, 80 or 3389 permits 0.0.0.0/0 or ::/0."
    },
    "remediation_base_sha256": "b3b43de74acc2c8900aa209d879d39bc0b8482427693ba02fd128451fe7df006",
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "ls_world",
      "predicate_source_sha256": "15d4992e1dfa68a2a2a17150ad829f375866e19bc1de657c6af65cb1d18a3b9f",
      "closure": {},
      "helper_contract": {
        "qualname": "_open_ports",
        "source_sha256": "b4199ed341491f07ba38a732d25096ab6ce8d3dc848a55a25fda49a4efbbfeff"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.cb.lightsail.ssh_restricted": {
    "batch": "containers-serverless30",
    "description_base_sha256": "afc796ab36386105d37f65741785eb878a4675dc13f6d0e059f3f380c27f1d6b",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 22 and allow the IPv4 world source.",
      "pass_when": "No valid TCP interval containing 22 permits 0.0.0.0/0.",
      "fail_when": "A valid TCP interval containing 22 permits 0.0.0.0/0."
    },
    "remediation_base_sha256": "8a2173b81ec1b2eab6e6e90bce27d52bbd1121bfe0f9890e661d5b42434dc059",
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "_ls_port.<locals>.evaluate",
      "predicate_source_sha256": "708293ce9a9fd6ecbb962e9627865e4a75034e884578a113a4ddca60813b9e8e",
      "closure": {
        "port": 22
      },
      "helper_contract": {
        "qualname": "_open_ports",
        "source_sha256": "b4199ed341491f07ba38a732d25096ab6ce8d3dc848a55a25fda49a4efbbfeff"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.cb.lightsail.rdp_restricted": {
    "batch": "containers-serverless30",
    "description_base_sha256": "64cbe7adbd329d1f4c695400c84b826b5667edd7c99cfba67ef8056f054045b0",
    "description_fields": {
      "description": "Checks whether bounded TCP port intervals include 3389 and allow the IPv4 world source.",
      "pass_when": "No valid TCP interval containing 3389 permits 0.0.0.0/0.",
      "fail_when": "A valid TCP interval containing 3389 permits 0.0.0.0/0."
    },
    "remediation_base_sha256": "0b2e6879788d25989d3e52c294092104ca529ae6003b9513f46e106a150a6dd8",
    "remediation_fields": {
      "summary": "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it.",
      "steps": [
        "Restrict administrative access to necessary sources; retain public HTTP only if the workload needs it."
      ],
      "caveats": [
        "Malformed intervals remain undetermined; these rule declarations do not prove a complete reachable network path."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lightsail TCP rules allow worldwide access to a checked port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "_ls_port.<locals>.evaluate",
      "predicate_source_sha256": "708293ce9a9fd6ecbb962e9627865e4a75034e884578a113a4ddca60813b9e8e",
      "closure": {
        "port": 3389
      },
      "helper_contract": {
        "qualname": "_open_ports",
        "source_sha256": "b4199ed341491f07ba38a732d25096ab6ce8d3dc848a55a25fda49a4efbbfeff"
      }
    },
    "criterion_correction": "Inclusive bounded TCP intervals are tested for containing the selected port; exact interval endpoints no longer required."
  },
  "aws.c2b.emr.cluster_kerberos_enabled": {
    "batch": "containers-serverless30",
    "description_base_sha256": "6804fa598d4c41f2e38b51dd31abfd50f3704744a6a592c75b615504e0dd4027",
    "description_fields": {
      "description": "Checks whether collected cluster details include a non-null KerberosAttributes object."
    },
    "remediation_base_sha256": "b98352e7db215d705d52aac11aaa8798571c8a6bec5605703d6e5e1630b630fc",
    "remediation_fields": {
      "summary": "Configure Kerberos when the cluster authentication model requires it.",
      "steps": [
        "Configure Kerberos when the cluster authentication model requires it."
      ],
      "caveats": [
        "An empty object passes this presence criterion; actual authentication behavior is not tested."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EMR cluster does not declare Kerberos attributes.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "emr_kerberos",
      "predicate_source_sha256": "432be23766563e2e652aaf4a8e03fd471fe346eadacccb1e6f60f24a19569883",
      "closure": {}
    }
  },
  "aws.c2b.emr.cluster_security_configuration": {
    "batch": "containers-serverless30",
    "description_base_sha256": "4372ddad5626ce1566354eb7a4a92b3139291ded2fdb9fdbb859edde056899ba",
    "description_fields": {
      "description": "Checks for a nonempty SecurityConfiguration name in collected cluster details."
    },
    "remediation_base_sha256": "d3f9515eec7a8c5fa73b260f809b86b643e1e2e8256fd23047d36f5ab3b82ad8",
    "remediation_fields": {
      "summary": "Attach an appropriate EMR security configuration if required by the workload.",
      "steps": [
        "Attach an appropriate EMR security configuration if required by the workload."
      ],
      "caveats": [
        "The named configuration contents and effective encryption or authentication are not assessed."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EMR cluster does not declare a security-configuration name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "emr_secconf",
      "predicate_source_sha256": "44308844cd51cbfed520be54c85dce5d706a2a6c864a5076895f7bac9502127b",
      "closure": {}
    }
  },
  "aws.a.s3.mfa_delete_enabled": {
    "batch": "containers-serverless30",
    "description_base_sha256": "286381a60bb603e0acf7370be37a81b55f31459f89f9351fc63b04afa2a50f07",
    "description_fields": {
      "description": "Reads collected Versioning.MFADelete and requires Enabled."
    },
    "remediation_base_sha256": "9d5e0a351300604366d9fe0c7cc42cb185df4ba1954bc20f095bf13d6eaa3476",
    "remediation_fields": {
      "summary": "Consider MFA Delete where its operational restrictions fit the intended deletion-protection design.",
      "steps": [
        "Consider MFA Delete where its operational restrictions fit the intended deletion-protection design."
      ],
      "caveats": [
        "Unproven absence remains undetermined; versioning, Object Lock and effective deletion permissions are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "S 3 MFA Delete is disabled or confirmed absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "mfa_delete",
      "predicate_source_sha256": "e2106a22c3390ee33ae9385a0e2ba2f83127c01eb730d7e644fdc26bdca776cc",
      "closure": {}
    }
  },
  "aws.a.s3.bucket_account_public_blocks": {
    "batch": "containers-serverless30",
    "description_base_sha256": "376e2f93e000a66b7f8feedf9782f16ee881d0653853ca85f3396acdd66e9ff7",
    "description_fields": {
      "description": "Requires every Public Access Block setting at bucket scope or the verified owning-account scope."
    },
    "remediation_base_sha256": "981923fc4cb47823afc110df5d2e5a800e2e36a885ec71f93dc8e9e2c2051344",
    "remediation_fields": {
      "summary": "Enable the missing preventive block settings unless intended public distribution requires a reviewed exception.",
      "steps": [
        "Enable the missing preventive block settings unless intended public distribution requires a reviewed exception."
      ],
      "caveats": [
        "These preventive declarations do not establish that any object is currently public."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "One or more effective S 3 Public Access Block settings are disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "public_blocks",
      "predicate_source_sha256": "9df15c2fa078de27bb0625c50ba721b5cc617f9b556cbc54b872131fffbe2d6a",
      "closure": {}
    }
  },
  "aws.htbp.eks.access_entries_authentication": {
    "batch": "final-native30",
    "description_base_sha256": "ae3ba44b258e1f7b3073f22ae2fad783a54e1e620a179a433540154c931ef9d2",
    "description_fields": {
      "description": "Reads accessConfig.authenticationMode: API passes, CONFIG_MAP fails and mixed mode requires review."
    },
    "remediation_base_sha256": "0be72191854ebae75e8fce110a813c90f88902acac1dba734e2c9349c0ab4a6a",
    "remediation_fields": {
      "summary": "Migrate required identity mappings to access entries and review creator privileges before completing the switch.",
      "steps": [
        "Migrate required identity mappings to access entries and review creator privileges before completing the switch."
      ],
      "caveats": [
        "Mixed API_AND_CONFIG_MAP mode remains manual; this does not enumerate all effective Kubernetes permissions."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The EKS cluster authenticates through CONFIG_MAP mode.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "eks_cluster",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "predicate_source_sha256": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
      "closure": {},
      "delegates": [
        {
          "qualname": "eks_authentication_mode",
          "sha256": "91e3e4c8b5f3fc1b7f2cef3ff53e41ace0817fa219d4a62192056fee5f4eac74"
        }
      ]
    }
  },
  "aws.htbp.ecs.exec_session_logging_not_disabled": {
    "batch": "final-native30",
    "description_base_sha256": "ca199aad47291decd6f2e24d5128b948efebd8302f2e2f30b909ccee01d38853",
    "description_fields": {
      "description": "Reads executeCommandConfiguration.logging and flags explicit NONE; omitted mode defaults to DEFAULT."
    },
    "remediation_base_sha256": "b78a52f7cb878f21ccc3a3f1c7d618fe789c956ca57524f0450b6a3a1f8a2108",
    "remediation_fields": {
      "summary": "Enable suitable ECS Exec session logging and verify the intended task logging configuration.",
      "steps": [
        "Enable suitable ECS Exec session logging and verify the intended task logging configuration."
      ],
      "caveats": [
        "DEFAULT depends on task awslogs settings; this check does not establish transcript delivery."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "ECS Exec session logging is explicitly disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "predicate_source_sha256": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
      "closure": {},
      "delegates": [
        {
          "qualname": "ecs_exec_logging",
          "sha256": "b1493d87b5fd9ac3047cd4442db3359721f7447ddf45f606bcddbabc812d01d8"
        }
      ]
    }
  },
  "aws.htbp.ecs.no_sensitive_host_mounts": {
    "batch": "final-native30",
    "description_base_sha256": "2a16d50cdf23875757a44c953e3ef13baa77a1c7e05d507d5189e57418df15f3",
    "description_fields": {
      "description": "Joins declared host-volume source paths with container mounts and matches the sensitive-path list."
    },
    "remediation_base_sha256": "fbee274ec40af7118fe9b071d654cca0efb6299f64a33bb37c8c3f59667cbc17",
    "remediation_fields": {
      "summary": "Remove unnecessary sensitive host mounts and tightly constrain the agents that require them.",
      "steps": [
        "Remove unnecessary sensitive host mounts and tightly constrain the agents that require them."
      ],
      "caveats": [
        "Read-only mounts are still flagged; declared paths do not prove successful runtime access."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "An ECS container mounts a sensitive host path or runtime socket.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "predicate_source_sha256": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
      "closure": {},
      "delegates": [
        {
          "qualname": "ecs_host_mounts",
          "sha256": "36e328d5f79527c0c6a2eea89cd6d3a39ddaac3ed43b3717ff7078d3aaa14e76"
        }
      ]
    }
  },
  "aws.htbp.lambda.runtime_updates_not_pinned_manual": {
    "batch": "final-native30",
    "description_base_sha256": "42c75ef396f225db4a89f100c7e75ff1d4cb677c147ac2414864aa40c82944e4",
    "description_fields": {
      "description": "Reads RuntimeManagement.UpdateRuntimeOn and flags Manual."
    },
    "remediation_base_sha256": "a48caf7e3c5a601e4fa4c72fde912b0d528a14195367cf9b04c3f628b3bc2ef6",
    "remediation_fields": {
      "summary": "Use Auto or FunctionUpdate unless a deliberate rollback requires manual pinning.",
      "steps": [
        "Use Auto or FunctionUpdate unless a deliberate rollback requires manual pinning."
      ],
      "caveats": [
        "Confirmed absent configuration is not applicable; current support and actual patch level are separate."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "The Lambda runtime management mode is Manual.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "predicate_source_sha256": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
      "closure": {},
      "delegates": [
        {
          "qualname": "runtime_pinning",
          "sha256": "a169235d29b0e1563459261d0f695dc3e038f49109870706bf136b71e95e87fe"
        }
      ]
    }
  },
  "aws.htbp.lambda.env_var_names_not_credentials": {
    "batch": "final-native30",
    "description_base_sha256": "58e8b4ae341514deebfc8e633ccb69e3f81990bcd18982c613e179133b782d53",
    "description_fields": {
      "description": "Matches collected environment-variable names against credential patterns, excluding recognized reference names."
    },
    "remediation_base_sha256": "c11f3d5400609aa708ad1faaf316022b6f43daaaad39dbb8e8a5ce37a8a74db4",
    "remediation_fields": {
      "summary": "Confirm whether the named variables hold secrets and move actual secrets to suitable managed storage.",
      "steps": [
        "Confirm whether the named variables hold secrets and move actual secrets to suitable managed storage."
      ],
      "caveats": [
        "This is a name heuristic; values are not collected and a match does not prove a secret is present."
      ]
    },
    "new_text_only_template": false,
    "observed_fail": "Lambda environment-variable names resemble literal credentials.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "predicate_source_sha256": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
      "closure": {},
      "delegates": [
        {
          "qualname": "env_var_names",
          "sha256": "364bd8c98a86c5c233f00c3e8f8bf80e6217dbb0f726756ba087f9b907ae62d7"
        }
      ]
    }
  },
  "aws_cis_ec2_default_security_group_not_attached": {
    "batch": "final-native30",
    "description_base_sha256": "c6b1650c03bae6c53c53a47f55214ba1123fd19cf1162378950b0126520e1399",
    "description_fields": {
      "description": "Joins every attached interface group to same-VPC inventory and flags groups named default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use application-specific groups where needed and preserve required traffic when replacing attachments.",
      "steps": [
        "Use application-specific groups where needed and preserve required traffic when replacing attachments."
      ],
      "caveats": [
        "Group identity alone does not establish permissive rules; missing group inventory remains undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An attached EC 2 network interface uses the default security group.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "no_default_group",
      "predicate_source_sha256": "78e46725de4641f55283981e062c9ebacf0453e341e9dc46f9bcc1a6a1b75434",
      "closure": {},
      "delegates": []
    }
  },
  "aws_g6_ec2_instance_no_public_ipv6": {
    "batch": "final-native30",
    "description_base_sha256": "ef53190576deeb4dbf4288684778f385d3a5da1b90c0e79cc3655fbe115ae845",
    "description_fields": {
      "description": "Parses assigned interface IPv6 addresses and flags globally routable addresses."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review global IPv6 assignments and restrict intended listeners before removing unneeded addresses.",
      "steps": [
        "Review global IPv6 assignments and restrict intended listeners before removing unneeded addresses."
      ],
      "caveats": [
        "This checks allocation only; routes, ingress permissions and listeners are separate."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 instance has a globally routable IPv6 address assigned.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "no_global_ipv6",
      "predicate_source_sha256": "b5cf516aa808966b059e7e326ee8169dd58a8ccb1b8880bef80642ee1099b479",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_s3_bucket_cross_region_replication_enabled": {
    "batch": "final-native30",
    "description_base_sha256": "29556495f593530e85c2105d63f391784a807ace42da21026760295f438d4d0f",
    "description_fields": {
      "description": "Resolves enabled replication destinations to collected bucket Regions and requires one different from the source."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure cross-Region replication where recovery needs it and verify destination protection.",
      "steps": [
        "Configure cross-Region replication where recovery needs it and verify destination protection."
      ],
      "caveats": [
        "External or unresolved destinations remain undetermined; replication success and recovery are not measured."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The bucket has no resolved enabled replication rule to another Region.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "cross_region_replication",
      "predicate_source_sha256": "a4797c95c0c89de957acaf919bb27c98a6b34caa0182886f8a7712d34ffe04f2",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_lambda_execution_role_exists": {
    "batch": "final-native30",
    "description_base_sha256": "bf76ab767a3377e76d7eb69a862b8199919b923484c879542b941b6942da37b6",
    "description_fields": {
      "description": "Resolves the declared execution-role ARN against complete same-account IAM role inventory."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Assign an existing suitable execution role and verify the function can use its required permissions.",
      "steps": [
        "Assign an existing suitable execution role and verify the function can use its required permissions."
      ],
      "caveats": [
        "Role trust, effective permissions and successful execution are separate."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The function execution role is absent from complete IAM role inventory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "execution_role_exists",
      "predicate_source_sha256": "fe1ee7380147487d7c0d6a56f051194546d8909d9fc2f9b2d90d90f27e72a74d",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_lambda_execution_role_unique": {
    "batch": "final-native30",
    "description_base_sha256": "5ed24dc9c304202f4599bd4e6f48f33cd355a2957625a2486b315e78a22a9aba",
    "description_fields": {
      "description": "Checks active functions against account-wide execution-role usage with complete enabled-Region coverage for a pass."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use a dedicated execution role where function isolation requires it and narrow its permissions.",
      "steps": [
        "Use a dedicated execution role where function isolation requires it and narrow its permissions."
      ],
      "caveats": [
        "Known sharing fails even with partial inventory; a unique role alone does not prove least privilege."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The active Lambda function shares its execution role with another active function.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "execution_role_unique",
      "predicate_source_sha256": "96828a3515a58638f82f03d5691f67150928019ff84604e19efc54f6cf806dbe",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az": {
    "batch": "final-native30",
    "description_base_sha256": "80bc0b60607bb6d05495ffc3d8bbccb8884af6b04abaf5bd53dd28548a30e3c2",
    "description_fields": {
      "description": "Requires two Availability Zones and two distinct explicit MixedInstancesPolicy override instance types."
    },
    "remediation_base_sha256": "41dde8a9fc9b93ebde8cc3eaae6a953c7cfb758c37438821841445378fffa778",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Use multiple zones and suitable instance-type alternatives where resilience requires them.",
      "steps": [
        "Use multiple zones and suitable instance-type alternatives where resilience requires them."
      ],
      "caveats": [
        "Attribute-based instance requirements remain undetermined; this does not test actual capacity availability."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The Auto Scaling group lacks two zones or two explicit instance-type choices.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "autoscaling_group",
      "predicate_qualname": "callback.<locals>.evaluate",
      "predicate_source_sha256": "a3515888007b6245ca46be046ad55d6d9479170e99b7845c65a89988ff8d5a2d",
      "closure": {
        "kind": "autoscaling_group"
      },
      "delegates": [
        {
          "qualname": "autoscaling",
          "sha256": "e2a1bd45a62b0a736e2999f12bc636b345930704c3d43089fce3c079bcdabc65"
        }
      ]
    }
  },
  "aws_ecs_task_definition_credential_environment_names": {
    "batch": "final-native30",
    "description_base_sha256": "5fc5a3d874c254726059188c376b3e4096b14f278d6be78728b7934b5eef6894",
    "description_fields": {
      "description": "Checks complete task definitions for environment names matching the fixed AWS credential-name set."
    },
    "remediation_base_sha256": "2e1fe77d3de6f25e3782fb74a5cf4f391ea568b268f5cbf331389d2b5d30e424",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove literal credential variables when present and use a narrowly scoped task role or secret references.",
      "steps": [
        "Remove literal credential variables when present and use a narrowly scoped task role or secret references."
      ],
      "caveats": [
        "Only names are assessed; actual secret values and runtime credential use are not proven."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An ECS container declares an AWS credential environment-variable name.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_task_definition",
      "predicate_qualname": "ecs_credential_environment_names",
      "predicate_source_sha256": "29fed785837965b739b9995e80a3868170083bfd6abfefb22ec1c4812e272194",
      "closure": {},
      "delegates": []
    }
  },
  "aws_fedramp_emr_master_no_public_ip": {
    "batch": "final-native30",
    "description_base_sha256": "20361241a96d15ddda4810abda841b36cbc73644329e2f7000dcff7288f739c8",
    "description_fields": {
      "description": "Joins the selected primary master to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "predicate_source_sha256": "35cfb68cb9a72c2aa89cd8e511b0f3b74009c88fcce9e926b15627fed45f1f98",
      "closure": {},
      "delegates": []
    }
  },
  "aws.nist.emr_master_nodes_no_public_ip": {
    "batch": "final-native30",
    "description_base_sha256": "1382d469fa88e78f2b21ed4669d362b7e9b950b130cf80840931ea2e28e0ef4e",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "predicate_source_sha256": "35cfb68cb9a72c2aa89cd8e511b0f3b74009c88fcce9e926b15627fed45f1f98",
      "closure": {},
      "delegates": []
    }
  },
  "aws_nist_emr_cluster_master_nodes_no_public_ip": {
    "batch": "final-native30",
    "description_base_sha256": "7b06871769f275b058e4c69efc581a348c5f627600fa5490fca1bd08605bab9b",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "predicate_source_sha256": "35cfb68cb9a72c2aa89cd8e511b0f3b74009c88fcce9e926b15627fed45f1f98",
      "closure": {},
      "delegates": []
    }
  },
  "aws_g6_emr_master_nodes_no_public_address": {
    "batch": "final-native30",
    "description_base_sha256": "b4ede23befbbfa6791cc6f495c76ab6e6d7f87a50d1694da60c99d5efff20be7",
    "description_fields": {
      "description": "Joins all reported master instances to EC2 interfaces and flags public IPv4 or global IPv6 assignments."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Keep master-node addressing private where required and preserve administrative access through controlled paths.",
      "steps": [
        "Keep master-node addressing private where required and preserve administrative access through controlled paths."
      ],
      "caveats": [
        "Only running or waiting clusters apply; incomplete joins remain undetermined and network reachability is not probed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-security-groups.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed EMR master node has a public address assigned.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "emr_cluster",
      "predicate_qualname": "callback",
      "predicate_source_sha256": "35cfb68cb9a72c2aa89cd8e511b0f3b74009c88fcce9e926b15627fed45f1f98",
      "closure": {},
      "delegates": []
    }
  },
  "aws.pci.s3.bucket_backup_plan": {
    "batch": "final-native30",
    "description_base_sha256": "5467b57b9fcfd25044b1dae1a9fd2c5f234f356939d9c769fefe50b6d4d08afe",
    "description_fields": {
      "description": "Requires an explicit non-excluded bucket ARN in an active scheduled backup selection with complete enabled-Region coverage."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the bucket in the intended scheduled backup plan and verify suitable recovery points.",
      "steps": [
        "Include the bucket in the intended scheduled backup plan and verify suitable recovery points."
      ],
      "caveats": [
        "Wildcard or conditional selections remain undetermined; plan membership does not demonstrate a successful backup."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying explicit scheduled backup selection includes the bucket.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "bucket_backup_plan",
      "predicate_source_sha256": "60558e41548e0f59ac110f9a519a631cc655c2364693776cdcfc4e1d6ef75064",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_beanstalk_persistent_logs_s3": {
    "batch": "final-native30",
    "description_base_sha256": "6d7ea53d52ffaa5c534ad4cdf18fcff8943f0b281c387ff9615296450c820158",
    "description_fields": {
      "description": "Requires LogPublicationControl=true and a resolved S3 log bucket and prefix for an active environment."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable required persistent log publication and resolve its intended S 3 destination.",
      "steps": [
        "Enable required persistent log publication and resolve its intended S 3 destination."
      ],
      "caveats": [
        "Terminating environments are not applicable; actual delivery and retention are not measured."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "Beanstalk log publication is disabled or its S 3 destination is unresolved.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "99bdd26e9c1fc8833e997fdbc16598cf633a793518a7f6fc7509becf02358868",
      "closure": {},
      "delegates": [
        {
          "qualname": "_persistent_logs",
          "sha256": "2a2d4dcf4d492b60c94907d4574095e66cc2a9aa3c37ba084e0495c308f549ff"
        }
      ]
    }
  },
  "aws_cis_ec2_userdata_embedded_secrets": {
    "batch": "final-native30",
    "description_base_sha256": "7c5bb9432ed417194df771933fb1e7c371f8deb60f2d74ae33ff290585901e11",
    "description_fields": {
      "description": "Validates the collected instance-bound user-data secret-indicator projection and flags recognized high-confidence categories."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove confirmed embedded secrets and rotate exposed credentials after migrating consumers.",
      "steps": [
        "Remove confirmed embedded secrets and rotate exposed credentials after migrating consumers."
      ],
      "caveats": [
        "Only projected categories are returned; raw user data and secret values are not exposed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The user-data projection reports high-confidence embedded secret indicators.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "userdata_embedded_secrets",
      "predicate_source_sha256": "d01ef6b1e851c9100c016dd087638d73f59ecf0a884ff266f5cab3c83d847bdc",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_elasticbeanstalk_https_listener": {
    "batch": "final-native30",
    "description_base_sha256": "c52ff2ce5e94f616c1635598e3539f55fe169c189d9a5ca3866cb99dfdfb642e",
    "description_fields": {
      "description": "Requires associated load balancers to declare certificate-backed TLS and redirect plain listeners to HTTPS."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Configure suitable TLS listeners and redirect or remove unnecessary plain listeners.",
      "steps": [
        "Configure suitable TLS listeners and redirect or remove unnecessary plain listeners."
      ],
      "caveats": [
        "No active associated load balancer is not applicable; certificate validity and actual routing are not tested."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.loggingS3.title.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An associated Beanstalk load balancer lacks required TLS or permits plain forwarding.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "99bdd26e9c1fc8833e997fdbc16598cf633a793518a7f6fc7509becf02358868",
      "closure": {},
      "delegates": [
        {
          "qualname": "_https_listener",
          "sha256": "3dd0921a28699a8e6b2ff29f0c2cfa2abcc55b09afb2bd59f1d4cb186ef18b96"
        }
      ]
    }
  },
  "aws_cis_elasticbeanstalk_load_balancer_access_logs": {
    "batch": "final-native30",
    "description_base_sha256": "c84dd8b4ea7338f2c959509011374d464f8f2f18d0f55b267763222c4a9a00c7",
    "description_fields": {
      "description": "Reads the access-log enabled attribute for every associated active load balancer."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable required load-balancer access logs and protect their intended S 3 destination.",
      "steps": [
        "Enable required load-balancer access logs and protect their intended S 3 destination."
      ],
      "caveats": [
        "This checks enabled declarations, not delivery, destination security or retention."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.loggingS3.title.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An associated Beanstalk load balancer has access logging disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elastic_beanstalk_environment",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "99bdd26e9c1fc8833e997fdbc16598cf633a793518a7f6fc7509becf02358868",
      "closure": {},
      "delegates": [
        {
          "qualname": "_lb_access_logs",
          "sha256": "eb43c391c50dea846f16bc4ddf03562c2e1cfd925dd09980c74abaab9bc165c3"
        }
      ]
    }
  },
  "aws_cis_lambda_execution_role_no_admin": {
    "batch": "final-native30",
    "description_base_sha256": "5fbbb0314b6623d4e392687b12eea214c858bb93004d515c93e73ced59442e8d",
    "description_fields": {
      "description": "Requires a complete role-bound effective-policy projection and flags unconditional action/resource wildcard administration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Remove unnecessary administrator grants from the execution role and retain required function permissions.",
      "steps": [
        "Remove unnecessary administrator grants from the execution role and retain required function permissions."
      ],
      "caveats": [
        "Incomplete policy, boundary, session or organization constraint analysis remains undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The Lambda execution-role projection establishes unconditional administrator access.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "lambda_function",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "9603f2932f36a82f4762d424b9106ba27e31f10d1f07f60bc7db07ece1f79f47",
      "closure": {},
      "delegates": [
        {
          "qualname": "_admin",
          "sha256": "4a6e5fb046eb40a36ca2e5235eb7263c4aa99323b68f277b2819d71036e9f0b9"
        }
      ]
    }
  },
  "aws_cis_lightsail_ssm_patch_compliance": {
    "batch": "final-native30",
    "description_base_sha256": "7b82c7f97efe631e5e61364fcdb9b832fc03d2324a055408c96802b7e21c7116",
    "description_fields": {
      "description": "Verifies the Lightsail-to-SSM mapping and flags positive MissingCount, FailedCount or InstalledRejectedCount values."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Resolve the reported missing, failed or rejected patches using the workload patch process.",
      "steps": [
        "Resolve the reported missing, failed or rejected patches using the workload patch process."
      ],
      "caveats": [
        "Malformed counts or unverified instance mappings remain undetermined; patch freshness is not assessed."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "SSM reports missing, failed or rejected patches for the matched Lightsail instance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lightsail_instance",
      "predicate_qualname": "lightsail_patch",
      "predicate_source_sha256": "70e98bfd178581ae0f764b67a19623e49dc2599f74d401447b2f4bfc403eac8d",
      "closure": {},
      "delegates": []
    }
  },
  "aws_cis_s3_macie_classification_coverage": {
    "batch": "final-native30",
    "description_base_sha256": "59a687ec1f965714d5717a4ab7df8c83db01412134afbf855408245b6c00c288",
    "description_fields": {
      "description": "Checks regional Macie enablement and automated discovery or a running/completed classification job selecting this bucket."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable appropriate discovery or configure a classification job covering the intended bucket.",
      "steps": [
        "Enable appropriate discovery or configure a classification job covering the intended bucket."
      ],
      "caveats": [
        "Selection does not prove every object was analyzed; unresolved job criteria remain undetermined."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying Macie discovery or classification-job configuration covers the bucket.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "bucket",
      "predicate_qualname": "macie_classification_coverage",
      "predicate_source_sha256": "21762658802418600d0888e1d5f49611fdb841287ba5b143257266465dd27a6c",
      "closure": {},
      "delegates": []
    }
  },
  "aws_ebs_snapshot_trusted_accounts": {
    "batch": "final-native30",
    "description_base_sha256": "c953add3fd0e76cc6c08604b33cbf9c97d08895b648456ed43c66175303b910e",
    "description_fields": {
      "description": "Compares snapshot create-volume grants with the explicitly supplied trusted-account allowlist and flags public grants."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Review external grants and restrict snapshot sharing to intended recipients.",
      "steps": [
        "Review external grants and restrict snapshot sharing to intended recipients."
      ],
      "caveats": [
        "This historical custom-policy check cannot infer trusted third parties from read-only cloud configuration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The snapshot grants access outside the supplied trusted-account allowlist.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ebs_snapshot",
      "predicate_qualname": "check_aws_ebs_snapshot_trusted_accounts",
      "predicate_source_sha256": "8117f9a1699c187d6db792001b2da5be9114b8163251355a52df8995f6fccf96",
      "closure": {},
      "delegates": []
    }
  },
  "aws_ec2_instance_time_offset_monitored": {
    "batch": "final-native30",
    "description_base_sha256": "3bb27b9b62a21b21293fe89b20d1a840a2416db806c8c0b1c84d00d5333cd624",
    "description_fields": {
      "description": "For running instances, checks the bound CWAgent time_offset sample is within 1000 milliseconds and 24 hours old."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Investigate excessive clock offset or restore current time-offset telemetry.",
      "steps": [
        "Investigate excessive clock offset or restore current time-offset telemetry."
      ],
      "caveats": [
        "Future, missing or mismatched samples remain undetermined; this does not directly query the operating-system clock."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 time-offset sample exceeds the offset or freshness threshold.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_make.<locals>.evaluate",
      "predicate_source_sha256": "ece643fcf7b6f37ee64c32732f3b18acfd79f12d26ebdc595399679a8338ee88",
      "closure": {
        "cid": "aws_ec2_instance_time_offset_monitored"
      },
      "delegates": [
        {
          "qualname": "_ec2_time",
          "sha256": "43718fef595cceb044ffe45fdcb849f9dc6bfacc2c16e89d4d2dd3ae2fb54cb3"
        }
      ]
    }
  },
  "aws_g6_ecs_fargate_storage_encryption": {
    "batch": "final-native30",
    "description_base_sha256": "c7d2eb3da02f6a931817641af3486d15656c830619e6d57cdfe4ebd1a46b2088",
    "description_fields": {
      "description": "Joins service launch-volume configurations and task EFS references, requiring encryption on associated managed EBS and EFS storage."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Enable encryption on the identified storage and migrate safely when replacement is required.",
      "steps": [
        "Enable encryption on the identified storage and migrate safely when replacement is required."
      ],
      "caveats": [
        "This source criterion assesses associated storage declarations, not all Fargate ephemeral storage or effective key authorization."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "An assessed ECS service volume uses unencrypted managed EBS or EFS storage.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "ecs_cluster",
      "predicate_qualname": "_install.<locals>.check",
      "predicate_source_sha256": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
      "closure": {
        "identifier": "aws_g6_ecs_fargate_storage_encryption"
      },
      "delegates": [
        {
          "qualname": "_ecs",
          "sha256": "133fd7f5b2ee8129336f297202ff3bb3895008c6ff00e23da9f4c75c2690e2a7"
        }
      ]
    }
  },
  "aws_g6_efs_effective_backup_plan_selection": {
    "batch": "final-native30",
    "description_base_sha256": "9e6ab21450872a0848c54798fa8c4452cf2d269be3755f84fe1fbdc3e8fd133e",
    "description_fields": {
      "description": "Matches enabled backup-plan selections using resource patterns, exclusions and supported tag conditions; requires a declared IAM role."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the filesystem in the required backup selection and verify suitable recovery points.",
      "steps": [
        "Include the filesystem in the required backup selection and verify suitable recovery points."
      ],
      "caveats": [
        "A matching selection does not prove role usability, completed backups or successful restoration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying enabled backup-plan selection matches the EFS filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "ee842f8a3599092126ec189037cbc6fc57a65b3af746985a2dca092ab9f7f4cc",
      "closure": {},
      "delegates": [
        {
          "qualname": "<lambda>",
          "sha256": "3243dffa921c40318a69334b2aea6670efbb6916ae835dc25333d46e17b311db"
        }
      ]
    }
  },
  "aws_nist_ec2_instance_not_publicly_accessible": {
    "batch": "final-native30",
    "description_base_sha256": "82d56a8c89b258d441c9ffcb1fce8224df18f44b9b2f0581fb97e010a81445a0",
    "description_fields": {
      "description": "Requires complete route, ingress, target and listener projections, then flags public paths with all three access conditions true."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Restrict unnecessary public listeners or ingress sources while preserving intended access.",
      "steps": [
        "Restrict unnecessary public listeners or ingress sources while preserving intended access."
      ],
      "caveats": [
        "This uses the collected reachability projection; it does not send packets or establish application authentication."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "The EC 2 reachability projection reports a complete permitted public path.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "instance",
      "predicate_qualname": "_make.<locals>.evaluate",
      "predicate_source_sha256": "ece643fcf7b6f37ee64c32732f3b18acfd79f12d26ebdc595399679a8338ee88",
      "closure": {
        "cid": "aws_nist_ec2_instance_not_publicly_accessible"
      },
      "delegates": [
        {
          "qualname": "_ec2_public",
          "sha256": "4392038a3c9834d48010a0335f4308db3808dad52bcbdee9978e9bf405fcc393"
        }
      ]
    }
  },
  "aws_nist_efs_file_system_in_backup_plan": {
    "batch": "final-native30",
    "description_base_sha256": "de9f706c2bd49f32a17f7cd8914318fb5771e8997db59ba97e4b035256f47768",
    "description_fields": {
      "description": "Matches enabled backup-plan selections using resource patterns, exclusions and supported tag conditions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "review_status": "approved",
      "summary": "Include the filesystem in the required backup selection and verify suitable recovery points.",
      "steps": [
        "Include the filesystem in the required backup selection and verify suitable recovery points."
      ],
      "caveats": [
        "A matching selection does not prove role usability, completed backups or successful restoration."
      ],
      "cli": [],
      "references": [
        {
          "title": "AWS service security reference",
          "url": "https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html"
        }
      ]
    },
    "new_text_only_template": true,
    "observed_fail": "No qualifying enabled backup-plan selection matches the EFS filesystem.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_file_system",
      "predicate_qualname": "_evaluate",
      "predicate_source_sha256": "ee842f8a3599092126ec189037cbc6fc57a65b3af746985a2dca092ab9f7f4cc",
      "closure": {},
      "delegates": [
        {
          "qualname": "<lambda>",
          "sha256": "0e652da72e044777160f614e464a892955ec86ecf7acb509ebcbd5cc8180bd61"
        }
      ]
    }
  }
}
''')


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",", ":"),ensure_ascii=False).encode()).hexdigest()


def _apply(cid,original,kind):
    row=ROWS.get(cid)
    if row is None:
        return deepcopy(original)
    if _digest(original)!=row[kind+"_base_sha256"]:
        raise ValueError("Reviewed compute/storage clarity base changed: "+cid)
    if kind=="remediation" and row["new_text_only_template"]:
        current={}
    elif isinstance(original,dict):
        current=deepcopy(original)
    else:
        raise ValueError("Reviewed compute/storage clarity base type changed: "+cid)
    current.update(deepcopy(row[kind+"_fields"]))
    return current


def description(cid,original):
    return _apply(cid,original,"description")


def remediation(cid,original):
    return _apply(cid,original,"remediation")


REVIEWED_RISKS={cid:(row["reviewed_source_severity"],row["reviewed_severity"]) for cid,row in ROWS.items()}

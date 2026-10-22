"""Exact binding for the additive principal-target v4 catalog and legacy cards."""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import tarfile
from pathlib import Path

import yaml

from .schema import CATALOG_DIR, CatalogError, load_catalog

BINDING_SCHEMA = "privesc-catalog-binding-v1"
LEGACY_MANIFEST = "fe767aecd3beee553441ec6e586fa5aa6a946345b7beca43397e4c4c7c6bb481"
LEGACY_REVISION = "0b3633117413069d93b713d2a98a9e16b1d189f3"
LEGACY_DELTA_SHA256 = "40640ad0e7179af395ec37f9456ef7b9d8340e8ab81e9edb7a460769edca258a"
V4_MANIFEST = "6008acf71acda21408c7039dddff2d7ccaeeaa3aecfc6f31ef5d2cdc5a4ea388"
V4_REVISION = "4913b6d88ced9972f72ccdd708d21641725a6fb5"
V4_EFFECTIVE_TREE = "413792ea4aec86e48c352ffab2c0bea9e82795bc234251342737ec0276b748d2"
LEGACY_DELTA = Path(__file__).resolve().parent / "catalog_versions/legacy-0b3633-delta.json"
BOUNDED_MANIFEST = "734401b202895e00ac1b6cb0f1534f77cde4d8e2ba912ca0ee974b1b8ec5035c"
BOUNDED_TREE = "1a54bad4102d18f89c78f45c915964554a62f994c1bffa693844cac5e119cca8"
CURRENT_MANIFEST = 'f8336a45e947eda18a1580f331e11db183c05a2a522019ce4d162a5704ba21f5'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST = '51ad72ee8e05dacaca2b532cd851d8527a00930bb7475d5e2154ea1b6059158d'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE = 'a3334fa6d17032c44e0f37cd1d83b1aadfdc4247fe836ca616a66494911714d1'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '2c5161a4c90c79611b2a2c1694527376fd5cf2f5b28733c69c03910f59cb008b'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-effect-source-manifest.json'
BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-effect-catalog.tar.gz'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST = '8ce864b0fe471254abb80bfeb68cdb5146692eda4be282494a3c5fb771a6c9be'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE = '739e8413a050127100d094cca16689ded67edc500866d7924b23c8b234cd1628'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '721afb18982a26ee59e145e703e744bf022a3170439f62dd09070348b7ed0e7e'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-effect-source-manifest.json'
AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-effect-catalog.tar.gz'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST = '49ef0c95f71e891a4604037d0197d90fe455c829fedcbd54c0e800c4351a7db0'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE = '7a122fab5b7a1ae53982a2bdf557863210f5d6188366aa006a9628724a3faa64'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'cfb29edb1ebb14ea22f727b7b3f949bc2beebb9f6583cc6bbabe1cb246f8ca0d'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-effects-source-manifest.json'
AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-effects-catalog.tar.gz'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST = '5b905aecc542a60efecc97e6403d740ef7c9f770bdfe4ae93b2f2a0e42bd6a86'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE = '8a8eaeb5628ea6111417f2f73d6e2243b1ff59edf9a87e623a99a7dd3f71676f'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'b133c40b7d937de0592a2b4b3293f9e1b2e014269171e4f37004b2980fbb183d'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-amplify-role-effects-source-manifest.json'
AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-amplify-role-effects-catalog.tar.gz'
CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST = 'f3bfba9621bff59733dc98b0fe121aa5bb3c68c719ad2e7068f37a9e66ce56c0'
CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE = 'b025978c4283bb3280a2ddefc075e89d9309d12526b05ed870d8a077494c75b9'
CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256 = 'bbed62b8b77c872a0a594ff51de1fad951633972b9040b23ab6bbe2921df1d3c'
CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-stackset-effects-source-manifest.json'
CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-stackset-effects-catalog.tar.gz'
CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST = 'd9a85c3da367de77a3dcf10ef968edbd918119346efab80e8f94bec62c9e7b91'
CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE = '558fe51a5c9922b03131ec96f4c917ab73d54b179c87c033b948ae3d0c3e35b4'
CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '57db9b70702d20b6e459f818a2c46c75f6c874168142923c9266d30f8e447dc3'
CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-extension-effect-source-manifest.json'
CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-extension-effect-catalog.tar.gz'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST = 'f3ed89fd4e4884b3e526ddbcf04fd202b3c56be995f97bf46cc9d4fd35bdae95'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE = 'd8a6d6eecd5a1549e40e7b5844b0d7a73c5c83d84c9b5eff5460bda963ed0f8b'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '2f3a3ff201aceaa530fc66f593a279bc3a4cb228e0b9f5149b4a7e457e07f99d'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-template-effect-source-manifest.json'
CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-cfn-template-effect-catalog.tar.gz'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST = 'f0586639b1ad4837cac0dc5b12806d0ced42bb2fb0c4aa1328e3f2afb7e88fb7'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE = '363415fa117bdacb6974de883392d7a6a1da3b54eb4f06bc8ace64714003671a'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '3b17dbdb69bf3ab6a2f8ec64211e94a6109bda3d8d8d0396fbd5f8c38f9b6c10'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-teststate-role-effect-source-manifest.json'
TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-teststate-role-effect-catalog.tar.gz'
SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST = '530170809258602823f876081bb4c85b2817c0d62f5161344652189ea0924c43'
SFN_ROLE_EFFECT_691_PREVIOUS_TREE = '16825d2b867b660efb9d3e7f47bc47542f9ca5b0e97d9a8b631e60f5123d5644'
SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256 = '21d3cef33b6297fee68ae4674b6b9f8aeadcc5a32531328cd95103c545307a67'
SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sfn-role-effect-source-manifest.json'
SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sfn-role-effect-catalog.tar.gz'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST = 'f868300f0dd2c8c4cec0e77aa8bb2e9a23b44c8fa740d6c9566134bdd589cbd1'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE = '7fa8d5aee2d834b447c4044e7c3de29dff646646b053e60dff16ab1da95cee2b'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE_SHA256 = '1e8854b793889ad9ba630f8a3b66eed206809d6888269ebd793c5c50cc59c18c'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-instance-connect-witness-source-manifest.json'
INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-instance-connect-witness-catalog.tar.gz'
ECS_TASKSET_691_PREVIOUS_MANIFEST = 'f1a9881cb26ee82add04203c590a097dfcbbda3d28e494f6e88bd2cb9340aec3'
ECS_TASKSET_691_PREVIOUS_TREE = 'fcf5b88f42934843baf95fe1d0c5d4cea59014de4f4965964c358d6ea915996d'
ECS_TASKSET_691_PREVIOUS_ARCHIVE_SHA256 = 'd9e3f7d8b25b396c1db7fa6f194f379a6e414a9817df6c20bda14d84f2c05cce'
ECS_TASKSET_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-taskset-source-manifest.json'
ECS_TASKSET_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-taskset-catalog.tar.gz'
ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST = '5561563fabef7927c2763f40b5a04ba3ceb544cdf47674fe0b7f898f96c40583'
ECS_NODE_ESCAPE_691_PREVIOUS_TREE = '5550788c8db2fc527af237a77d9477597038ed825c171c95dd162a71c24d2800'
ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE_SHA256 = '9cf128317951805677d171707eca8641c6147dcd2428fe9488e9e1a51eed3c7d'
ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-node-escape-source-manifest.json'
ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-node-escape-catalog.tar.gz'
ECS_SERVICE_691_PREVIOUS_MANIFEST = 'f677bda213c14acfb265232020ac1f40299d9a578b1c245b8cc4997afdcd669f'
ECS_SERVICE_691_PREVIOUS_TREE = '1d5715aa0b5bab28f619adf3bf28f5843d7b320bfea0b1cfa3cc7869d1f09ed9'
ECS_SERVICE_691_PREVIOUS_ARCHIVE_SHA256 = 'ace7f8bf08f5b4cc6246f0f6447617370b64a2ec98fbe668892be308c9556b9a'
ECS_SERVICE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-service-source-manifest.json'
ECS_SERVICE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-service-catalog.tar.gz'
ECS_START_TASK_691_PREVIOUS_MANIFEST = 'cc82aa1ec6b773f74eae2c9cd1151117fa5b4429d49db99e21361a6340af04c5'
ECS_START_TASK_691_PREVIOUS_TREE = '0ff0d0acb3b498cfe7ff075c67997faf7ff9c90530f30636106a228c221d6a57'
ECS_START_TASK_691_PREVIOUS_ARCHIVE_SHA256 = '655e6b485b22bf6acb720b6f06440d8d9e7228d1a2a9f5c811210f60309561d0'
ECS_START_TASK_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-start-task-source-manifest.json'
ECS_START_TASK_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-start-task-catalog.tar.gz'
ECS_NEW_TASK_691_PREVIOUS_MANIFEST = 'eaa7ebf65018ebf1050dd6e0da0f0fe5faeba1cb8860e58d767ff5514f1b26a0'
ECS_NEW_TASK_691_PREVIOUS_TREE = '14c112c88b85e8b2b7931b3bc1188be670c78101f832b5af82d623b57976f35e'
ECS_NEW_TASK_691_PREVIOUS_ARCHIVE_SHA256 = '5df7bb9d79c556cfb7434981f7e9c25385d3cd37d7f70a309c3521021350e528'
ECS_NEW_TASK_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-new-task-source-manifest.json'
ECS_NEW_TASK_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-ecs-new-task-catalog.tar.gz'
ORGANIZATIONS_RCP_691_REVISIONLESS_MANIFEST = '7d528406be7793c99131834f3b4747dbf14fec5ac0515d813c60949670c1baba'
ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST = 'fb78323d003a13e56cb130b11cbc5b5236bd91c31a67f0cc81c5aae05eaac45e'
ORGANIZATIONS_RCP_691_PREVIOUS_TREE = 'e79cf10386508df546b33f8383e78907948571eaf6479b2047a8a45683b65ae8'
ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE_SHA256 = '511107dedd9565230d7b23cd67856f2d4c658e2429460796cf8b9fb097c38c6f'
ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-organizations-rcp-source-manifest.json'
ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-organizations-rcp-catalog.tar.gz'
LAMBDA_SIGNER_691_PREVIOUS_MANIFEST = '8307e36f62dcbb54c919323e0d64ada6c22eea1d9eb24fd0226206b11614c08b'
LAMBDA_SIGNER_691_PREVIOUS_TREE = 'd3922e48ac9141556673d0efc1abd97ba6098dd5da25ae2adb4e205a5ae40a9c'
LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE_SHA256 = 'b0a1b2f8cdbba10a915270d3d1f92fb20652f986c856ee3da267f0fdcbc5b2bf'
LAMBDA_SIGNER_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-signer-source-manifest.json'
LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-lambda-signer-catalog.tar.gz'
BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST = '3fdcb007a021b3ef361042ab08f872b94b4fbd9f8a9dd75cb559121ab151b548'
BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE = '6afe893eae9983f5ade792d4843859d17345e976d42059c20956006f05239b28'
BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE_SHA256 = 'e6b9c6578202c95cd66f6c884bd8ba2ca15fc3211361937dad140e6e06807347'
BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-source-manifest.json'
BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-bedrock-actiongroup-catalog.tar.gz'
QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST = '19bf9a8082fa3a377c618ad7913031984c5e26a284eb97973db4e2a3ad247b6c'
QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE = 'aae59f4e332677bf53b6a818be971322e6b3dd6abaa235d656d0e4ad091dc7cc'
QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE_SHA256 = '0442c1a94aa226ca060762d87057a63472b0c1dfb84238698708276f4645a2c6'
QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-quicksight-iam-user-source-manifest.json'
QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-quicksight-iam-user-catalog.tar.gz'
KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST = 'ca9cdc54975419f2a34f0f63b21f786020a29cc1805bfd10e7e7c708206b6724'
KAFKACONNECT_GUARD_691_PREVIOUS_TREE = 'dbea3e2c627b7f6eba5419a35136c0e64a494a515dda2a908cbd3ae322d712ec'
KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE_SHA256 = '47f2d1ddebce44c6a0ec35227fb2755a0354ed15c69f64d1dc742e7613fff409'
KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-guard-source-manifest.json'
KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-kafkaconnect-guard-catalog.tar.gz'
BRAKET_SCRIPT_691_PREVIOUS_MANIFEST = '0ce8c76fdce5d95d95e0356a00a4b0d74c83dda2978ad01e6a1f6b2aeabbd0ef'
BRAKET_SCRIPT_691_PREVIOUS_TREE = 'e9066dcaa6f9922dc2c052b40b91890b080050196a18a91813569b424fa6c648'
BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE_SHA256 = '116de18203795165e7fadd8e3b9a3aadfd2a6ab7b24ceb6f5abee22a0709bd7e'
BRAKET_SCRIPT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-braket-script-source-manifest.json'
BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-braket-script-catalog.tar.gz'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST = '392a4be387c23be959eb5f576754139a927dd25d1792a8d449c3ee60d5773200'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE = 'f3583c06bde667bfd76875c5e26d419c48da172f627a7102764c28a8e814d3a7'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE_SHA256 = '052a888ebaa2aa10575e91231642ea5e62018490f0691ab3486e172c664185ed'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-domain-default-source-manifest.json'
SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-domain-default-catalog.tar.gz'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST = '56ae535cd55189ad085897b4827810fc54b0a22a1ea3257ae9f8f2b64febb640'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE = 'c5d892bce674772fd331fd1dade9179dd2585862ac6a59307b67d9d80b676dc5'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256 = 'fe2e845edbdc735fd8004f0ac1a711a4bcf22c109fae5800bd4674e2fa55ac14'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-role-swap-source-manifest.json'
SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-role-swap-catalog.tar.gz'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST = '4dcaaedf17e9a32f4be83a2bdf2b89449d0e26f50e2ceebcdcd660654a076b58'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE = '3be383bad95b339d945719d0f945077b49ed3cba1e7e836ccb256d520bd44def'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE_SHA256 = 'c8f9b66155d2048e71eba4afadddbc8a59b50b3781efb5ebd2031c93d9bb51c6'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-new-profile-source-manifest.json'
SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-new-profile-catalog.tar.gz'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST = '0f335824eeb4cc48a61e8933dafb44e642ad6d6ae14a6b505cd69a2adb718add'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE = '3aff7843f0fa840ec3972b1e45135ab115bbc7a9d42e7c9d5942dfe10d5acdd5'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE_SHA256 = '8e18ccbe4fe86756a95178897dfa68c67becf4198378b0efca0af924212b49b9'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-studio-profile-source-manifest.json'
SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-studio-profile-catalog.tar.gz'
SAGEMAKER_HPO_691_PREVIOUS_MANIFEST = '89035f1582caf6c7432d96e9588c9fefb12672f0c7803bf18237c5de6333a07e'
SAGEMAKER_HPO_691_PREVIOUS_TREE = 'd1da99310af26bc3bf72599cb916b73ecfd5f2bdf7e2c49985686b9ee02b038e'
SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE_SHA256 = 'c2ad00104eb25ae4b053915e9fa50a1ce6a71bbf135fad2f6593c31d88701855'
SAGEMAKER_HPO_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-hpo-source-manifest.json'
SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-hpo-catalog.tar.gz'
SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST = 'fa4f4499c5cb0a1ea4dc496168823bf43793442796e3dc05f9ea9fed9a2cdec0'
SAGEMAKER_TRAINING_691_PREVIOUS_TREE = '231f6c0a3e59f7657ef024e97092eecba2806d7d1be6ba77827cd121b4df1cba'
SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE_SHA256 = '504045ad4a28c0f86e68f4c633af9ee23e4d3e69415b8f06b507a400aab3f8fa'
SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-training-source-manifest.json'
SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-training-catalog.tar.gz'
SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST = '0a7b194cdaceb8c90e1595914f39a8d40aef3b30c56364ccf6473d3263b7068e'
SAGEMAKER_PROCESSING_691_PREVIOUS_TREE = 'de0d1a5f2bdc6f27fb016007c6f7d3963a6b40b7c7be3c1bebadf979468f76a3'
SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE_SHA256 = 'be0662361f363634bb51f05a1b2f80b3dfad55f93ea25050e857b0c2412ef2e4'
SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-processing-source-manifest.json'
SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-processing-catalog.tar.gz'
SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST = '47fdcba8d133a306b9317f2bcad6c7a77e96d12a65123d2f486dfd0700f68c04'
SAGEMAKER_JOBS_691_PREVIOUS_TREE = '848f9d1792a34ea8c00efad0bf1937b21ed2b9f93a15aee1829b245e1fc79304'
SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE_SHA256 = '7cbfcb11a726a8475fae954481fea6db84b47309ab7c46d8a9cc54b288216833'
SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-jobs-source-manifest.json'
SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-sagemaker-jobs-catalog.tar.gz'
AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST = '81627b08898b863af35f59a5332f7621f8aa8d06cd375b7f9753e733da3e2395'
AGENTCORE_HARNESS_691_PREVIOUS_TREE = 'ea1e585646eaea4c98b43fca034d006cae9fd40f03cf288f98862b5649aea6cf'
AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE_SHA256 = '2adc4f6ac05da00f15b583d67f1b352398b2fb2a434d2308e46d57a468ae88c0'
AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-source-manifest.json'
AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-harness-catalog.tar.gz'
AGENTCORE_CREATE_691_PREVIOUS_MANIFEST = 'f92c37efdda62e967b9d9ade6e8e54177d6aee388adccadab7f56ac285dc4962'
AGENTCORE_CREATE_691_PREVIOUS_TREE = 'e236cb6644af345fccdbb4fc360ecba35cc1da5eadaf416dd64ef1d17d718399'
AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE_SHA256 = 'b97efb36f1a85326abd19a80d0276460962daac558e9ed37e155a1362abca530'
AGENTCORE_CREATE_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-create-source-manifest.json'
AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-create-catalog.tar.gz'
AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST = 'ac9b5fef566fed0d17edec1e7c59851693e7f046791eb17372eb3ea6e4917f08'
AGENTCORE_RUNTIME_691_PREVIOUS_TREE = 'b24b77793e75ed4604d2ef9e9a4ac80f1f5285c0cdc38d1f66952537ca4a416f'
AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE_SHA256 = '7e06d00f5871dadeca62ce7826945ebebcfc9e30b6037e7729150553a6e47d96'
AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-source-manifest.json'
AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-691-agentcore-runtime-catalog.tar.gz'
AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST = 'a7a84dd20d61b4083c7be91e42c54f93bf4d4f7cb1e87a1521a18127979d5e5e'
AGENTCORE_EXISTING_690_PREVIOUS_TREE = '5c64f696e91db857c524df563419f870dc80beb12573d16d269a7cf365894786'
AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE_SHA256 = '08c960e9e96e2e20f96c58a707438e0d2f5b4472fddbe86cf0481675a1e373f2'
AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-existing-source-manifest.json'
AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-existing-catalog.tar.gz'
AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST = '6460f3bdd25bb05f15a3a33b2b23c57781b28fce63fe44a7d3a7bcf51f9aa495'
AGENTCORE_BOUNDS_690_PREVIOUS_TREE = '3e4ea09bcfbec4ae862853d6893a9a280e68508586151afe84c674d45d2bb629'
AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE_SHA256 = '1a1ac60d7cf7943142fa79efdef01e976eb04dd971d5597e2e53a7f334cc162d'
AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-bounds-source-manifest.json'
AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-agentcore-bounds-catalog.tar.gz'
STS_FEDERATION_690_PREVIOUS_MANIFEST = '01fd53c0626d86f93074ff5bf9df156a9669fbfdcde49e4fdf62e98651800177'
STS_FEDERATION_690_PREVIOUS_TREE = '6f53ecb88d28c8d85b5662af8bab7d057593105d4a6d00a16f04e6c35ca3cae9'
STS_FEDERATION_690_PREVIOUS_ARCHIVE_SHA256 = '733288886fe9cc1ffb823613cb4e35701bcb25d9ddb9664d12546985fd1c0e3e'
STS_FEDERATION_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-sts-federation-source-manifest.json'
STS_FEDERATION_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-sts-federation-catalog.tar.gz'
AMPLIFY_ROLE_690_PREVIOUS_MANIFEST = 'd7b5b4a730dd083dd61bd5cf7e7811347b93e00a884282b0c83574fea0f4596f'
AMPLIFY_ROLE_690_PREVIOUS_TREE = 'aac314c56a9ec863567616f8046c0e007ffc5febd7305b4710c0758ad545160f'
AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE_SHA256 = '027497fb9af5db2481b84160433349234e2b3396fa88e4847678cd301cd43e65'
AMPLIFY_ROLE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-amplify-role-source-manifest.json'
AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-amplify-role-catalog.tar.gz'
EMR_RUNTIME_689_PREVIOUS_MANIFEST = '91c90190da87604f641fc64670f698cfdf4fb8d68b7ecd8a17176bcf2025866f'
EMR_RUNTIME_689_PREVIOUS_TREE = '3b779fee9682b4b10ed7e72be534371528d23007f35ab6a041785e5ca66ed02f'
EMR_RUNTIME_689_PREVIOUS_ARCHIVE_SHA256 = '172462e09fd16c782ebc5ec20eca46a26f21c6aa9be51c2a94dd1cb1ce972262'
EMR_RUNTIME_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-emr-runtime-source-manifest.json'
EMR_RUNTIME_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-emr-runtime-catalog.tar.gz'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST = '093fc183e5cd8f1b97afd29330d06e8aa5c4ce6bcd4a9a01236ab3ff6ac3c936'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE = 'f4a38f3b6628abbb56b900b6a740aa7406be26a95512bce16b42845778b87663'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE_SHA256 = '649bcd860061403ebd63f4b342133179fcdf45db124a19ad212c7284f375da1a'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-elasticbeanstalk-effect-source-manifest.json'
ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-elasticbeanstalk-effect-catalog.tar.gz'
CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST = '7ce57468896503c2d0d674e3588357872b5e9d9e4a182f78471d1b66988f3b47'
CONFIG_REMEDIATION_689_PREVIOUS_TREE = '3847c9b4ef67600aebfcbfaf0d1866faeaea1f4e27a69fc140680906d434fb17'
CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE_SHA256 = 'b56e63f84f09b3cc3623950ba2f665f7ef460d166c32669986d5178d2b3bf330'
CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-config-remediation-source-manifest.json'
CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-config-remediation-catalog.tar.gz'
SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST = '29b74a9633cc0900893ce77dabd373fa53efd6f4b1f58739cc9b2544f9b53d28'
SERVICECATALOG_EFFECT_689_PREVIOUS_TREE = '1311ff4ef2de5f6e0fca5c8fccb108d3ce258d2c0077c8c193c4db9a00b21785'
SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE_SHA256 = '12af6717d5601a0e0ffa7765a15648f7c3c0fe3c0e1cef7f9c9f32a7e6ce4344'
SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-servicecatalog-effect-source-manifest.json'
SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-servicecatalog-effect-catalog.tar.gz'
ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST = '40ed3dbdcf05791488c34fe3c3bae1677f84229e8e1b3d3fd1bc69abe33879c2'
ORG_ACCESS_ROLE_689_PREVIOUS_TREE = '02e8ad7362978074692d08fb861a88b70d24cc0513cf77b275a4395d812131c3'
ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE_SHA256 = '39af0a2ceb978416e25473fdc08a9175fc84d3e6c0b33ffe8073f46b0bbbba0e'
ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-org-access-role-source-manifest.json'
ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-org-access-role-catalog.tar.gz'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST = '357bbbdbb165311268aa808065b43553f1a301bcd8c1ea08caf3ec58a78ee1e9'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE = '2f3970ff928e4ff224581aea739d26fa1d532205db450300151702f17daadea4'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE_SHA256 = '876a304860924d592979155806ef45dc1b24e160f32386bbfce5f5fe543f4d0e'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stepfunctions-passrole-source-manifest.json'
STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stepfunctions-passrole-catalog.tar.gz'
GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST = '0c28d0a2c692ed51aecc805fff445975b885d68f3d26f5c4dd6e9d062cbddbf0'
GAMELIFT_COVERAGE_689_PREVIOUS_TREE = 'a0535402ab3eb2c234cad79a425ebdecabf7eb307f55ac85f7edc3c7dbb6b7b9'
GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256 = '063f2bd25164aed56d660ba54411f719a90d25a930f9e9a1cbb0eff0876d4b15'
GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-coverage-source-manifest.json'
GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-coverage-catalog.tar.gz'
COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST = '87b1606cb1fc9b04eb7a94aba9c211b94f30470f07c6c8f4f2682c5456291812'
COGNITO_IDP_SECRET_689_PREVIOUS_TREE = '0c36966d4b7286cacbdcd71835074acfa161ed6512dc6ff181a5b236157fbb24'
COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE_SHA256 = 'f7a0b692161b10307885b0f0d238cabd25470227c52148668c2ef2088b522416'
COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-cognito-idp-secret-source-manifest.json'
COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-cognito-idp-secret-catalog.tar.gz'
EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST = '198ea2384323076842402c5a41a0609d68bce7796a3ee358e989bc7b2c9b55fc'
EC2_RUNINSTANCES_689_PREVIOUS_TREE = '63df04c3d07b852e079e91acc80ccd8f37ad134eef035981976aa76df12dd559'
EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE_SHA256 = '9eac9d43af09b43bb63c3ed8e4337f038b4a6ac665e1d81be42d51a1e4a53df6'
EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-ec2-runinstances-source-manifest.json'
EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-ec2-runinstances-catalog.tar.gz'
STALE_COVERAGE_689_PREVIOUS_MANIFEST = '2c3da3d187ff9dfa1f5b3ce05a8cb3f90bfa71a877d4a448fe667c894248cd62'
STALE_COVERAGE_689_PREVIOUS_TREE = '74d2b6e516ce9f2d5b6fa13b1a220697c5800d9330c160ac0fdb89b19ea47038'
STALE_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256 = '6dc4fe0177bce9eee480ef65740a1c05c308ca122fb516f1015d687fd532cbfd'
STALE_COVERAGE_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stale-coverage-source-manifest.json'
STALE_COVERAGE_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-stale-coverage-catalog.tar.gz'
FINSPACE_SUNSET_690_PREVIOUS_MANIFEST = '2d85f83a0367d243011a00f1b176bfea9f96464a6518b99db1db8acb592271ca'
FINSPACE_SUNSET_690_PREVIOUS_TREE = '7e8ac01d407a05d8d6babf57eb02b43f3cd28d8906147594dc5e87d81c472992'
FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE_SHA256 = '1b8753caaeb7141ee06ccd62d550bb6dce8223d6d92bb61a7c2d41b4b3f80fdf'
FINSPACE_SUNSET_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-finspace-sunset-source-manifest.json'
FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-finspace-sunset-catalog.tar.gz'
SPOT_REQUEST_690_PREVIOUS_MANIFEST = 'caa32ddb832aae734f3b96f0a9de124802995b23c9f375e72dfde64e5d8ba196'
SPOT_REQUEST_690_PREVIOUS_TREE = '9c1b10cde6cbc0fb180b7b6908bf1d9dc1979942fd253647903d00eb3d9b700e'
SPOT_REQUEST_690_PREVIOUS_ARCHIVE_SHA256 = 'e384f312ff4e88b7a0667b8b2333910febeefb2d84583938d6a557beb3bf2089'
SPOT_REQUEST_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-spot-request-source-manifest.json'
SPOT_REQUEST_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-spot-request-catalog.tar.gz'
TESTSTATE_690_PREVIOUS_MANIFEST = '020ac318f044f346654731db54ce11b7647a88ca45cbfc23dcfaa174578d0e2c'
TESTSTATE_690_PREVIOUS_TREE = '4ec8e1868e9713ce4055f9d0112c183345dcfaff8dfcb491a72e4d1de856aba7'
TESTSTATE_690_PREVIOUS_ARCHIVE_SHA256 = 'c5a0ee00075c139c0a568d67e1968c74613dbe0f63940494398610c4b692ae20'
TESTSTATE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-stepfunctions-teststate-source-manifest.json'
TESTSTATE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-stepfunctions-teststate-catalog.tar.gz'
INSTANCE_CONNECT_690_PREVIOUS_MANIFEST = '57ec5bf9b335c1369f895d8a73d1baa9c633a6f62d47ac7be47d6e598af8bbab'
INSTANCE_CONNECT_690_PREVIOUS_TREE = 'a2fd5dd18c65ea4b80090995c12f87977470457653fd344878d97efa98f11882'
INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE_SHA256 = '6a8a10d0142bce84df55b010fa3a03c53771d220c779221b3d3e84c415b8498c'
INSTANCE_CONNECT_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-instance-connect-source-manifest.json'
INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-instance-connect-catalog.tar.gz'
BRAKET_690_PREVIOUS_MANIFEST = 'f618292a0fd784dfd2d63a979494e31e42ca75873fa2c0ba65518ee6380137c4'
BRAKET_690_PREVIOUS_TREE = '39ad82f667cf13b21cfa83c7af9824bdd0196642e7aee919acdd24ae9d038384'
BRAKET_690_PREVIOUS_ARCHIVE_SHA256 = '41d294d768a69bf55352a12c857f2fa787fe8ec7408ad639cff6cea19e6e1908'
BRAKET_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-braket-device-job-source-manifest.json'
BRAKET_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-braket-device-job-catalog.tar.gz'
CLOUDCONTROL_690_PREVIOUS_MANIFEST = '7f88162ac1519995d3ca2b4f7e4fb20ba8cf094139f3bf11be1a7f87c9964cc0'
CLOUDCONTROL_690_PREVIOUS_TREE = '11bf8b5fe6ca71220bcd892902cefe6661f8e7d858ca541fd57c25637e5e4393'
CLOUDCONTROL_690_PREVIOUS_ARCHIVE_SHA256 = 'e656656a19d2cb82a4e7edd223f6348f621980784a6fefcdbde81a092daa2623'
CLOUDCONTROL_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-cloudcontrol-global-source-manifest.json'
CLOUDCONTROL_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-cloudcontrol-global-catalog.tar.gz'
MWAA_SLR_690_PREVIOUS_MANIFEST = '38eb22ca895b154e26c7fb4e57efac2fd1d7c7f2b93cb15e953fd0dd5494a677'
MWAA_SLR_690_PREVIOUS_TREE = '6a2558eb2f3c33449bbb8a2e81c55caac59394978869706c447f65ebaad8c71f'
MWAA_SLR_690_PREVIOUS_ARCHIVE_SHA256 = '3618eb55592ef3d104fa4d5568b4745a874f4303513a8b26f62aa56ec0b666e3'
MWAA_SLR_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-mwaa-slr-source-manifest.json'
MWAA_SLR_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-mwaa-slr-catalog.tar.gz'
GLUE_SCRIPT_690_PREVIOUS_MANIFEST = '5688e8828d5da6bfe50dc0e7d7ecf57c205ff51a15b0dbfd7c3605e86cf20244'
GLUE_SCRIPT_690_PREVIOUS_TREE = 'e677064371a06be1699166d93a1c4014479584387281b0ada9bf814cce339ab1'
GLUE_SCRIPT_690_PREVIOUS_ARCHIVE_SHA256 = '926f48081c890a43935b2186f49fa4e5696cb421c14e7375e0ccf662471dd337'
GLUE_SCRIPT_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-script-binding-source-manifest.json'
GLUE_SCRIPT_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-script-binding-catalog.tar.gz'
GLUE_690_PREVIOUS_MANIFEST = 'd9aabeaf2ad628290897d7bdd71a3f340c64285fd16c05bba78e419d80b67c1f'
GLUE_690_PREVIOUS_TREE = '41a2882ae0c929b50fc12407a7caefd76ed21644950a1a8131a79da8420bb3db'
GLUE_690_PREVIOUS_ARCHIVE_SHA256 = 'b799ec4aa3d3cc9cf35e738616586696d168b919f972afeec5d1f39151d40fb2'
GLUE_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-dev-endpoint-source-manifest.json'
GLUE_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-glue-dev-endpoint-catalog.tar.gz'
DEVICEFARM_690_PREVIOUS_MANIFEST = 'd7605097dbcd5220cad0aecd2bbf4b2b08b839a442fed67644ba9161782556fd'
DEVICEFARM_690_PREVIOUS_TREE = 'a5b712f658ccaed3b962839c3e7e634652db05f5f297def720002f3e65a72ea7'
DEVICEFARM_690_PREVIOUS_ARCHIVE_SHA256 = '7c0c2fdc3890e3c1c460e4084fe175bfe80f8aeec408096a7ffa89a2e1531d3a'
DEVICEFARM_690_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-devicefarm-source-manifest.json'
DEVICEFARM_690_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-690-devicefarm-catalog.tar.gz'
IOT_EXISTING_689_PREVIOUS_MANIFEST = 'e8f57144d46d8135eb9f474e143f418263d00d2f38f1cc4a9b4130a42577e85f'
IOT_EXISTING_689_PREVIOUS_TREE = '642f2ed5b4dd647f616650e8ea182f2b666b56239843d5561ad8475e32296ed8'
IOT_EXISTING_689_PREVIOUS_ARCHIVE_SHA256 = '33a68002171d9530e7cef98c1dac0c2be6f7404ae66906579655efef81bcc7f6'
IOT_EXISTING_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-iot-existing-alias-source-manifest.json'
IOT_EXISTING_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-iot-existing-alias-catalog.tar.gz'
GAMELIFT_SHELL_689_PREVIOUS_MANIFEST = '96af62443eb91ef5f191e53431a1c454d6c01a9227990296b975859304061e38'
GAMELIFT_SHELL_689_PREVIOUS_TREE = 'ea0f81124392a2b3c1497fcbd84f5f10e29b0f7233faa98b9e3f55040d46b787'
GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE_SHA256 = '7c203f81019b1c73ec8cccf185aa122c3f092aef57dcf987fdb586eb4b243100'
GAMELIFT_SHELL_689_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-shell-source-manifest.json'
GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-689-gamelift-shell-catalog.tar.gz'
GAMELIFT_SHARED_688_PREVIOUS_MANIFEST = '4f7aad5ed3fac85e64cf6a48b1c3dedd8d437716841b4c0542de5ffce7ff416b'
GAMELIFT_SHARED_688_PREVIOUS_TREE = '2932696952ff3d375e67011d9d390f44a47bda268dd3715f4a18e96e784ebaf9'
GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE_SHA256 = '46371c73bf402bdadddc8a2d3e7890bf0d15bd0536488e982ba050f30cda150e'
GAMELIFT_SHARED_688_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-688-quicksight-source-manifest.json'
GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-688-quicksight-catalog.tar.gz'
SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST = '2bbb1711fccc2d4de32e9f80f30a44b5fa90eea3c40233da917217222897790f'
SCHEDULER_UPDATE_687_PREVIOUS_TREE = '7ecbbce66663c7cafab4d2ff70b75e56fb4048d854f0a0b039fcb321e1b1c2bb'
SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE_SHA256 = '1aeb24e40c36b96d529d620dd60a6e51307a7556935c599e14a8443c4a455b14'
SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-687-scheduler-update-source-manifest.json'
SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-687-scheduler-update-catalog.tar.gz'
SCHEDULER_CREATE_686_PREVIOUS_MANIFEST = 'e1ba0fb3b429fc2bb9ce6dc1c9d307969d3b70cd3b62d3823f4e5fe3711aa976'
SCHEDULER_CREATE_686_PREVIOUS_TREE = '853549b616c06803bba97771b9d14d1cbca9459f1d750fc9f40a0df83ecf0bc3'
SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE_SHA256 = 'd1e84bdcc4d0c54dbaffbddaaab4db987a46a979f80c05d4ed924a65655d203a'
SCHEDULER_CREATE_686_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-scheduler-create-source-manifest.json'
SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-scheduler-create-catalog.tar.gz'
DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST = '296e1b6e6d8359d486cbba8d9a250fc4b2f430bd0d06b98ff31fdf3243fdd360'
DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE = '3d231c0ab1f30796668b2d12e2de29e9a5357ae4f8e810462e4843814ab1c199'
DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE_SHA256 = '2b152b5e753a25243ff73a2ba2a7f22b6c5848224fe42c14ed5ea2dac69cc32f'
DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-deadline-worker-dependencies-source-manifest.json'
DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-686-deadline-worker-dependencies-catalog.tar.gz'
DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST = 'e616da28305d487c70d65f238bfe725e0a69e8eaadba108249b28cdca0bd03a9'
DEADLINE_NEW_WORKER_685_PREVIOUS_TREE = '65314cd326eca8023b58b7ecaf1d143ffe1167cbe6c3025858484cc2a8dbd245'
DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE_SHA256 = 'a4a528b725a6d2a8d8c50a5dfab19b76f945ec115dfa2bf679398d1778cbf539'
DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-685-deadline-new-worker-source-manifest.json'
DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-685-deadline-new-worker-catalog.tar.gz'
DEADLINE_WORKER_684_PREVIOUS_MANIFEST = '8f1a9abe937cc74f499cc1dc6316544a37f37967cd4f4c254f80ad269fb4e60d'
DEADLINE_WORKER_684_PREVIOUS_TREE = 'd9bcd120bf3d79acde0e2520e0056a3d77b30988d5201be874e3ccc930293a8b'
DEADLINE_WORKER_684_PREVIOUS_ARCHIVE_SHA256 = '1ed684664f996a36a05b8c88aea17e55133e6df60af8b54b0d7e8d5ebd8684f3'
DEADLINE_WORKER_684_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-existing-worker-source-manifest.json'
DEADLINE_WORKER_684_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-existing-worker-catalog.tar.gz'
DEADLINE_FLEET_684_PREVIOUS_MANIFEST = 'af62253634cee8f664d4fe5d7e25133734a363cd8c917f6e74bdadc3ecb71732'
DEADLINE_FLEET_684_PREVIOUS_TREE = 'ca26d6b56ae3848b61da6ba96ab413616223877caa5973be1f00e4b0d2f3c95b'
DEADLINE_FLEET_684_PREVIOUS_ARCHIVE_SHA256 = 'e3ce247d4403235280743256dc19d890f4c8dad6d96199cc6c3bf7cc551b6d88'
DEADLINE_FLEET_684_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-fleet-scope-source-manifest.json'
DEADLINE_FLEET_684_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-684-deadline-fleet-scope-catalog.tar.gz'
DEADLINE_QUEUE_683_PREVIOUS_MANIFEST = '51881e49473f48dac6fa4b1a724dcdf2bd08fe6d6ae9b7d1833c127999298365'
DEADLINE_QUEUE_683_PREVIOUS_TREE = '73524d94236f143acfa52452e22c28e37111f997ec8ed841fa218846ce4a88fd'
DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE_SHA256 = '83134ca0fb63e6b30aa52f8d3776be8fbfcef56a61e6376c5d78d7549881a68e'
DEADLINE_QUEUE_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-deadline-queue-source-manifest.json'
DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-deadline-queue-catalog.tar.gz'
CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST = '473c03db5521c972b4eabbd478955243825d55055a834b336786f4415f1a235e'
CLOUDFRONT_CREATE_683_PREVIOUS_TREE = '9b57effb04904ecbeb32ce792ed3668b4ea1fb645b8ca6790ec73a572a4475c3'
CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE_SHA256 = '12100524ae96a118b67541532819b3ccf0a40d1144a95bdda89dcf8fc30711a0'
CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cloudfront-create-source-manifest.json'
CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cloudfront-create-catalog.tar.gz'
COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST = '70f2970c1744af66851bbe87dfa372a18aa908c89f5f61d7072b8313918f64c6'
COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE = '781cd6f1481e00cc34086fbcaa4f2bd6147beaad623762725fda6c1ddc2445da'
COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE_SHA256 = 'c6d1b8bcd9f2587a4d309f96debd1ad0be92f772abbc2057582ade5bd82979ae'
COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cognito-guest-existing-source-manifest.json'
COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-683-cognito-guest-existing-catalog.tar.gz'
COGNITO_GUEST_682_PREVIOUS_MANIFEST = '070ffca432c04525fd59598b50b38e3dace8e7f1f9eaad60f8851fc4ee68fe1e'
COGNITO_GUEST_682_PREVIOUS_TREE = '86de91111e926806ad603078a88e1becd5ffc53f50b7323bb9fa0e5ccfa2114b'
COGNITO_GUEST_682_PREVIOUS_ARCHIVE_SHA256 = '12f90b298900206937bc7c01fbfc2962d495fcb2b2c3975e5f6c45a060c3b82c'
COGNITO_GUEST_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-cognito-guest-classic-source-manifest.json'
COGNITO_GUEST_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-cognito-guest-classic-catalog.tar.gz'
SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST = '1e3da74d7edbd1490aeafccfa650e7e01a7a71163d5aa959b8e6f9244949ebd9'
SAGEMAKER_ATTACH_682_PREVIOUS_TREE = 'dd09ade57ea0a886c7a37963c60b1f7badfbbb6bbf65bd9abf3f737dfe7c3a07'
SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE_SHA256 = 'd1dd9259a4cbd1383a916e80235d74be26929f604fe8dbc3caf579aeeee02d25'
SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-sagemaker-attach-source-manifest.json'
SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-sagemaker-attach-catalog.tar.gz'
GAMELIFT_GROUP_682_PREVIOUS_MANIFEST = '028d895b523eb128696dbcdc0f866bb180c2f3c733f44337fa52fbd64a1b4e15'
GAMELIFT_GROUP_682_PREVIOUS_TREE = '39e933196b904e1af7b4fe2b10544317de91a5c2e0e6ea07df268e5bc0e7ca4e'
GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE_SHA256 = '9176b3e00232b0d76d6c7a3e3ac956b3242c4164b9f3fe9ee8306e0173c52c8a'
GAMELIFT_GROUP_682_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-gamelift-group-source-manifest.json'
GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-682-gamelift-group-catalog.tar.gz'
SAGEMAKER_LCC_677_PREVIOUS_MANIFEST = '22ecf1eb87abe05bdab76bcdc3756f63a042c225ca55f7e7f0402fa2f77f2a81'
SAGEMAKER_LCC_677_PREVIOUS_TREE = 'a969be051deaead368da7bfc18836720adc16ba39dff047971d52b84233218e6'
SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE_SHA256 = '666314d8973313ff2aa50fae1c87911f2fbb4805bcfd157102ef5b93456ae4f2'
SAGEMAKER_LCC_677_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-677-sagemaker-lcc-source-manifest.json'
SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-677-sagemaker-lcc-catalog.tar.gz'
SAGEMAKER_LCC_PREVIOUS_MANIFEST = 'd50f94c14b997e98e7109eb5a38831243eb164498ff5872c680288caf0b44f5d'
SAGEMAKER_LCC_PREVIOUS_TREE = '84537823c63b438f9e41d7e7b115a3ef46dd6c85383b99122d1b6ed6a1aef508'
SAGEMAKER_LCC_PREVIOUS_ENTRY_COUNT = 676
SAGEMAKER_LCC_PREVIOUS_EXCLUDED_COUNT = 3723
SAGEMAKER_LCC_PREVIOUS_ARCHIVE_SHA256 = 'acbb2f78a8f4fd489218e0dad20b2774f84cf91afe40babb8ab4d40fd9f68793'
SAGEMAKER_LCC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-676-sagemaker-lcc-source-manifest.json'
SAGEMAKER_LCC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-676-sagemaker-lcc-catalog.tar.gz'
SSM_HYBRID_PREVIOUS_MANIFEST = '767604c8fd7bb41e51177886371eb3c33f31d698a21586bc5b230364271d9d18'
SSM_HYBRID_PREVIOUS_TREE = '5677fb5e5aced10aaed8cf84e51d42f7813f7d213f72e89e3956558616d5cb71'
SSM_HYBRID_PREVIOUS_ENTRY_COUNT = 674
SSM_HYBRID_PREVIOUS_EXCLUDED_COUNT = 3723
SSM_HYBRID_PREVIOUS_ARCHIVE_SHA256 = '103d422dedb73776703f8d33e3c7278b0c01c6b35160e2ac23d1818173421a9b'
SSM_HYBRID_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-674-ssm-hybrid-source-manifest.json'
SSM_HYBRID_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-674-ssm-hybrid-catalog.tar.gz'
MWAA_DAG_PREVIOUS_MANIFEST = 'ead398e038dec38299179fe6dcadbaaa1125bafa85617e8ba738320d46d99e0c'
MWAA_DAG_PREVIOUS_TREE = '68e7b2982721974b183936f2fe6612b1cae983ddf2088010f3167bd6a7c540a6'
MWAA_DAG_PREVIOUS_ENTRY_COUNT = 673
MWAA_DAG_PREVIOUS_EXCLUDED_COUNT = 3723
MWAA_DAG_PREVIOUS_ARCHIVE_SHA256 = '5fde181a76164521079837f7ec4ba12ed9d83b2147bd0f56c4529fde3251e8a8'
MWAA_DAG_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-mwaa-dag-source-manifest.json'
MWAA_DAG_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-mwaa-dag-catalog.tar.gz'
IMAGEBUILDER_PREVIOUS_MANIFEST = '806df7e9e167327f94546f21aef691ead74b27aac1807278ac0500ab031ce5dd'
IMAGEBUILDER_PREVIOUS_TREE = '25f7f17354a44d519da70a2b0b7dc9ee8bc7cc7190325fc457d96978cc07881b'
IMAGEBUILDER_PREVIOUS_ENTRY_COUNT = 673
IMAGEBUILDER_PREVIOUS_EXCLUDED_COUNT = 3723
IMAGEBUILDER_PREVIOUS_ARCHIVE_SHA256 = '33ba00ab6f5240658907c8a2c04c8fb45dcf9d7df261214fe01f4de783b7dd26'
IMAGEBUILDER_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-imagebuilder-source-manifest.json'
IMAGEBUILDER_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-673-imagebuilder-catalog.tar.gz'
GLUE_SCRIPT_PREVIOUS_MANIFEST = '78c82d0bffa7d95e75fcd66c798cd7b3d5423f328b632731f62c61cd5c02db5e'
GLUE_SCRIPT_PREVIOUS_TREE = '05938ad2b8b18f72f55be44a2b420eab322e0e744198e9e14f4b40a61e4b52e6'
GLUE_SCRIPT_PREVIOUS_ENTRY_COUNT = 672
GLUE_SCRIPT_PREVIOUS_EXCLUDED_COUNT = 3723
GLUE_SCRIPT_PREVIOUS_ARCHIVE_SHA256 = 'eb58c2e2349910946a399264ebc60a80e7ada3ee2b5d5e2d53a4cd41f72d5afb'
GLUE_SCRIPT_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-glue-script-source-manifest.json'
GLUE_SCRIPT_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-glue-script-catalog.tar.gz'
ECSCAPE_PREVIOUS_MANIFEST = '9c316dfc3f48451080f3d92579fb9428bdd4963cdd2a6a6eb4ab76eaeb8f1dc3'
ECSCAPE_PREVIOUS_TREE = '6fef6e9cbdd398932c52f43f98d2f4323fe81c0506ec3f6bfd30cb51594138dc'
ECSCAPE_PREVIOUS_ENTRY_COUNT = 672
ECSCAPE_PREVIOUS_EXCLUDED_COUNT = 3723
ECSCAPE_PREVIOUS_ARCHIVE_SHA256 = '9edc25d69c607dc5f7e97ed768aa7b3a21296ce488a95a0cd6d61e84d24bdb91'
ECSCAPE_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-ecscape-source-manifest.json'
ECSCAPE_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-672-ecscape-catalog.tar.gz'
ENABLE_CLASSIC_PREVIOUS_MANIFEST = '563a6cdc997965f2bb4c277293a077d4d54756bb3c4d2bd6079abf9ed3ec6e3b'
ENABLE_CLASSIC_PREVIOUS_TREE = '034912fcdf1fee642a14d2d8269778b7ba1a51d5adb48db547e88da4005da425'
ENABLE_CLASSIC_PREVIOUS_ENTRY_COUNT = 671
ENABLE_CLASSIC_PREVIOUS_EXCLUDED_COUNT = 3723
ENABLE_CLASSIC_PREVIOUS_ARCHIVE_SHA256 = '066a64c76b33ca6b9222526e0f880198001baa200315faa918db52747d02bbbf'
ENABLE_CLASSIC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-671-cognito-enable-classic-source-manifest.json'
ENABLE_CLASSIC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-671-cognito-enable-classic-catalog.tar.gz'
SETROLES_PREVIOUS_MANIFEST = '9101d6942f7cb64270b0593849623d3bc2f591a961ca48a60158bb59abf620d0'
SETROLES_PREVIOUS_TREE = '8cf68cd6be9d5ead8210d5333ee813a2829ce086cf141a4a3d601b657609fd81'
SETROLES_PREVIOUS_ENTRY_COUNT = 670
SETROLES_PREVIOUS_EXCLUDED_COUNT = 3723
SETROLES_PREVIOUS_ARCHIVE_SHA256 = '6c599495006c19b0781150323151f959cea481b4e813a065897248d78fd7928f'
SETROLES_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-670-cognito-setroles-source-manifest.json'
SETROLES_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-670-cognito-setroles-catalog.tar.gz'
CLASSIC_PREVIOUS_MANIFEST = '9f9d526ff17571b7fd3c8610e9ca5c01aa9ea22f6654065659a1bcfd718a49d2'
CLASSIC_PREVIOUS_TREE = '9f077698a417165440cbd9bd9404cc007ad793c6bc5c09347191cd173c5611a5'
CLASSIC_PREVIOUS_ENTRY_COUNT = 669
CLASSIC_PREVIOUS_EXCLUDED_COUNT = 3723
CLASSIC_PREVIOUS_ARCHIVE_SHA256 = 'f868234cb65a87d552da35768276aab8cf3d2de0f85bb583d60d5adf895e8096'
CLASSIC_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-669-cognito-classic-source-manifest.json'
CLASSIC_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-669-cognito-classic-catalog.tar.gz'
COGNITO_PREVIOUS_MANIFEST = 'fa98e52c3a7b0778d45750885e62c1f08a0b08c68b2a2fe405d407ca24bf8d83'
COGNITO_PREVIOUS_TREE = '92585138ea667380fdd66d6cf2c03c46f080034aa8904975fc0ec82feda14a9d'
COGNITO_PREVIOUS_ENTRY_COUNT = 668
COGNITO_PREVIOUS_EXCLUDED_COUNT = 3724
COGNITO_PREVIOUS_ARCHIVE_SHA256 = '57bd1634f4787a387d9711fc2d09119ed2f956a6ed5d85e235f22cab03d94a0d'
COGNITO_PREVIOUS_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-668-cognito-source-manifest.json'
COGNITO_PREVIOUS_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-668-cognito-catalog.tar.gz'
GAMELIFT_CURRENT_MANIFEST = '37a6cc93d703b54c1bbf58e346ab0c855bbec910dee9611ee77511928699e7fe'
GAMELIFT_CURRENT_TREE = '4e029c42de100f8d63ace40173ce4b9e894a5f12bb42f470831a8745b4950399'
GAMELIFT_CURRENT_ENTRY_COUNT = 667
GAMELIFT_CURRENT_EXCLUDED_COUNT = 3725
GAMELIFT_CURRENT_ARCHIVE_SHA256 = 'f16d34175f0dca5d92d316fc2f5d4eaf6506a11fdb0a92dfdcf31e828b32d0af'
GAMELIFT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-gamelift-source-manifest.json'
GAMELIFT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-gamelift-catalog.tar.gz'
IOT_V2_CURRENT_MANIFEST = 'b34c5215e969f886c4b286c3d33afd62f3364d5b58dce96a8393d8ef79465090'
IOT_V2_CURRENT_TREE = '98e3a4ac18955dec5670e267f03b8f942bfadf01d5cb483d94a928e4229b4428'
IOT_V2_CURRENT_ENTRY_COUNT = 667
IOT_V2_CURRENT_EXCLUDED_COUNT = 3725
IOT_V2_CURRENT_ARCHIVE_SHA256 = '8c52a13e77b13013342d9f70acbc2e8b3cd6a339d15d421ab86090f23455605f'
IOT_V2_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v2-source-manifest.json'
IOT_V2_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v2-catalog.tar.gz'
IOT_V1_CURRENT_MANIFEST = 'd0b9a70385686e426173bb33f5ceced688eef8b145863f06bd656e9872e6087b'
IOT_V1_CURRENT_TREE = 'ec6fd3f2a2f745ccb28bbac553ca280604f43607754da2364f0602c78ffed964'
IOT_V1_CURRENT_ENTRY_COUNT = 667
IOT_V1_CURRENT_EXCLUDED_COUNT = 3725
IOT_V1_CURRENT_ARCHIVE_SHA256 = '0927784c95eb72590096dd56fae5b290c7866feb13ba29893b590f332767aafd'
IOT_V1_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v1-source-manifest.json'
IOT_V1_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-iot-v1-catalog.tar.gz'
IOT_CURRENT_MANIFEST = 'c154e1c71f1351f02f99477babae646760c491ca1039b8ba51a9508076a9cc08'
IOT_CURRENT_TREE = 'b68a44ccadaf04a9efccf624d4cf7ce2c3c5e9c4b099357dec05b66f59b46efa'
IOT_CURRENT_ENTRY_COUNT = 667
IOT_CURRENT_EXCLUDED_COUNT = 3725
IOT_CURRENT_ARCHIVE_SHA256 = '9cfa0520e58d5ddee3f45161e934e5b849ab82881c06bf2962325611452925a8'
IOT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-source-manifest.json'
IOT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-667-catalog.tar.gz'
APPRUNNER_CURRENT_MANIFEST = '6fbd47a393f3377664859a479c46ca53192305096c5cf8366a249854c406f654'
APPRUNNER_CURRENT_TREE = '3043d253ecdb229018b0d0a71326a136d1f8d7af669933a22a65d9affc84a7d4'
APPRUNNER_CURRENT_ENTRY_COUNT = 666
APPRUNNER_CURRENT_EXCLUDED_COUNT = 3725
APPRUNNER_CURRENT_ARCHIVE_SHA256 = 'd42fd391ed8bdddc61960c0613af6ce598847c78c560c6aa352b18dda6d405e8'
APPRUNNER_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-666-source-manifest.json'
APPRUNNER_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-666-catalog.tar.gz'
BATCH_CURRENT_MANIFEST = 'a295871d623b8091fe0d3c1536293784ec93ec12db1914ae3707134e7840e6a2'
BATCH_CURRENT_TREE = '79a6945cd533dc781d668c234a59029476948af84d2b4af7198a8c1b10543cd9'
BATCH_CURRENT_ENTRY_COUNT = 665
BATCH_CURRENT_EXCLUDED_COUNT = 3726
BATCH_CURRENT_ARCHIVE_SHA256 = 'bc49a17111242283be708b591eeb95c53f9be60a23f8ff23952ad0476dfc835e'
BATCH_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-665-source-manifest.json'
BATCH_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-665-catalog.tar.gz'
ATHENA_CURRENT_MANIFEST = '9376370a8e63fefb6853e4e07ff750eb91d6aa66450e2eea3e9346930a1092f1'
ATHENA_CURRENT_TREE = '6aed4798e9eb1ba63eea1a1b4cace68122b1c13f0cd64e52d849951191f51343'
ATHENA_CURRENT_ENTRY_COUNT = 664
ATHENA_CURRENT_EXCLUDED_COUNT = 3727
ATHENA_CURRENT_ARCHIVE_SHA256 = '996bfe08a042b7000758250688faca0a1f8dfc4ba0bb43923977547ec2758baa'
ATHENA_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-664-source-manifest.json'
ATHENA_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-664-catalog.tar.gz'
RECENT_CURRENT_MANIFEST = '206b1895056780d15c6707bb434e46a25df4d53bf6c284e8bbb6d7d567a46806'
RECENT_CURRENT_TREE = 'd3dbaf40848dd14c4c2d199c8f7ec81126724f8311e23f9579282c02026c4f2f'
RECENT_CURRENT_ENTRY_COUNT = 661
RECENT_CURRENT_EXCLUDED_COUNT = 3730
RECENT_CURRENT_ARCHIVE_SHA256 = '96e4a5344ab18a45a41ddc1be280d816afe4356a675f9d11ae5871e64b5df484'
RECENT_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-661-source-manifest.json'
RECENT_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-661-catalog.tar.gz'
INTERMEDIATE_CURRENT_MANIFEST = 'eada56c3fbbbf06891601ef0711e3b2d2f216cdf8981e5e87e9501f7702ef868'
INTERMEDIATE_CURRENT_TREE = '9cace7c01a6cc13e22b369c99298cc0a4f6df6226aa13a7b63cfb6a4d1ad29e9'
INTERMEDIATE_CURRENT_ENTRY_COUNT = 660
INTERMEDIATE_CURRENT_EXCLUDED_COUNT = 3731
INTERMEDIATE_CURRENT_ARCHIVE_SHA256 = '24ef5805dc374d0b9163abe241dd86bf5edfb05e9e8746241bfab253e19634dd'
INTERMEDIATE_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-source-manifest.json'
INTERMEDIATE_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-660-catalog.tar.gz'
PREVIOUS_CURRENT_MANIFEST = '6d994be99fd3fd696c05dd0a352c0cb348da2dc62648e7caf99f03a113162f18'
PREVIOUS_CURRENT_TREE = '163c469428477120a0b2ff7aa9af4f0dfc82fb8dcf339165ddbae4d32f00914d'
PREVIOUS_CURRENT_ENTRY_COUNT = 633
PREVIOUS_CURRENT_EXCLUDED_COUNT = 3515
PREVIOUS_CURRENT_ARCHIVE_SHA256 = 'fad4c89765aa466f27831b6992a7e79059c28a118ee3707496a0e944b6335826'
PREVIOUS_CURRENT_MANIFEST_PATH = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-source-manifest.json'
PREVIOUS_CURRENT_ARCHIVE = Path(__file__).resolve().parent / 'catalog_versions/prior-bulk-633-catalog.tar.gz'
PRIOR_CURRENT_MANIFEST = "eb459bc440cdad814f3acde244a36fa7f546119a351d5ce720ef0cd2281835bf"
PRIOR_DISCLOSURE_MANIFEST = "91ffe7389d02568cdcdf74a6b08dafa5f665ea07c0c528988127ffc4d2a86c45"
PRIOR_DISCLOSURE_TREE = "5091464bedcb10bb87301695ca733276dc67b865e544c408ccf72a5408176f0f"
PRIOR_DISCLOSURE_HISTORY = Path(__file__).resolve().parent / "catalog_versions/disclosure-v7-manifest.json"
CURRENT_TREE = 'a57ad15997ffacee374dac42b8325cc9fcd9f99526f8e1b200112aff39be686e'
PRIOR_CURRENT_TREE = "99207e6469fc5e5b3daf21324e6860599b116ffcf7d30600643bd229b0f11494"
CURRENT_ENTRY_COUNT = 691
CURRENT_EXCLUDED_COUNT = 3737
CURRENT_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bulk-principal-v6-manifest.json"
PRIOR_CATALOG_ARCHIVE = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-catalog-20261016.tar.gz"
PRIOR_SOURCE_MANIFEST = Path(__file__).resolve().parent / "catalog_versions/prior-disclosure-source-manifest.json"
PRIOR_BOUNDED_MANIFEST = "082451e81fa450830ae5f6835e241dd412a6c30a8b2a0b1172cdbc89b2d71429"
PRIOR_BOUNDED_TREE = "695e38b0bc93df9ba031828ffefbabe8e10b60741580554a5f36b8f37aa05414"
BOUNDED_HISTORY = Path(__file__).resolve().parent / "catalog_versions/bounded-v5-manifest.json"
V4_HISTORY = Path(__file__).resolve().parent / "catalog_versions/principal-v4-manifest.json"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _paths(catalog_dir=None, manifest_path=None, history_path=None):
    catalog_dir = Path(catalog_dir or CATALOG_DIR)
    manifest_path = Path(manifest_path or catalog_dir.parents[2] / "risk_rules/hacktricks-privesc-source.json")
    history_path = Path(history_path or LEGACY_DELTA)
    return catalog_dir, manifest_path, history_path


@lru_cache(maxsize=4)
def _verified_current(catalog_dir, manifest_path):
    root, manifest_path = Path(catalog_dir), Path(manifest_path)
    if _sha(manifest_path) != CURRENT_MANIFEST:
        raise ValueError("v4_catalog_manifest_mismatch")
    manifest = json.loads(manifest_path.read_text())
    wanted = manifest.get("sha256")
    actual = {str(path.relative_to(root)): _sha(path) for path in root.rglob("*.yaml")}
    if not isinstance(wanted, dict) or actual != wanted:
        raise ValueError("v4_catalog_file_mismatch")
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    if hashlib.sha256(tree.encode()).hexdigest() != CURRENT_TREE:
        raise ValueError("v4_catalog_tree_mismatch")
    loaded = load_catalog(root, strict=True)
    if len(loaded["entries"]) != CURRENT_ENTRY_COUNT or loaded["excluded"] != CURRENT_EXCLUDED_COUNT:
        raise ValueError("v4_catalog_counts_mismatch")
    return {entry["id"]: entry for entry in loaded["entries"]}


@lru_cache(maxsize=1)
def _verified_previous_current():
    """Keep the exact 633-entry catalog used by already stored report cards."""
    return _verified_archived_current(
        PREVIOUS_CURRENT_MANIFEST_PATH, PREVIOUS_CURRENT_ARCHIVE,
        PREVIOUS_CURRENT_MANIFEST, PREVIOUS_CURRENT_ARCHIVE_SHA256,
        PREVIOUS_CURRENT_TREE, PREVIOUS_CURRENT_ENTRY_COUNT, PREVIOUS_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_gamelift_group_682_previous():
    """Keep the exact 682-entry catalog before the active-group condition."""
    return _verified_archived_current(
        GAMELIFT_GROUP_682_PREVIOUS_MANIFEST_PATH, GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE,
        GAMELIFT_GROUP_682_PREVIOUS_MANIFEST, GAMELIFT_GROUP_682_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_GROUP_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_cognito_guest_682_previous():
    """Keep the exact catalog before the Cognito guest Basic-flow route."""
    return _verified_archived_current(
        COGNITO_GUEST_682_PREVIOUS_MANIFEST_PATH, COGNITO_GUEST_682_PREVIOUS_ARCHIVE,
        COGNITO_GUEST_682_PREVIOUS_MANIFEST, COGNITO_GUEST_682_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_GUEST_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_scheduler_update_687_previous():
    """Keep the exact 687-entry catalog before QuickSight self-promotion."""
    return _verified_archived_current(
        SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST_PATH, SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE,
        SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST, SCHEDULER_UPDATE_687_PREVIOUS_ARCHIVE_SHA256,
        SCHEDULER_UPDATE_687_PREVIOUS_TREE, 687, 3723)


@lru_cache(maxsize=1)
def _verified_gamelift_shared_688_previous():
    """Keep the exact 688-entry catalog before the GameLift shell route."""
    return _verified_archived_current(
        GAMELIFT_SHARED_688_PREVIOUS_MANIFEST_PATH, GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE,
        GAMELIFT_SHARED_688_PREVIOUS_MANIFEST, GAMELIFT_SHARED_688_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_SHARED_688_PREVIOUS_TREE, 688, 3723)


@lru_cache(maxsize=1)
def _verified_cloudcontrol_690_previous():
    """Keep the exact catalog before Cloud Control's global action correction."""
    return _verified_archived_current(
        CLOUDCONTROL_690_PREVIOUS_MANIFEST_PATH, CLOUDCONTROL_690_PREVIOUS_ARCHIVE,
        CLOUDCONTROL_690_PREVIOUS_MANIFEST, CLOUDCONTROL_690_PREVIOUS_ARCHIVE_SHA256,
        CLOUDCONTROL_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_braket_690_previous():
    """Keep the exact catalog before Braket's device and job resource correction."""
    return _verified_archived_current(
        BRAKET_690_PREVIOUS_MANIFEST_PATH, BRAKET_690_PREVIOUS_ARCHIVE,
        BRAKET_690_PREVIOUS_MANIFEST, BRAKET_690_PREVIOUS_ARCHIVE_SHA256,
        BRAKET_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_instance_connect_690_previous():
    """Keep the exact catalog before host access became unresolved."""
    return _verified_archived_current(
        INSTANCE_CONNECT_690_PREVIOUS_MANIFEST_PATH, INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE,
        INSTANCE_CONNECT_690_PREVIOUS_MANIFEST, INSTANCE_CONNECT_690_PREVIOUS_ARCHIVE_SHA256,
        INSTANCE_CONNECT_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_teststate_690_previous():
    """Keep the exact catalog before TestState role reach became unresolved."""
    return _verified_archived_current(
        TESTSTATE_690_PREVIOUS_MANIFEST_PATH, TESTSTATE_690_PREVIOUS_ARCHIVE,
        TESTSTATE_690_PREVIOUS_MANIFEST, TESTSTATE_690_PREVIOUS_ARCHIVE_SHA256,
        TESTSTATE_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_bedrock_actiongroup_effect_691_previous():
    """Keep the exact catalog before Bedrock action groups required observed execution."""
    return _verified_archived_current(
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST_PATH,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_agentcore_harness_effect_691_previous():
    """Keep the exact catalog before AgentCore harness commands required evidence."""
    return _verified_archived_current(
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE,
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST, AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_agentcore_runtime_effects_691_previous():
    """Keep the exact catalog before AgentCore runtime effects required evidence."""
    return _verified_archived_current(
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE,
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST, AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_amplify_role_effects_691_previous():
    """Keep the exact catalog before Amplify role effects required observed operations."""
    return _verified_archived_current(
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST_PATH, AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE,
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST, AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_stackset_effects_691_previous():
    """Keep the exact catalog before StackSet effects required reviewed evidence."""
    return _verified_archived_current(
        CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST_PATH, CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE,
        CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST, CFN_STACKSET_EFFECTS_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_extension_effect_691_previous():
    """Keep the exact catalog before private extension handler effects were witnessed."""
    return _verified_archived_current(
        CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST_PATH, CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE,
        CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST, CFN_EXTENSION_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_cfn_template_effect_691_previous():
    """Keep the exact catalog before CloudFormation required witnessed role effects."""
    return _verified_archived_current(
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST_PATH, CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE,
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST, CFN_TEMPLATE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_teststate_role_effect_691_previous():
    """Keep the exact catalog before TestState accepted a reviewed role operation."""
    return _verified_archived_current(
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH, TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE,
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST, TESTSTATE_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_sfn_role_effect_691_previous():
    """Keep the exact catalog before Step Functions role effects required reviewed execution."""
    return _verified_archived_current(
        SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST_PATH, SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE,
        SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST, SFN_ROLE_EFFECT_691_PREVIOUS_ARCHIVE_SHA256,
        SFN_ROLE_EFFECT_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_instance_connect_witness_691_previous():
    """Keep the exact catalog before Instance Connect accepted a bounded host witness."""
    return _verified_archived_current(
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST_PATH,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_ARCHIVE_SHA256,
        INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_taskset_691_previous():
    """Keep the exact catalog before task-set escalation was bound to one service."""
    return _verified_archived_current(
        ECS_TASKSET_691_PREVIOUS_MANIFEST_PATH, ECS_TASKSET_691_PREVIOUS_ARCHIVE,
        ECS_TASKSET_691_PREVIOUS_MANIFEST, ECS_TASKSET_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_TASKSET_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_node_escape_691_previous():
    """Keep the exact catalog before privileged task escape was bound to one host."""
    return _verified_archived_current(
        ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST_PATH, ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE,
        ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST, ECS_NODE_ESCAPE_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_NODE_ESCAPE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_service_691_previous():
    """Keep the exact catalog before ECS service deployment was bound to a concrete cluster."""
    return _verified_archived_current(
        ECS_SERVICE_691_PREVIOUS_MANIFEST_PATH, ECS_SERVICE_691_PREVIOUS_ARCHIVE,
        ECS_SERVICE_691_PREVIOUS_MANIFEST, ECS_SERVICE_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_SERVICE_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_start_task_691_previous():
    """Keep the exact catalog before ECS StartTask was bound to a connected host."""
    return _verified_archived_current(
        ECS_START_TASK_691_PREVIOUS_MANIFEST_PATH, ECS_START_TASK_691_PREVIOUS_ARCHIVE,
        ECS_START_TASK_691_PREVIOUS_MANIFEST, ECS_START_TASK_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_START_TASK_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_ecs_new_task_691_previous():
    """Keep the exact catalog before the new ECS task launch was bound to a live cluster."""
    return _verified_archived_current(
        ECS_NEW_TASK_691_PREVIOUS_MANIFEST_PATH, ECS_NEW_TASK_691_PREVIOUS_ARCHIVE,
        ECS_NEW_TASK_691_PREVIOUS_MANIFEST, ECS_NEW_TASK_691_PREVIOUS_ARCHIVE_SHA256,
        ECS_NEW_TASK_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_organizations_rcp_691_previous():
    """Keep the exact catalog before the Organizations root SCP and target RCP wording."""
    return _verified_archived_current(
        ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST_PATH,
        ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE,
        ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST,
        ORGANIZATIONS_RCP_691_PREVIOUS_ARCHIVE_SHA256,
        ORGANIZATIONS_RCP_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_lambda_signer_691_previous():
    """Keep the exact catalog before signing-profile and artifact join requirements."""
    return _verified_archived_current(
        LAMBDA_SIGNER_691_PREVIOUS_MANIFEST_PATH,
        LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE,
        LAMBDA_SIGNER_691_PREVIOUS_MANIFEST,
        LAMBDA_SIGNER_691_PREVIOUS_ARCHIVE_SHA256,
        LAMBDA_SIGNER_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_bedrock_actiongroup_691_previous():
    """Keep the exact catalog before guarding unverified Bedrock action-group execution."""
    return _verified_archived_current(
        BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST_PATH,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_ARCHIVE_SHA256,
        BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE, 691, 3737)


@lru_cache(maxsize=1)
def _verified_quicksight_iam_user_691_previous():
    """Keep the exact catalog before IAM-user registration documentation and role-session exclusion."""
    return _verified_archived_current(
        QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST_PATH,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_ARCHIVE_SHA256,
        QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_kafkaconnect_guard_691_previous():
    """Keep the exact catalog before the MSK Connect execution guard."""
    return _verified_archived_current(
        KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST_PATH,
        KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE,
        KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST,
        KAFKACONNECT_GUARD_691_PREVIOUS_ARCHIVE_SHA256,
        KAFKACONNECT_GUARD_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_braket_script_691_previous():
    """Keep the exact catalog before Braket device, code and output joins."""
    return _verified_archived_current(
        BRAKET_SCRIPT_691_PREVIOUS_MANIFEST_PATH, BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE,
        BRAKET_SCRIPT_691_PREVIOUS_MANIFEST, BRAKET_SCRIPT_691_PREVIOUS_ARCHIVE_SHA256,
        BRAKET_SCRIPT_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_domain_default_691_previous():
    """Keep the exact catalog before the Studio domain-default route."""
    return _verified_archived_current(
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_role_swap_691_previous():
    """Keep the exact catalog before the Studio profile role-swap route."""
    return _verified_archived_current(
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_new_profile_691_previous():
    """Keep the exact catalog before the Studio new-profile app route."""
    return _verified_archived_current(
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_studio_profile_691_previous():
    """Keep the exact catalog before the Studio profile lifecycle route."""
    return _verified_archived_current(
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST_PATH,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_hpo_691_previous():
    """Keep the exact catalog before the HPO script-mode role route."""
    return _verified_archived_current(
        SAGEMAKER_HPO_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_HPO_691_PREVIOUS_MANIFEST, SAGEMAKER_HPO_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_HPO_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_training_691_previous():
    """Keep the exact catalog before the Training job inline-entrypoint route."""
    return _verified_archived_current(
        SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST, SAGEMAKER_TRAINING_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_TRAINING_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_processing_691_previous():
    """Keep the exact catalog before the Processing job inline-entrypoint route."""
    return _verified_archived_current(
        SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST, SAGEMAKER_PROCESSING_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_PROCESSING_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_sagemaker_jobs_691_previous():
    """Keep the exact catalog before SageMaker job and PassRole scoping."""
    return _verified_archived_current(
        SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST_PATH, SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE,
        SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST, SAGEMAKER_JOBS_691_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_JOBS_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_harness_691_previous():
    """Keep the exact catalog before the harness composite-operation correction."""
    return _verified_archived_current(
        AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE,
        AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST, AGENTCORE_HARNESS_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_HARNESS_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_create_691_previous():
    """Keep the exact catalog before generated AgentCore Runtime scope binding."""
    return _verified_archived_current(
        AGENTCORE_CREATE_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE,
        AGENTCORE_CREATE_691_PREVIOUS_MANIFEST, AGENTCORE_CREATE_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_CREATE_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_runtime_691_previous():
    """Keep the exact catalog before the AgentCore runtime/endpoint join."""
    return _verified_archived_current(
        AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST_PATH, AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE,
        AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST, AGENTCORE_RUNTIME_691_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_RUNTIME_691_PREVIOUS_TREE, 691, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_existing_690_previous():
    """Keep the exact catalog before the existing Code Interpreter route."""
    return _verified_archived_current(
        AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST_PATH, AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE,
        AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST, AGENTCORE_EXISTING_690_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_EXISTING_690_PREVIOUS_TREE, 690, 3736)


@lru_cache(maxsize=1)
def _verified_agentcore_bounds_690_previous():
    """Keep the exact catalog before AgentCore browser and gateway bounds."""
    return _verified_archived_current(
        AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST_PATH, AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE,
        AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST, AGENTCORE_BOUNDS_690_PREVIOUS_ARCHIVE_SHA256,
        AGENTCORE_BOUNDS_690_PREVIOUS_TREE, 690, 3734)


@lru_cache(maxsize=1)
def _verified_sts_federation_690_previous():
    """Keep the exact catalog before SAML and web-identity candidates were tracked."""
    return _verified_archived_current(
        STS_FEDERATION_690_PREVIOUS_MANIFEST_PATH, STS_FEDERATION_690_PREVIOUS_ARCHIVE,
        STS_FEDERATION_690_PREVIOUS_MANIFEST, STS_FEDERATION_690_PREVIOUS_ARCHIVE_SHA256,
        STS_FEDERATION_690_PREVIOUS_TREE, 690, 3732)


@lru_cache(maxsize=1)
def _verified_amplify_role_690_previous():
    """Keep the exact catalog before Amplify app and branch gating."""
    return _verified_archived_current(
        AMPLIFY_ROLE_690_PREVIOUS_MANIFEST_PATH, AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE,
        AMPLIFY_ROLE_690_PREVIOUS_MANIFEST, AMPLIFY_ROLE_690_PREVIOUS_ARCHIVE_SHA256,
        AMPLIFY_ROLE_690_PREVIOUS_TREE, 690, 3732)


@lru_cache(maxsize=1)
def _verified_emr_runtime_689_previous():
    """Keep the exact catalog before EMR runtime-role routes were corrected."""
    return _verified_archived_current(
        EMR_RUNTIME_689_PREVIOUS_MANIFEST_PATH, EMR_RUNTIME_689_PREVIOUS_ARCHIVE,
        EMR_RUNTIME_689_PREVIOUS_MANIFEST, EMR_RUNTIME_689_PREVIOUS_ARCHIVE_SHA256,
        EMR_RUNTIME_689_PREVIOUS_TREE, 689, 3730)


@lru_cache(maxsize=1)
def _verified_elasticbeanstalk_effect_689_previous():
    """Keep the exact catalog before Elastic Beanstalk runtime gating."""
    return _verified_archived_current(
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST_PATH, ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE,
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST, ELASTICBEANSTALK_EFFECT_689_PREVIOUS_ARCHIVE_SHA256,
        ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE, 689, 3730)


@lru_cache(maxsize=1)
def _verified_config_remediation_689_previous():
    """Keep the exact catalog before Config remediation runtime gating."""
    return _verified_archived_current(
        CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST_PATH, CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE,
        CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST, CONFIG_REMEDIATION_689_PREVIOUS_ARCHIVE_SHA256,
        CONFIG_REMEDIATION_689_PREVIOUS_TREE, 689, 3729)


@lru_cache(maxsize=1)
def _verified_servicecatalog_effect_689_previous():
    """Keep the exact catalog before Service Catalog artifact-effect gating."""
    return _verified_archived_current(
        SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST_PATH, SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE,
        SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST, SERVICECATALOG_EFFECT_689_PREVIOUS_ARCHIVE_SHA256,
        SERVICECATALOG_EFFECT_689_PREVIOUS_TREE, 689, 3729)


@lru_cache(maxsize=1)
def _verified_org_access_role_689_previous():
    """Keep the exact catalog before generated Organizations access-role gating."""
    return _verified_archived_current(
        ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST_PATH, ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE,
        ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST, ORG_ACCESS_ROLE_689_PREVIOUS_ARCHIVE_SHA256,
        ORG_ACCESS_ROLE_689_PREVIOUS_TREE, 689, 3726)


@lru_cache(maxsize=1)
def _verified_stepfunctions_passrole_689_previous():
    """Keep the exact catalog before Step Functions PassRole service binding."""
    return _verified_archived_current(
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST_PATH, STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE,
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST, STEPFUNCTIONS_PASSROLE_689_PREVIOUS_ARCHIVE_SHA256,
        STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE, 689, 3726)


@lru_cache(maxsize=1)
def _verified_gamelift_coverage_689_previous():
    """Keep the exact catalog before GameLift fleet-variant exclusions."""
    return _verified_archived_current(
        GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST_PATH, GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE,
        GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST, GAMELIFT_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_COVERAGE_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_cognito_idp_secret_689_previous():
    """Keep the exact catalog before Cognito client-secret scope correction."""
    return _verified_archived_current(
        COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST_PATH, COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE,
        COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST, COGNITO_IDP_SECRET_689_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_IDP_SECRET_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_ec2_runinstances_689_previous():
    """Keep the exact catalog before EC2 launch reach became unresolved."""
    return _verified_archived_current(
        EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST_PATH, EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE,
        EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST, EC2_RUNINSTANCES_689_PREVIOUS_ARCHIVE_SHA256,
        EC2_RUNINSTANCES_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_stale_coverage_689_previous():
    """Keep the exact catalog before stale coverage text was corrected."""
    return _verified_archived_current(
        STALE_COVERAGE_689_PREVIOUS_MANIFEST_PATH, STALE_COVERAGE_689_PREVIOUS_ARCHIVE,
        STALE_COVERAGE_689_PREVIOUS_MANIFEST, STALE_COVERAGE_689_PREVIOUS_ARCHIVE_SHA256,
        STALE_COVERAGE_689_PREVIOUS_TREE, 689, 3724)


@lru_cache(maxsize=1)
def _verified_finspace_sunset_690_previous():
    """Keep the exact catalog before Amazon FinSpace became unavailable."""
    return _verified_archived_current(
        FINSPACE_SUNSET_690_PREVIOUS_MANIFEST_PATH, FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE,
        FINSPACE_SUNSET_690_PREVIOUS_MANIFEST, FINSPACE_SUNSET_690_PREVIOUS_ARCHIVE_SHA256,
        FINSPACE_SUNSET_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_spot_request_690_previous():
    """Keep the exact catalog before scoped Spot grants became unresolved."""
    return _verified_archived_current(
        SPOT_REQUEST_690_PREVIOUS_MANIFEST_PATH, SPOT_REQUEST_690_PREVIOUS_ARCHIVE,
        SPOT_REQUEST_690_PREVIOUS_MANIFEST, SPOT_REQUEST_690_PREVIOUS_ARCHIVE_SHA256,
        SPOT_REQUEST_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_mwaa_slr_690_previous():
    """Keep the exact catalog before MWAA service-linked role scope correction."""
    return _verified_archived_current(
        MWAA_SLR_690_PREVIOUS_MANIFEST_PATH, MWAA_SLR_690_PREVIOUS_ARCHIVE,
        MWAA_SLR_690_PREVIOUS_MANIFEST, MWAA_SLR_690_PREVIOUS_ARCHIVE_SHA256,
        MWAA_SLR_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_glue_script_690_previous():
    """Keep the exact catalog before the Glue script-object binding was documented."""
    return _verified_archived_current(
        GLUE_SCRIPT_690_PREVIOUS_MANIFEST_PATH, GLUE_SCRIPT_690_PREVIOUS_ARCHIVE,
        GLUE_SCRIPT_690_PREVIOUS_MANIFEST, GLUE_SCRIPT_690_PREVIOUS_ARCHIVE_SHA256,
        GLUE_SCRIPT_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_glue_690_previous():
    """Keep the exact catalog before the Glue endpoint route was narrowed."""
    return _verified_archived_current(
        GLUE_690_PREVIOUS_MANIFEST_PATH, GLUE_690_PREVIOUS_ARCHIVE,
        GLUE_690_PREVIOUS_MANIFEST, GLUE_690_PREVIOUS_ARCHIVE_SHA256,
        GLUE_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_devicefarm_690_previous():
    """Keep the exact catalog before the Device Farm route was narrowed."""
    return _verified_archived_current(
        DEVICEFARM_690_PREVIOUS_MANIFEST_PATH, DEVICEFARM_690_PREVIOUS_ARCHIVE,
        DEVICEFARM_690_PREVIOUS_MANIFEST, DEVICEFARM_690_PREVIOUS_ARCHIVE_SHA256,
        DEVICEFARM_690_PREVIOUS_TREE, 690, 3723)


@lru_cache(maxsize=1)
def _verified_gamelift_shell_689_previous():
    """Keep the exact 689-entry catalog before the controlled-build join."""
    return _verified_archived_current(
        GAMELIFT_SHELL_689_PREVIOUS_MANIFEST_PATH, GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE,
        GAMELIFT_SHELL_689_PREVIOUS_MANIFEST, GAMELIFT_SHELL_689_PREVIOUS_ARCHIVE_SHA256,
        GAMELIFT_SHELL_689_PREVIOUS_TREE, 689, 3723)


@lru_cache(maxsize=1)
def _verified_iot_existing_689_previous():
    """Keep the exact 689-entry catalog before existing IoT alias repointing."""
    return _verified_archived_current(
        IOT_EXISTING_689_PREVIOUS_MANIFEST_PATH, IOT_EXISTING_689_PREVIOUS_ARCHIVE,
        IOT_EXISTING_689_PREVIOUS_MANIFEST, IOT_EXISTING_689_PREVIOUS_ARCHIVE_SHA256,
        IOT_EXISTING_689_PREVIOUS_TREE, 689, 3723)


@lru_cache(maxsize=1)
def _verified_scheduler_create_686_previous():
    """Keep the exact catalog before the existing-schedule update route."""
    return _verified_archived_current(
        SCHEDULER_CREATE_686_PREVIOUS_MANIFEST_PATH, SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE,
        SCHEDULER_CREATE_686_PREVIOUS_MANIFEST, SCHEDULER_CREATE_686_PREVIOUS_ARCHIVE_SHA256,
        SCHEDULER_CREATE_686_PREVIOUS_TREE, 686, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_dependencies_686_previous():
    """Keep the exact catalog before worker creation dependencies were documented."""
    return _verified_archived_current(
        DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST_PATH, DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE,
        DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST, DEADLINE_DEPENDENCIES_686_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE, 686, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_new_worker_685_previous():
    """Keep the exact catalog before the new worker route on an existing fleet."""
    return _verified_archived_current(
        DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST_PATH, DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE,
        DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST, DEADLINE_NEW_WORKER_685_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_NEW_WORKER_685_PREVIOUS_TREE, 685, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_worker_684_previous():
    """Keep the exact catalog before the existing Deadline worker role route."""
    return _verified_archived_current(
        DEADLINE_WORKER_684_PREVIOUS_MANIFEST_PATH, DEADLINE_WORKER_684_PREVIOUS_ARCHIVE,
        DEADLINE_WORKER_684_PREVIOUS_MANIFEST, DEADLINE_WORKER_684_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_WORKER_684_PREVIOUS_TREE, 684, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_fleet_684_previous():
    """Keep the exact catalog before the Deadline fleet worker scope correction."""
    return _verified_archived_current(
        DEADLINE_FLEET_684_PREVIOUS_MANIFEST_PATH, DEADLINE_FLEET_684_PREVIOUS_ARCHIVE,
        DEADLINE_FLEET_684_PREVIOUS_MANIFEST, DEADLINE_FLEET_684_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_FLEET_684_PREVIOUS_TREE, 684, 3723)


@lru_cache(maxsize=1)
def _verified_deadline_queue_683_previous():
    """Keep the exact catalog before the existing Deadline queue role route."""
    return _verified_archived_current(
        DEADLINE_QUEUE_683_PREVIOUS_MANIFEST_PATH, DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE,
        DEADLINE_QUEUE_683_PREVIOUS_MANIFEST, DEADLINE_QUEUE_683_PREVIOUS_ARCHIVE_SHA256,
        DEADLINE_QUEUE_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_cloudfront_create_683_previous():
    """Keep the exact catalog before the CloudFront creation path was added."""
    return _verified_archived_current(
        CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST_PATH, CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE,
        CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST, CLOUDFRONT_CREATE_683_PREVIOUS_ARCHIVE_SHA256,
        CLOUDFRONT_CREATE_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_cognito_guest_existing_683_previous():
    """Keep the exact catalog before already-public pools were excluded."""
    return _verified_archived_current(
        COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST_PATH, COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE,
        COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST, COGNITO_GUEST_EXISTING_683_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE, 683, 3723)


@lru_cache(maxsize=1)
def _verified_sagemaker_attach_682_previous():
    """Keep the exact catalog before the notebook attachment condition."""
    return _verified_archived_current(
        SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST_PATH, SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE,
        SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST, SAGEMAKER_ATTACH_682_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_ATTACH_682_PREVIOUS_TREE, 682, 3723)


@lru_cache(maxsize=1)
def _verified_sagemaker_lcc_677_previous():
    """Keep the exact 677-entry catalog used before the next audit batch."""
    return _verified_archived_current(
        SAGEMAKER_LCC_677_PREVIOUS_MANIFEST_PATH, SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE,
        SAGEMAKER_LCC_677_PREVIOUS_MANIFEST, SAGEMAKER_LCC_677_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_LCC_677_PREVIOUS_TREE, 677, 3722)


@lru_cache(maxsize=1)
def _verified_sagemaker_lcc_previous():
    """Keep the exact catalog used before the attached notebook lifecycle route."""
    return _verified_archived_current(
        SAGEMAKER_LCC_PREVIOUS_MANIFEST_PATH, SAGEMAKER_LCC_PREVIOUS_ARCHIVE,
        SAGEMAKER_LCC_PREVIOUS_MANIFEST, SAGEMAKER_LCC_PREVIOUS_ARCHIVE_SHA256,
        SAGEMAKER_LCC_PREVIOUS_TREE, SAGEMAKER_LCC_PREVIOUS_ENTRY_COUNT,
        SAGEMAKER_LCC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_mwaa_dag_previous():
    """Keep the exact catalog used before the MWAA DAG-object route."""
    return _verified_archived_current(
        MWAA_DAG_PREVIOUS_MANIFEST_PATH, MWAA_DAG_PREVIOUS_ARCHIVE,
        MWAA_DAG_PREVIOUS_MANIFEST, MWAA_DAG_PREVIOUS_ARCHIVE_SHA256,
        MWAA_DAG_PREVIOUS_TREE, MWAA_DAG_PREVIOUS_ENTRY_COUNT,
        MWAA_DAG_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_ssm_hybrid_previous():
    """Keep the exact catalog used before the hybrid-node shell routes."""
    return _verified_archived_current(
        SSM_HYBRID_PREVIOUS_MANIFEST_PATH, SSM_HYBRID_PREVIOUS_ARCHIVE,
        SSM_HYBRID_PREVIOUS_MANIFEST, SSM_HYBRID_PREVIOUS_ARCHIVE_SHA256,
        SSM_HYBRID_PREVIOUS_TREE, SSM_HYBRID_PREVIOUS_ENTRY_COUNT,
        SSM_HYBRID_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_cognito_previous():
    """Keep the exact 668-entry catalog used before the developer-token route."""
    return _verified_archived_current(
        COGNITO_PREVIOUS_MANIFEST_PATH, COGNITO_PREVIOUS_ARCHIVE,
        COGNITO_PREVIOUS_MANIFEST, COGNITO_PREVIOUS_ARCHIVE_SHA256,
        COGNITO_PREVIOUS_TREE, COGNITO_PREVIOUS_ENTRY_COUNT, COGNITO_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_classic_previous():
    """Keep the exact 669-entry catalog used before the Basic-flow route."""
    return _verified_archived_current(
        CLASSIC_PREVIOUS_MANIFEST_PATH, CLASSIC_PREVIOUS_ARCHIVE,
        CLASSIC_PREVIOUS_MANIFEST, CLASSIC_PREVIOUS_ARCHIVE_SHA256,
        CLASSIC_PREVIOUS_TREE, CLASSIC_PREVIOUS_ENTRY_COUNT, CLASSIC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_setroles_previous():
    """Keep the exact 670-entry catalog used before the pool-role mutation route."""
    return _verified_archived_current(
        SETROLES_PREVIOUS_MANIFEST_PATH, SETROLES_PREVIOUS_ARCHIVE,
        SETROLES_PREVIOUS_MANIFEST, SETROLES_PREVIOUS_ARCHIVE_SHA256,
        SETROLES_PREVIOUS_TREE, SETROLES_PREVIOUS_ENTRY_COUNT, SETROLES_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_enable_classic_previous():
    """Keep the exact 671-entry catalog used before the flow-enablement route."""
    return _verified_archived_current(
        ENABLE_CLASSIC_PREVIOUS_MANIFEST_PATH, ENABLE_CLASSIC_PREVIOUS_ARCHIVE,
        ENABLE_CLASSIC_PREVIOUS_MANIFEST, ENABLE_CLASSIC_PREVIOUS_ARCHIVE_SHA256,
        ENABLE_CLASSIC_PREVIOUS_TREE, ENABLE_CLASSIC_PREVIOUS_ENTRY_COUNT, ENABLE_CLASSIC_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_ecscape_previous():
    """Keep the exact catalog used before ECScape execution roles were included."""
    return _verified_archived_current(
        ECSCAPE_PREVIOUS_MANIFEST_PATH, ECSCAPE_PREVIOUS_ARCHIVE,
        ECSCAPE_PREVIOUS_MANIFEST, ECSCAPE_PREVIOUS_ARCHIVE_SHA256,
        ECSCAPE_PREVIOUS_TREE, ECSCAPE_PREVIOUS_ENTRY_COUNT, ECSCAPE_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_glue_script_previous():
    """Keep the exact catalog used before the Glue script-object route was added."""
    return _verified_archived_current(
        GLUE_SCRIPT_PREVIOUS_MANIFEST_PATH, GLUE_SCRIPT_PREVIOUS_ARCHIVE,
        GLUE_SCRIPT_PREVIOUS_MANIFEST, GLUE_SCRIPT_PREVIOUS_ARCHIVE_SHA256,
        GLUE_SCRIPT_PREVIOUS_TREE, GLUE_SCRIPT_PREVIOUS_ENTRY_COUNT,
        GLUE_SCRIPT_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_imagebuilder_previous():
    """Keep the exact catalog used before the Image Builder pipeline binding repair."""
    return _verified_archived_current(
        IMAGEBUILDER_PREVIOUS_MANIFEST_PATH, IMAGEBUILDER_PREVIOUS_ARCHIVE,
        IMAGEBUILDER_PREVIOUS_MANIFEST, IMAGEBUILDER_PREVIOUS_ARCHIVE_SHA256,
        IMAGEBUILDER_PREVIOUS_TREE, IMAGEBUILDER_PREVIOUS_ENTRY_COUNT,
        IMAGEBUILDER_PREVIOUS_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_gamelift_current():
    """Keep the exact catalog used before the GameLift admin-shell route."""
    return _verified_archived_current(
        GAMELIFT_CURRENT_MANIFEST_PATH, GAMELIFT_CURRENT_ARCHIVE,
        GAMELIFT_CURRENT_MANIFEST, GAMELIFT_CURRENT_ARCHIVE_SHA256,
        GAMELIFT_CURRENT_TREE, GAMELIFT_CURRENT_ENTRY_COUNT, GAMELIFT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_current():
    """Keep the exact 667-entry catalog used before the IoT route correction."""
    return _verified_archived_current(
        IOT_CURRENT_MANIFEST_PATH, IOT_CURRENT_ARCHIVE,
        IOT_CURRENT_MANIFEST, IOT_CURRENT_ARCHIVE_SHA256,
        IOT_CURRENT_TREE, IOT_CURRENT_ENTRY_COUNT, IOT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_v1_current():
    """Keep the exact IoT catalog before the self-registered certificate variant."""
    return _verified_archived_current(
        IOT_V1_CURRENT_MANIFEST_PATH, IOT_V1_CURRENT_ARCHIVE,
        IOT_V1_CURRENT_MANIFEST, IOT_V1_CURRENT_ARCHIVE_SHA256,
        IOT_V1_CURRENT_TREE, IOT_V1_CURRENT_ENTRY_COUNT, IOT_V1_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_iot_v2_current():
    """Keep the exact IoT catalog before regional setup was joined."""
    return _verified_archived_current(
        IOT_V2_CURRENT_MANIFEST_PATH, IOT_V2_CURRENT_ARCHIVE,
        IOT_V2_CURRENT_MANIFEST, IOT_V2_CURRENT_ARCHIVE_SHA256,
        IOT_V2_CURRENT_TREE, IOT_V2_CURRENT_ENTRY_COUNT, IOT_V2_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_intermediate_current():
    """Keep the exact 660-entry catalog used before the next AWS recovery."""
    return _verified_archived_current(
        INTERMEDIATE_CURRENT_MANIFEST_PATH, INTERMEDIATE_CURRENT_ARCHIVE,
        INTERMEDIATE_CURRENT_MANIFEST, INTERMEDIATE_CURRENT_ARCHIVE_SHA256,
        INTERMEDIATE_CURRENT_TREE, INTERMEDIATE_CURRENT_ENTRY_COUNT, INTERMEDIATE_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_recent_current():
    """Keep the exact 661-entry catalog used before Athena sessions were restored."""
    return _verified_archived_current(
        RECENT_CURRENT_MANIFEST_PATH, RECENT_CURRENT_ARCHIVE,
        RECENT_CURRENT_MANIFEST, RECENT_CURRENT_ARCHIVE_SHA256,
        RECENT_CURRENT_TREE, RECENT_CURRENT_ENTRY_COUNT, RECENT_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_athena_current():
    """Keep the exact 664-entry catalog used before the Batch restoration."""
    return _verified_archived_current(
        ATHENA_CURRENT_MANIFEST_PATH, ATHENA_CURRENT_ARCHIVE,
        ATHENA_CURRENT_MANIFEST, ATHENA_CURRENT_ARCHIVE_SHA256,
        ATHENA_CURRENT_TREE, ATHENA_CURRENT_ENTRY_COUNT, ATHENA_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_batch_current():
    """Keep the exact 665-entry catalog used before App Runner restoration."""
    return _verified_archived_current(
        BATCH_CURRENT_MANIFEST_PATH, BATCH_CURRENT_ARCHIVE,
        BATCH_CURRENT_MANIFEST, BATCH_CURRENT_ARCHIVE_SHA256,
        BATCH_CURRENT_TREE, BATCH_CURRENT_ENTRY_COUNT, BATCH_CURRENT_EXCLUDED_COUNT)


@lru_cache(maxsize=1)
def _verified_apprunner_current():
    """Keep the exact 666-entry catalog used before the AppSync addition."""
    return _verified_archived_current(
        APPRUNNER_CURRENT_MANIFEST_PATH, APPRUNNER_CURRENT_ARCHIVE,
        APPRUNNER_CURRENT_MANIFEST, APPRUNNER_CURRENT_ARCHIVE_SHA256,
        APPRUNNER_CURRENT_TREE, APPRUNNER_CURRENT_ENTRY_COUNT, APPRUNNER_CURRENT_EXCLUDED_COUNT)


def _verified_archived_current(manifest_path, archive_path, manifest_digest, archive_digest,
                               tree_digest, entry_count, excluded_count):
    if _sha(manifest_path) != manifest_digest or _sha(archive_path) != archive_digest:
        raise ValueError("archived_current_changed")
    wanted = json.loads(manifest_path.read_text())["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith("catalog/"):
                raise ValueError("archived_current_path_mismatch")
            name = member.name.removeprefix("catalog/")
            if name not in wanted or name in actual:
                raise ValueError("archived_current_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.safe_load(payload) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("archived_current_duplicate_id")
                    entries[item["id"]] = item
    tree = ''.join(f'{name} {actual[name]}\n' for name in sorted(actual))
    if (actual != wanted or hashlib.sha256(tree.encode()).hexdigest() != tree_digest or
            len(entries) != entry_count or excluded != excluded_count):
        raise ValueError("archived_current_mismatch")
    return entries


@lru_cache(maxsize=1)
def _verified_prior():
    """Read the exact previous catalog so old report bindings keep their meanings."""
    if _sha(PRIOR_SOURCE_MANIFEST) != PRIOR_CURRENT_MANIFEST:
        raise ValueError("prior_catalog_manifest_mismatch")
    wanted = json.loads(PRIOR_SOURCE_MANIFEST.read_text())["sha256"]
    actual, entries, excluded = {}, {}, 0
    with tarfile.open(PRIOR_CATALOG_ARCHIVE, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.removeprefix("catalog/")
            if name == member.name or name not in wanted:
                raise ValueError("prior_catalog_archive_path_mismatch")
            payload = archive.extractfile(member).read()
            actual[name] = hashlib.sha256(payload).hexdigest()
            rows = yaml.safe_load(payload) or []
            if name.rsplit("/", 1)[-1].startswith("_excluded"):
                excluded += len(rows)
            else:
                for row in rows:
                    item = dict(row, _file=name)
                    if item["id"] in entries:
                        raise ValueError("prior_catalog_duplicate_id")
                    entries[item["id"]] = item
    if actual != wanted or len(entries) != 1234 or excluded != 2847:
        raise ValueError("prior_catalog_archive_mismatch")
    return entries, actual


def _principal_v4(entries, catalog_hashes):
    """Old cards retain their exact 244-file catalog and original 1,052 meanings."""
    if _sha(V4_HISTORY) != V4_MANIFEST:
        raise ValueError("principal_v4_history_mismatch")
    pins = json.loads(V4_HISTORY.read_text())["sha256"]
    if len(pins) != 244 or any(catalog_hashes.get(name) != digest for name, digest in pins.items()):
        raise ValueError("principal_v4_history_files_mismatch")
    retained = {ident: entry for ident, entry in entries.items()
                if str(entry.get("_file", "")) in pins}
    if len(retained) != 1052:
        raise ValueError("principal_v4_history_count_mismatch")
    return retained


@lru_cache(maxsize=4)
def _verified_history(history_path):
    if _sha(Path(history_path)) != LEGACY_DELTA_SHA256:
        raise ValueError("legacy_delta_sha_mismatch")
    history = json.loads(Path(history_path).read_text())
    if (history.get("schema") != "legacy-source0b-catalog-delta-v1" or
            history.get("baseline_manifest_sha256") != LEGACY_MANIFEST or
            history.get("baseline_revision") != LEGACY_REVISION or
            len(history.get("legacy_ids", [])) != 1004 or
            len(history.get("changed_shared_ids", [])) != 75 or
            len(history.get("retired_ids", [])) != 28 or
            len(history.get("old_entries", {})) != 103 or history.get("retired_aliases") != {}):
        raise ValueError("legacy_delta_mismatch")
    return history


def current_binding(*, catalog_dir=None, manifest_path=None):
    catalog_dir, manifest_path, _ = _paths(catalog_dir, manifest_path)
    _verified_current(str(catalog_dir), str(manifest_path))
    return {"schema": BINDING_SCHEMA, "manifest_sha256": CURRENT_MANIFEST,
            "effective_tree_sha256": CURRENT_TREE, "source_revision": V4_REVISION}


def lookup_entries(technique_ids, binding=None, *, tenant_id=None, catalog_dir=None,
                   manifest_path=None, history_path=None):
    """Return original entries plus lookup state; never reinterpret graph edges.

    Missing bindings use source0b labels as an explicitly uncertain legacy
    fallback. Unknown or contradictory bindings return no descriptions.
    """
    catalog_dir, manifest_path, history_path = _paths(catalog_dir, manifest_path, history_path)
    ids = tuple(dict.fromkeys(technique_ids))
    if binding is None:
        version, status = "legacy", "legacy_unversioned_fallback"
    elif not isinstance(binding, dict) or binding.get("schema") != BINDING_SCHEMA:
        return {}, "invalid_catalog_binding"
    elif tenant_id is not None and binding.get("tenant_id") != tenant_id:
        return {}, "tenant_binding_mismatch"
    elif (binding.get("manifest_sha256") == CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "current", "exact_strict_privesc"
    elif (binding.get("manifest_sha256") == BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEDROCK_ACTIONGROUP_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bedrock_actiongroup_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_HARNESS_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_harness_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_RUNTIME_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_runtime_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AMPLIFY_ROLE_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "amplify_role_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_STACKSET_EFFECTS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_STACKSET_EFFECTS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_stackset_effects_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_EXTENSION_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_EXTENSION_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_extension_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CFN_TEMPLATE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CFN_TEMPLATE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cfn_template_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == TESTSTATE_ROLE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == TESTSTATE_ROLE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "teststate_role_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SFN_ROLE_EFFECT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SFN_ROLE_EFFECT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sfn_role_effect_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INSTANCE_CONNECT_WITNESS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == INSTANCE_CONNECT_WITNESS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "instance_connect_witness_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_TASKSET_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_TASKSET_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_taskset_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_NODE_ESCAPE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_NODE_ESCAPE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_node_escape_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_SERVICE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_SERVICE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_service_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_START_TASK_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_START_TASK_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_start_task_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECS_NEW_TASK_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECS_NEW_TASK_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecs_new_task_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORGANIZATIONS_RCP_691_REVISIONLESS_MANIFEST and
          binding.get("effective_tree_sha256") == CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        # The source commit became known after the YAML was committed; the
        # effective catalog tree did not change.
        version, status = "current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORGANIZATIONS_RCP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ORGANIZATIONS_RCP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "organizations_rcp_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == LAMBDA_SIGNER_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == LAMBDA_SIGNER_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "lambda_signer_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BEDROCK_ACTIONGROUP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BEDROCK_ACTIONGROUP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bedrock_actiongroup_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == QUICKSIGHT_IAM_USER_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == QUICKSIGHT_IAM_USER_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "quicksight_iam_user_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == KAFKACONNECT_GUARD_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == KAFKACONNECT_GUARD_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "kafkaconnect_guard_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BRAKET_SCRIPT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BRAKET_SCRIPT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "braket_script_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_DOMAIN_DEFAULT_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_domain_default_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_ROLE_SWAP_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_ROLE_SWAP_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_role_swap_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_NEW_PROFILE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_NEW_PROFILE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_new_profile_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_STUDIO_PROFILE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_studio_profile_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_HPO_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_HPO_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_hpo_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_TRAINING_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_TRAINING_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_training_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_PROCESSING_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_PROCESSING_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_processing_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_JOBS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_JOBS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_jobs_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_HARNESS_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_HARNESS_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_harness_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_CREATE_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_CREATE_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_create_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_RUNTIME_691_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_RUNTIME_691_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_runtime_691_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_EXISTING_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_EXISTING_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_existing_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AGENTCORE_BOUNDS_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AGENTCORE_BOUNDS_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "agentcore_bounds_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STS_FEDERATION_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STS_FEDERATION_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sts_federation_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == AMPLIFY_ROLE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == AMPLIFY_ROLE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "amplify_role_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EMR_RUNTIME_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EMR_RUNTIME_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "emr_runtime_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ELASTICBEANSTALK_EFFECT_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ELASTICBEANSTALK_EFFECT_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "elasticbeanstalk_effect_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CONFIG_REMEDIATION_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CONFIG_REMEDIATION_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "config_remediation_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SERVICECATALOG_EFFECT_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SERVICECATALOG_EFFECT_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "servicecatalog_effect_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ORG_ACCESS_ROLE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ORG_ACCESS_ROLE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "org_access_role_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STEPFUNCTIONS_PASSROLE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STEPFUNCTIONS_PASSROLE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "stepfunctions_passrole_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_COVERAGE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_COVERAGE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_coverage_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_IDP_SECRET_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_IDP_SECRET_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_idp_secret_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == EC2_RUNINSTANCES_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == EC2_RUNINSTANCES_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ec2_runinstances_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == STALE_COVERAGE_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == STALE_COVERAGE_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "stale_coverage_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == FINSPACE_SUNSET_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == FINSPACE_SUNSET_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "finspace_sunset_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SPOT_REQUEST_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SPOT_REQUEST_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "spot_request_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == TESTSTATE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == TESTSTATE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "teststate_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INSTANCE_CONNECT_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == INSTANCE_CONNECT_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "instance_connect_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BRAKET_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == BRAKET_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "braket_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLOUDCONTROL_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLOUDCONTROL_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cloudcontrol_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_SLR_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_SLR_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_slr_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_SCRIPT_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_SCRIPT_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_script_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEVICEFARM_690_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEVICEFARM_690_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "devicefarm_690_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_EXISTING_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_EXISTING_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_existing_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_SHELL_689_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_SHELL_689_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_shell_689_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_SHARED_688_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_SHARED_688_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_shared_688_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SCHEDULER_UPDATE_687_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SCHEDULER_UPDATE_687_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "scheduler_update_687_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SCHEDULER_CREATE_686_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SCHEDULER_CREATE_686_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "scheduler_create_686_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_DEPENDENCIES_686_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_DEPENDENCIES_686_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_dependencies_686_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_NEW_WORKER_685_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_NEW_WORKER_685_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_new_worker_685_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_WORKER_684_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_WORKER_684_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_worker_684_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_FLEET_684_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_FLEET_684_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_fleet_684_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == DEADLINE_QUEUE_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == DEADLINE_QUEUE_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "deadline_queue_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLOUDFRONT_CREATE_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cloudfront_create_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_ATTACH_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_attach_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_GUEST_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_GUEST_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_guest_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_GUEST_EXISTING_683_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_GUEST_EXISTING_683_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_guest_existing_683_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_GROUP_682_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_GROUP_682_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_group_682_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_LCC_677_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_LCC_677_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_lcc_677_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SAGEMAKER_LCC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SAGEMAKER_LCC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "sagemaker_lcc_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SSM_HYBRID_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SSM_HYBRID_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ssm_hybrid_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == MWAA_DAG_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == MWAA_DAG_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "mwaa_dag_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IMAGEBUILDER_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == IMAGEBUILDER_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "imagebuilder_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GLUE_SCRIPT_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == GLUE_SCRIPT_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "glue_script_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ECSCAPE_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ECSCAPE_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "ecscape_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ENABLE_CLASSIC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == ENABLE_CLASSIC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "enable_classic_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == SETROLES_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == SETROLES_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "setroles_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == CLASSIC_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == CLASSIC_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "classic_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == COGNITO_PREVIOUS_MANIFEST and
          binding.get("effective_tree_sha256") == COGNITO_PREVIOUS_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "cognito_previous", "exact_previous_current"
    elif (binding.get("manifest_sha256") == PREVIOUS_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PREVIOUS_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "previous_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == GAMELIFT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == GAMELIFT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "gamelift_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_V1_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_V1_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_v1_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == IOT_V2_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == IOT_V2_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "iot_v2_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == BATCH_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == BATCH_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "batch_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == APPRUNNER_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == APPRUNNER_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "apprunner_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == INTERMEDIATE_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == INTERMEDIATE_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "intermediate_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == RECENT_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == RECENT_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "recent_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == ATHENA_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == ATHENA_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "athena_current", "exact_previous_current"
    elif (binding.get("manifest_sha256") == PRIOR_CURRENT_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_CURRENT_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_current", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_DISCLOSURE_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_DISCLOSURE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_disclosure", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == PRIOR_BOUNDED_MANIFEST and
          binding.get("effective_tree_sha256") == PRIOR_BOUNDED_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "prior_bounded", "exact_bounded_v5"
    elif (binding.get("manifest_sha256") == V4_MANIFEST and
          binding.get("effective_tree_sha256") == V4_EFFECTIVE_TREE and
          binding.get("source_revision") == V4_REVISION):
        version, status = "v4", "exact_additive_v4"
    elif (binding.get("manifest_sha256") == LEGACY_MANIFEST and
          binding.get("source_revision") == LEGACY_REVISION):
        version, status = "legacy", "exact_legacy"
    else:
        return {}, "unknown_catalog_manifest"
    try:
        if version == "current":
            current = _verified_current(str(catalog_dir), str(manifest_path))
            return {ident: current[ident] for ident in ids if ident in current}, status
        if version == "bedrock_actiongroup_effect_691_previous":
            previous = _verified_bedrock_actiongroup_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        elif version == "agentcore_harness_effect_691_previous":
            previous = _verified_agentcore_harness_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_runtime_effects_691_previous":
            previous = _verified_agentcore_runtime_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "amplify_role_effects_691_previous":
            previous = _verified_amplify_role_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_stackset_effects_691_previous":
            previous = _verified_cfn_stackset_effects_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_extension_effect_691_previous":
            previous = _verified_cfn_extension_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cfn_template_effect_691_previous":
            previous = _verified_cfn_template_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "teststate_role_effect_691_previous":
            previous = _verified_teststate_role_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sfn_role_effect_691_previous":
            previous = _verified_sfn_role_effect_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "instance_connect_witness_691_previous":
            previous = _verified_instance_connect_witness_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_taskset_691_previous":
            previous = _verified_ecs_taskset_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_node_escape_691_previous":
            previous = _verified_ecs_node_escape_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_service_691_previous":
            previous = _verified_ecs_service_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_start_task_691_previous":
            previous = _verified_ecs_start_task_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecs_new_task_691_previous":
            previous = _verified_ecs_new_task_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "organizations_rcp_691_previous":
            previous = _verified_organizations_rcp_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "lambda_signer_691_previous":
            previous = _verified_lambda_signer_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "bedrock_actiongroup_691_previous":
            previous = _verified_bedrock_actiongroup_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "quicksight_iam_user_691_previous":
            previous = _verified_quicksight_iam_user_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "kafkaconnect_guard_691_previous":
            previous = _verified_kafkaconnect_guard_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "braket_script_691_previous":
            previous = _verified_braket_script_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_domain_default_691_previous":
            previous = _verified_sagemaker_domain_default_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_role_swap_691_previous":
            previous = _verified_sagemaker_role_swap_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_new_profile_691_previous":
            previous = _verified_sagemaker_new_profile_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_studio_profile_691_previous":
            previous = _verified_sagemaker_studio_profile_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_hpo_691_previous":
            previous = _verified_sagemaker_hpo_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_training_691_previous":
            previous = _verified_sagemaker_training_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_processing_691_previous":
            previous = _verified_sagemaker_processing_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_jobs_691_previous":
            previous = _verified_sagemaker_jobs_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_harness_691_previous":
            previous = _verified_agentcore_harness_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_create_691_previous":
            previous = _verified_agentcore_create_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_runtime_691_previous":
            previous = _verified_agentcore_runtime_691_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_existing_690_previous":
            previous = _verified_agentcore_existing_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "agentcore_bounds_690_previous":
            previous = _verified_agentcore_bounds_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sts_federation_690_previous":
            previous = _verified_sts_federation_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "amplify_role_690_previous":
            previous = _verified_amplify_role_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "emr_runtime_689_previous":
            previous = _verified_emr_runtime_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "elasticbeanstalk_effect_689_previous":
            previous = _verified_elasticbeanstalk_effect_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "config_remediation_689_previous":
            previous = _verified_config_remediation_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "servicecatalog_effect_689_previous":
            previous = _verified_servicecatalog_effect_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "org_access_role_689_previous":
            previous = _verified_org_access_role_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "stepfunctions_passrole_689_previous":
            previous = _verified_stepfunctions_passrole_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_coverage_689_previous":
            previous = _verified_gamelift_coverage_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_idp_secret_689_previous":
            previous = _verified_cognito_idp_secret_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ec2_runinstances_689_previous":
            previous = _verified_ec2_runinstances_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "stale_coverage_689_previous":
            previous = _verified_stale_coverage_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "finspace_sunset_690_previous":
            previous = _verified_finspace_sunset_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "spot_request_690_previous":
            previous = _verified_spot_request_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "teststate_690_previous":
            previous = _verified_teststate_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "instance_connect_690_previous":
            previous = _verified_instance_connect_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "braket_690_previous":
            previous = _verified_braket_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cloudcontrol_690_previous":
            previous = _verified_cloudcontrol_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_slr_690_previous":
            previous = _verified_mwaa_slr_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_script_690_previous":
            previous = _verified_glue_script_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_690_previous":
            previous = _verified_glue_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "devicefarm_690_previous":
            previous = _verified_devicefarm_690_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_existing_689_previous":
            previous = _verified_iot_existing_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_shell_689_previous":
            previous = _verified_gamelift_shell_689_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_shared_688_previous":
            previous = _verified_gamelift_shared_688_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "scheduler_update_687_previous":
            previous = _verified_scheduler_update_687_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "scheduler_create_686_previous":
            previous = _verified_scheduler_create_686_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_dependencies_686_previous":
            previous = _verified_deadline_dependencies_686_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_new_worker_685_previous":
            previous = _verified_deadline_new_worker_685_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_worker_684_previous":
            previous = _verified_deadline_worker_684_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_fleet_684_previous":
            previous = _verified_deadline_fleet_684_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "deadline_queue_683_previous":
            previous = _verified_deadline_queue_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cloudfront_create_683_previous":
            previous = _verified_cloudfront_create_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_attach_682_previous":
            previous = _verified_sagemaker_attach_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_guest_682_previous":
            previous = _verified_cognito_guest_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_guest_existing_683_previous":
            previous = _verified_cognito_guest_existing_683_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_group_682_previous":
            previous = _verified_gamelift_group_682_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_lcc_677_previous":
            previous = _verified_sagemaker_lcc_677_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "sagemaker_lcc_previous":
            previous = _verified_sagemaker_lcc_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ssm_hybrid_previous":
            previous = _verified_ssm_hybrid_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "mwaa_dag_previous":
            previous = _verified_mwaa_dag_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "imagebuilder_previous":
            previous = _verified_imagebuilder_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "glue_script_previous":
            previous = _verified_glue_script_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "ecscape_previous":
            previous = _verified_ecscape_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "enable_classic_previous":
            previous = _verified_enable_classic_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "setroles_previous":
            previous = _verified_setroles_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "classic_previous":
            previous = _verified_classic_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "cognito_previous":
            previous = _verified_cognito_previous()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "previous_current":
            previous = _verified_previous_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "gamelift_current":
            previous = _verified_gamelift_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_current":
            previous = _verified_iot_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_v1_current":
            previous = _verified_iot_v1_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "iot_v2_current":
            previous = _verified_iot_v2_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "batch_current":
            previous = _verified_batch_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "apprunner_current":
            previous = _verified_apprunner_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "intermediate_current":
            previous = _verified_intermediate_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "recent_current":
            previous = _verified_recent_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        if version == "athena_current":
            previous = _verified_athena_current()
            return {ident: previous[ident] for ident in ids if ident in previous}, status
        v4, prior_hashes = _verified_prior()
        if version == "prior_current":
            return {ident: v4[ident] for ident in ids if ident in v4}, status
        if version == "prior_disclosure":
            if _sha(PRIOR_DISCLOSURE_HISTORY) != PRIOR_DISCLOSURE_MANIFEST:
                raise ValueError("disclosure_history_changed")
            pins = json.loads(PRIOR_DISCLOSURE_HISTORY.read_text())["sha256"]
            if len(pins) != 253 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("disclosure_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1227:
                raise ValueError("disclosure_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "bounded":
            if _sha(CURRENT_HISTORY) != BOUNDED_MANIFEST:
                raise ValueError("bulk_principal_history_changed")
            pins = json.loads(CURRENT_HISTORY.read_text())["sha256"]
            if len(pins) != 251 or any(prior_hashes.get(name) != digest for name, digest in pins.items()):
                raise ValueError("bulk_principal_history_files_changed")
            retained = {key: value for key, value in v4.items() if str(value.get("_file", "")) in pins}
            if len(retained) != 1224:
                raise ValueError("bulk_principal_history_count_changed")
            return {key: retained[key] for key in ids if key in retained}, status
        if version == "prior_bounded":
            if _sha(BOUNDED_HISTORY) != PRIOR_BOUNDED_MANIFEST: raise ValueError("bounded_history_changed")
            pins = json.loads(BOUNDED_HISTORY.read_text())["sha256"]
            if len(pins) != 249 or any(prior_hashes.get(name) != digest for name, digest in pins.items()): raise ValueError("bounded_history_files_changed")
            retained = {k:v for k,v in v4.items() if str(v.get("_file", "")) in pins}
            if len(retained) != 1126: raise ValueError("bounded_history_count_changed")
            return {k:retained[k] for k in ids if k in retained}, status
        if version == "v4":
            original = _principal_v4(v4, prior_hashes)
            return {ident: original[ident] for ident in ids if ident in original}, status
        history = _verified_history(str(history_path))
        allowed, old = set(history["legacy_ids"]), history["old_entries"]
        return {ident: old.get(ident, v4.get(ident)) for ident in ids if ident in allowed and
                (ident in old or ident in v4)}, status
    except (OSError, ValueError, KeyError, CatalogError):
        return {}, "catalog_unavailable"


def card_technique_ids(card, principal_id):
    """Select IDs only from edges bound to the requested card principal."""
    ids = set()
    aggregates = set(card.get("member_of_aggregates") or [])
    for edge in card.get("outgoing") or []:
        if edge.get("source") == principal_id:
            ids.update(edge.get("techniques") or [])
    for edge in card.get("incoming") or []:
        target = edge.get("target")
        if target == principal_id or (target in aggregates and edge.get("via_aggregate") == target):
            ids.update(edge.get("techniques") or [])
    return sorted(ident for ident in ids if isinstance(ident, str))

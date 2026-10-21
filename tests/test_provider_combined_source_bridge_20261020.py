"""Real combined imports and exact, atomic, isolated admission tamper checks.

No source reader is virtualized. Each mutation runs against real bytes in a
bounded hardlink clone; atomic replacement never writes through shared inodes.
"""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared, _reverse
from tests.retained_upstream_manifest_20261020 import ORIGINAL as RETAINED_UPSTREAM_PATH, original_bytes as retained_upstream_bytes


ROOT = Path(__file__).resolve().parents[1]
BASE = "5c59608087204eff7216bb3798a4521d7f3442d5"
BASELINE = "tests/fixtures/provider_combined_bridge_baseline_20261020.json.gz"
BASELINE_SHA256 = "82799a2e0c366c80f3ec4d0626837fdf37ec0b38fc426d0ede565301df4c54a6"
GENERATED_CATALOGS = frozenset({
    "peaso/rulepacks/catalog_summary.json", "peaso/rulepacks/native_catalog.json",
})
# Release owner may pin the final reviewed network correction here. Retain its
# original baseline hash as before_sha256; after_sha256/after_size bind all new
# bytes. This explicit file allowlist cannot admit unrelated package changes.
REVIEWED_CURRENT_CHANGES = {'peaso/ai/auth.py': {'after_sha256': 'c1879bc238710478fea7fcebbe38200c2b6c601f14970765956d42f4b18d9658',
                      'after_size': 15391,
                      'before_sha256': '4698a34f11d32f5d61dfa62ed2abd82dbf7f484d7c88af3903ea59a0038ee9d9'},
 'peaso/ai/codex_relay_cli.py': {'after_sha256': 'a1e8c519b624ab30d131f1a4a070deb2eea8e780584a41b405f6212592539fb9',
                                 'after_size': 1571,
                                 'before_sha256': 'eb21e350afa98e319676e12b5b60dbe9b9ef516fbc203970267798a66e5d6aee'},
 'peaso/ai/fargate.py': {'after_sha256': '9b39ddbb3844744c81fff421ed643c912ab61339071700c69e01af8ad7ccb176',
                         'after_size': 9071,
                         'before_sha256': 'f619a772d49642fb32453f6b9c18038e7573ba0370671f7e43581fe507cf76c5'},
 'peaso/ai/model_relay.py': {'after_sha256': '38b983c2a628e0b8d67aff0c58cdc3dabf5569262386c3124edfbd26b760cb6a',
                             'after_size': 12638,
                             'before_sha256': 'c8ffb7196454a6b1214fe9a47deb014b3d1679a59855494a0069125ab4bf9c4a'},
 'peaso/ai/network.py': {'after_sha256': 'f8da3a90c6fbc0e2c2bb8fa40f2007bf45abdfa149b37c92d8b7b693f5ebd6fd',
                         'after_size': 14438,
                         'before_sha256': 'c7e43d252261d26b2ee9d6fa2a3cee79a344dd052bee2f959a98b2a624d8d024'},
 'peaso/ai/pipeline.py': {'after_sha256': '18a096311a1485e466313ca68093ac6030aca332f136f2bae751da1b23871ee1',
                          'after_size': 22934,
                          'before_sha256': 'cff1e0a4e346c407ddef53a3e3b984b9eed0ff965acb9fb54329bcdb6751aa56'},
 'peaso/ai/runner.py': {'after_sha256': '34283810a05c9f06cb4046a98fc8b2689c0e85c2beb019caa9e658132c4b0197',
                        'after_size': 6065,
                        'before_sha256': 'd789f8a65af278d089bd9eaf18dc88d2dfa348b67f4f2d486a6b51f0aae9b997'},
 'peaso/ai/task_runtime.py': {'after_sha256': '85d5cd47ca3a586fc623dbd008ac1279784ebcd43d57fe0e696f4748012cea91',
                              'after_size': 7439,
                              'before_sha256': '1a8fd2234bcd145f08683449c0748fdf2a7741fb01b1e412799f85991366c02f'},
 'peaso/analysis/common.py': {'after_sha256': '43f5f66f4ab5d99ea96fe122108ff04e2e8fe857c964bf755cdfe6d5772054d9',
                              'after_size': 13921,
                              'before_sha256': '3895ba27f4a153bfa6ed88dfef7d3628dfa1ec4786e4d319d29a0ca42981a656'},
 'peaso/attack_detection/aws_kinesis_video_controls_next.py': {'after_sha256': 'bd468a871700f24b6ef3dd967bfc64cb507e28b7da7649f9d2ac2ac4286ff549',
                                                               'after_size': 5861,
                                                               'before_sha256': '51cb1690457da6ec9cb370cf3c4c015504a382acaada0d15426e2ec127e5725b'},
 'peaso/attack_detection/rules.py': {'after_sha256': 'b5a0ad9c83769be0d22829ee9fa40fb7773bdeb1286a74c454aaf7949fc0823c',
                                     'after_size': 68840,
                                     'before_sha256': 'c65b53b8f01ecfca2e4dbfc15d31f72f5915002c7a4b137aefb6c6cdbccf00a9'},
 'peaso/checks/catalog.py': {'after_sha256': 'd13bf63e3f4071846ef27adb992711fea783ad410359901cfa531f928552391c',
                             'after_size': 29453,
                             'before_sha256': 'c24821bee09ad54f650825c43886bd69e9c7b3143b75f380fef370857fac4568'},
 'peaso/checks/claude_azure_data.py': {'after_sha256': 'e8fd6583fe2d61fd07a2001a3d91c1a7983998e0e76b33add898f8a097af377b',
                                       'after_size': 76299,
                                       'before_sha256': 'd4013488f1536f9be4425a690d3cb87ef73ae35c08e02b356d1ff1324c00d472'},
 'peaso/checks/gcp_artifact_file_secret_review_20261019.py': {'after_sha256': '83b18b9e43d88c7fa4271defd6cb9d1111e320814e7e4d8f191f010fba7ba0b2',
                                                              'after_size': 7137,
                                                              'before_sha256': '0fe7d4fcbcd953d913e2ffa1df5b08573f01c8527ff333d351ddd3e037b36e54'},
 'peaso/checks/gcp_composer_source_secret_review_20261019.py': {'after_sha256': '4d792063c7dfde93400aa5ca89c5637f978fbca645aae51aaba7e06ae7aa12b7',
                                                                'after_size': 10867,
                                                                'before_sha256': 'd176034b246ff2f901e767f52d3c02832ec192766f361e552852d579dd567027'},
 'peaso/checks/gcp_image_secret_review_20261019.py': {'after_sha256': '0c0e9e68f1a7a39457822e3f7a20195f21c1f61948efa5c4e6b3fa926872263b',
                                                      'after_size': 11222,
                                                      'before_sha256': '83fe957437bdb4a8142361bc4329af903dede65cb2e0242d2c35cda5211c79fd'},
 'peaso/checks/gcp_selected_archive_secret_review_20261019.py': {'after_sha256': 'cde1fe3ec267ef201f7b9fbe432dd2266b36164b3ee6e20fa55d589f77388cfb',
                                                                 'after_size': 7805,
                                                                 'before_sha256': 'd7636cee350ce0aa0c9fc32f3a71ef141f960050abb0757af082772a4f315a6a'},
 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py': {'after_sha256': '1edae1338a7f2a7f8b13e5939b4e33ad01c79c7fe3d80f634c69f5243d2664ac',
                                                           'after_size': 12892,
                                                           'before_sha256': 'f397ee93b511f396bb49fb467e05a88e23a741e492a22dcb93d9f8d99aded5d0'},
 'peaso/checks/gcp_task_routine_secret_review_20261020.py': {'after_sha256': '7deb55ddf182adade8f6f0e2beb52a019ed30e62908698de5758fef7b99fa63b',
                                                             'after_size': 10779,
                                                             'before_sha256': '18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1'},
 'peaso/cli.py': {'after_sha256': '2b18af259c1cfc16c43041a1f7f9a9d53c93d3bbd935af307c842acded98c879',
                  'after_size': 12643,
                  'before_sha256': '64abe6b8c5128ffb41e92811766d8e6b263e683172ce754875958745cbe6a312'},
 'peaso/collectors/aws_additional_secret_indicators.py': {'after_sha256': 'c48782094d4e06282f4780a87d5b39c10bae7a90a52202a3dc6f7ba49359b374',
                                                          'after_size': 17383,
                                                          'before_sha256': 'e2cfc9bcd839b1a7a803580b549b3d02d8a67757274551a0afc4130e5d184787'},
 'peaso/collectors/aws_code_log_content_indicators.py': {'after_sha256': '8ba57bd8059a161ce02880d1df899ae475853f0de29d9dfb021d3822938bac04',
                                                         'after_size': 19495,
                                                         'before_sha256': '06fd10cdc45542e15e31d4e735256fa62b3733c805dc5eb1865b7e3923013355'},
 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py': {'after_sha256': '70e9d13e572bc77bae366e7bbcadee51c5a2e32dcba9c87043385c7013a9081d',
                                                                  'after_size': 11526,
                                                                  'before_sha256': '50be001febf5a568b2b2ffbe7c295edafeb3f34a5e395a4bf29a6bc94f58b01f'},
 'peaso/collectors/aws_codebuild_buildspec_source_20261020.py': {'after_sha256': '13cec858770033e4383f91180c4b20246c8c0f82bdbf1ffaf7c9eee0eb7ab042',
                                                                 'after_size': 14859,
                                                                 'before_sha256': '4890d8a97cd86cdcee0df334956531432ae26ec2f6a1758f1ecb858e7f778bce'},
 'peaso/collectors/aws_configuration_payload_secret_indicators.py': {'after_sha256': '242735153eecd312bfdc4d71fb48f94384942f4a95d42b2a918310367b925518',
                                                                     'after_size': 17836,
                                                                     'before_sha256': 'eef6d7241cc5f09f9560c427fa9f336a636d1996130f0eb5b05d17377883fdc9'},
 'peaso/collectors/aws_configuration_secret_indicators.py': {'after_sha256': '5970679996f93e13ad9d277fcc63556bcbe55d52371c617bb6844200057dbd05',
                                                             'after_size': 9109,
                                                             'before_sha256': 'cbeb631ac665dea0c221a3ad370d21000b8c458a33072b4f0d5c855bedbc147c'},
 'peaso/collectors/aws_lambda_environment_secret_indicators.py': {'after_sha256': 'be67753315513908ffee54bc96c4e1252930e3a8b9925ab87490164fd5a50d77',
                                                                  'after_size': 12486,
                                                                  'before_sha256': '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289'},
 'peaso/collectors/aws_package_content_indicators.py': {'after_sha256': '080458323cb07d817fb6d4f05e4ab7edcfb525d889ecdbeea07cdc12c949de98',
                                                        'after_size': 30095,
                                                        'before_sha256': 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'},
 'peaso/collectors/aws_s3_selected_source_secret_indicators.py': {'after_sha256': '169b22ff5868cdeb773c722fd5736e62ab1df47718140536491394ff557fb4ec',
                                                                  'after_size': 29890,
                                                                  'before_sha256': 'b040a3b23746561fe913b1bd985669a0820fdde72b12fd864c5f6b5b894e3053'},
 'peaso/collectors/aws_selected_configuration_secret_indicators.py': {'after_sha256': '2b096e44245a2b7c849c6cae75cf61dba7ae89012bc476c5af919622f5afca12',
                                                                      'after_size': 38795,
                                                                      'before_sha256': 'c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f'},
 'peaso/collectors/aws_user_data_secret_indicators.py': {'after_sha256': '28eeada41f9d1b10d31ccd469e1eec85d38c53def87fd520b2556bd598ee5161',
                                                         'after_size': 2201,
                                                         'before_sha256': '077b5d258d6728c0b712935d34899c0feb27e3d11f758a81e793a6a240016205'},
 'peaso/collectors/aws_workload_command_runtime_20261020.py': {'after_sha256': '22252144a2f21c517684ec0f25f362abaa145196dd59f23c4606674b3d1acc5c',
                                                               'after_size': 6719,
                                                               'before_sha256': '9dc132a81388ee3b228b8b1de0820aefe9bfb741be37ea4c082920254e5c96b5'},
 'peaso/collectors/aws_workload_command_source_20261020.py': {'after_sha256': 'd35bb5bf1da25c53b5f83dfbcce34901234bb109c96520a042eed1b8ab5fc5f7',
                                                              'after_size': 22698,
                                                              'before_sha256': 'c5c5c24b7fbd4b696903d38b6e84a02ad3ebfa35616e6378a67afb97b8ae757e'},
 'peaso/collectors/azure.py': {'after_sha256': 'cf30eb3e844f7e927a542f529bf90ff694437a214f1d472358078721e299b6da',
                               'after_size': 243811,
                               'before_sha256': '22aa297159aeec7ab4a0645877bf69de4c8c8c645098ffe1d0dd05a56f0f8aac'},
 'peaso/collectors/azure_acr_image_secret_indicators.py': {'after_sha256': 'e7e9854b72c3bafbc3ed67de99989843bedff823ac1c986fb7e11636e58a9218',
                                                           'after_size': 24510,
                                                           'before_sha256': '8e9c55f0fcee045b9c283554e7e5908f8ef1aff5225bfd3eb6a4e037b1a0995d'},
 'peaso/collectors/azure_app_settings_secret_indicators.py': {'after_sha256': '9e5b349da018641ddf6f7835560eea29ab35f13b28e1b5884d00a9e65d576ada',
                                                              'after_size': 13959,
                                                              'before_sha256': 'f7fed346ff359f463e72cff63f4de9e1971e2aeef2223ed8b338c91c7520248b'},
 'peaso/collectors/azure_databricks_notebook_secret_indicators.py': {'after_sha256': '382723d26e0d056ecff56444cb56cb92a46514e78aaf82f1dcbccd462e7a5784',
                                                                     'after_size': 14586,
                                                                     'before_sha256': '6eed83bf1d6b6e8055dabb1c0cee052f1b7c636121c742e74b8727bc23b4b222'},
 'peaso/collectors/azure_devops_git_native.py': {'after_sha256': 'aa627a331825c3466c692ab79d46944d8f57c182ac4f7e5bc610ef5388157d9a',
                                                 'after_size': 10671,
                                                 'before_sha256': '7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63'},
 'peaso/collectors/azure_devops_selected_content_secret_indicators.py': {'after_sha256': '03035c9d97862a0788c2b9fd3fb23236e099ebe8f2d178ae67bb010fa7717039',
                                                                         'after_size': 19250,
                                                                         'before_sha256': '3def2355bfad985b1543022cc14443677dd6ed37928a4d1109eeffb741fb5434'},
 'peaso/collectors/azure_function_package_integration_20261020.py': {'after_sha256': '9eb8c15ad1052795777ae95960f7c65a8062d5555e2456a9c34a9f2aa6d1e58c',
                                                                     'after_size': 12770,
                                                                     'before_sha256': '678fc74f19156541992b9ce3536cf642253842b34583e6408005a4e38858c0e0'},
 'peaso/collectors/azure_ml_selected_asset_secret_indicators.py': {'after_sha256': '1e2b8c8189fdd191885fd35f9cd2371627d551f21f3e95689ae66b55a918e356',
                                                                   'after_size': 18781,
                                                                   'before_sha256': 'e5d98f9692035b60342526497ca70076a06cdafd3dbf8bfc0aa706ea70f2486f'},
 'peaso/collectors/azure_ml_selected_job_secret_indicators.py': {'after_sha256': '451bbcad17d229a45b2a1950760a3e7e52a83ed7c041de26d7bf7776de6ad80a',
                                                                 'after_size': 9349,
                                                                 'before_sha256': 'a0644628612d680fea88a9dcedca7541f1560278fc5d4ea116710739035143c3'},
 'peaso/collectors/azure_selected_configuration_secret_indicators.py': {'after_sha256': 'd118e7faa46d63114f369f13fdf26f2bc0e5c2a5d8d13e504fd19ea8c181645b',
                                                                        'after_size': 22090,
                                                                        'before_sha256': '570bf399805ef12cd647007d43ea450f1138244d58c4326972842c42281d7604'},
 'peaso/collectors/azure_selected_declaration_secret_indicators.py': {'after_sha256': '361844ed7f69dfa530d539e3e661d40cdb7e3f96a08aa1704b36f9b76d75ed18',
                                                                      'after_size': 22710,
                                                                      'before_sha256': '31b9a452cc530f4ceee89b1ca5b6892217eeea82d1699b9c86126e3fd9bdc6f2'},
 'peaso/collectors/azure_selected_log_sample_secret_indicators.py': {'after_sha256': '9734c02af422eabb3f1308cdc046713b05a3071d3d29eae3cdc1944d647d695e',
                                                                     'after_size': 17799,
                                                                     'before_sha256': 'fd07ef51f86ef4ed6889c62c532de732f69f7c76e568c08db6d39271094718f8'},
 'peaso/collectors/azure_selected_storage_secret_indicators.py': {'after_sha256': '4a090b1f8fe9da69de7e4aef9d467e01d421cc00febc0fc20ea978e1f1f00b63',
                                                                  'after_size': 23672,
                                                                  'before_sha256': '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda'},
 'peaso/collectors/gcp.py': {'after_sha256': '2e4f5c32cb1bf0627efbdd0621fb6b46d14026b8ab016a26a4b2f365ebcaec79',
                             'after_size': 256385,
                             'before_sha256': 'f7554a0e905d712242bfd2826866517bbc410b1a4aa9e3ef195c75c07df37e96'},
 'peaso/collectors/gcp_additional_literal_secret_indicators.py': {'after_sha256': 'bd38dd89cbbbd0238f700e074954eef741a18b4605d8511297ba73df1aa0fef9',
                                                                  'after_size': 28804,
                                                                  'before_sha256': '0bfb934509a3ae9cd00f826371bbc1d7a7999d755d62a2234f1da650cc9ca492'},
 'peaso/collectors/gcp_appengine_source_secret_indicators.py': {'after_sha256': '2dada521edbcf79f1bc3c007faab7dec39ca3265ac805e6a18f186ae8cae363e',
                                                                'after_size': 14228,
                                                                'before_sha256': '5f0dc6ceb82d853f10f4af47858504ae09b266e50800f49ecf8724238385ad61'},
 'peaso/collectors/gcp_artifact_file_secret_indicators.py': {'after_sha256': '13f050c19bca65f164cece4c3f12e4745181e815bcc12c93f94f09815328a897',
                                                             'after_size': 16769,
                                                             'before_sha256': '30606f70908536e1fd5a710ccd5f62d0fb953fa1eeac474341c7f38c01db2e5b'},
 'peaso/collectors/gcp_batch_referenced_source_20261020.py': {'after_sha256': 'f21abd85d0484b63210b3a595ce00f2f7a4b0e463437ac626b174e1bb0c104c8',
                                                              'after_size': 20423,
                                                              'before_sha256': 'c0bb32c6b0f8aaa0975ec3ed28875b2618ab8c2a674e16b41173e21ba4082921'},
 'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py': {'after_sha256': 'f38f6d25dd081129e3dca5fac87d9caa47c08c5ac7c4bd0c9cc9f5d1fa0045bb',
                                                                      'after_size': 20913,
                                                                      'before_sha256': '91e6118e969286fd577eea11c65f5f2129e4711604c45414f601fbeb71ed0f51'},
 'peaso/collectors/gcp_composer_source_secret_indicators.py': {'after_sha256': '1155223c7360cddb7c7276ffe0213c1e8c145daafe28b58ba44d9b41f23ad9a8',
                                                               'after_size': 16488,
                                                               'before_sha256': 'fbe60d18f2ec81fd014ed8b1650daf194f49166324c01e0d5d9ab09c4f062257'},
 'peaso/collectors/gcp_configuration_secret_indicators.py': {'after_sha256': 'fece1e1e725f899dc06f7d257e97a5cf018b27f4915524289d398832d4e8969b',
                                                             'after_size': 16968,
                                                             'before_sha256': '8c573da30b8bf20c1dfa88d450e44caf0935aa68f831fef941ef58f832901549'},
 'peaso/collectors/gcp_dataflow_referenced_source_20261020.py': {'after_sha256': '5d65bcbaf0577eab70db510199972ce56446bd3026a56f06590b9bee53909c34',
                                                                 'after_size': 20783,
                                                                 'before_sha256': 'c638e6ad782b475e9d6bc2ee93aed1bc57da67281bbb53ffa364935f84c6ad59'},
 'peaso/collectors/gcp_dataform_secret_indicators.py': {'after_sha256': '05f69411648c3b5c43440259247da31501c3baaf533fd37318045cd645e15415',
                                                        'after_size': 18424,
                                                        'before_sha256': 'ca02f4a3025442421b25433a7930f157cb9ffd01295c8a07b8dce1d8a9428a70'},
 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py': {'after_sha256': '7c53b1687a6b7ff89a066b63d31cab226354a0ec76b346e77bb49442e0885e36',
                                                                          'after_size': 24100,
                                                                          'before_sha256': '75f3bb777dd00bb154f24de0f459994fefbced29262c91ec17967618f54801f0'},
 'peaso/collectors/gcp_function_secret_indicators.py': {'after_sha256': '3f0fd85858c2c29d76740539a3aef5c7d022e4b52b19398581b8d535fd7be7fe',
                                                        'after_size': 9357,
                                                        'before_sha256': 'f0107e484b39ca361710b0c838c07eb861fe8701239f79e91b41230a211b58c3'},
 'peaso/collectors/gcp_function_secret_pairs_20261020.py': {'after_sha256': '31237ce04804acc4a82923b5a0e4fb0a02d2246cb8a03ef15a364e576df31c9c',
                                                            'after_size': 9769,
                                                            'before_sha256': 'e6f344088f0fbbbb50ff782852495cc9c23a874448e9b732543027e01e068598'},
 'peaso/collectors/gcp_gke_literal_secret_indicators.py': {'after_sha256': 'd1fb79749be2e5731ff14f99285e600756772275ce3f2e47e9924af92795399b',
                                                           'after_size': 31424,
                                                           'before_sha256': '9939b98e6393d33fc105d9f1f6ece556f697d19a69f6064149fcbbc0b52a3def'},
 'peaso/collectors/gcp_image_secret_indicators.py': {'after_sha256': '2efa213d7f585588539816b337706391dfe7de244cf211462c7e363ec75aa778',
                                                     'after_size': 23017,
                                                     'before_sha256': '7891365e7a5ecd82734dd385d1ed64b56b11e1283e07dc2f3b9e16cbee2e104e'},
 'peaso/collectors/gcp_job_literal_secret_indicators.py': {'after_sha256': 'b0c3dbd8efbd003c03d3b4b67b87e74601b17698ee38303fa1eee1312c52c961',
                                                           'after_size': 28633,
                                                           'before_sha256': 'afe4305155c2350cab0faa3f00d8a2a1431de0d23f890fe3780075abd77c8055'},
 'peaso/collectors/gcp_log_secret_indicators.py': {'after_sha256': '742707093416635c370b49b5f4d4ceb7aa6ead869a7d3748e1ee3698a4ab8268',
                                                   'after_size': 16108,
                                                   'before_sha256': '7600114140eef746787981f73b18b47910c0d82797662050f2a6944306b7b161'},
 'peaso/collectors/gcp_notebook_airflow_secret_indicators.py': {'after_sha256': '8317f2883f819d07d88b05a5714e119a241c3f0a2200a9d54e47ba24d8f28684',
                                                                'after_size': 12331,
                                                                'before_sha256': '70d808587cca4847f5979f7ed9eb6452b6f332c6996d68157c7af00cf3278118'},
 'peaso/collectors/gcp_selected_archive_secret_indicators.py': {'after_sha256': '686b2922de3447d6fe91a76071e56f9d57df169253ab45b24124df2cd1aa5675',
                                                                'after_size': 11881,
                                                                'before_sha256': '5da0da030a5d7be256956f7126f5a8b5aaed8c552b49185a8d6ed7d4e1badd23'},
 'peaso/collectors/gcp_selected_object_secret_indicators.py': {'after_sha256': '9d9aa19b15499e3eb9c69add0610e014b9be8f1e4997403cdc6ad70818260339',
                                                               'after_size': 15166,
                                                               'before_sha256': 'fb9d1c2837660501bd87ab9642519f4caadfc395eee3193d1ccefd1bb2517959'},
 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py': {'after_sha256': 'a8f794d8b1cedcdc8d45e11d4c6f4bc7ca62c649e753d4abe5342e99d77e1ec6',
                                                                     'after_size': 16107,
                                                                     'before_sha256': 'b424bf05b428b54914baad891b272151351284c630b62c72d3ae1c826ccf8530'},
 'peaso/collectors/gcp_sourcerepo_secret_indicators.py': {'after_sha256': 'b885ce15301a12cfcbb9dcb9fdc9b22358af706f961c4c3c69110ac543af3dde',
                                                          'after_size': 16156,
                                                          'before_sha256': '34f0c7eaf42626d7da2bbeac98ce912e792000aa28e42bea91c6fbc3f0591069'},
 'peaso/collectors/gcp_workbench_referenced_source_20261020.py': {'after_sha256': '0362bb137ea6b0dfb1d5479e67e83b4478f10fa31d35bc41f22086806c5c76aa',
                                                                  'after_size': 24683,
                                                                  'before_sha256': '3c8a3b4dcaf51c6f1544dd1d4465d8a60c00ec1d605a3d808e7590b0ce219b73'},
 'peaso/collectors/k8s.py': {'after_sha256': '3dd3f487e84101f7f72c164e817e95ff8b3e4e5296cde2dbd102f01f96c5cf18',
                             'after_size': 124878,
                             'before_sha256': '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1'},
 'peaso/collectors/k8s_literal_secret_indicators.py': {'after_sha256': '81a720ec705b5ab461c93ca8db6df00314d74fbd797cdf48e9305553c0f2fc3b',
                                                       'after_size': 22303,
                                                       'before_sha256': '1ee91c6b52cf142d30ef58f55dd11f8e1688d129791c869a1a6783e7a80aa47b'},
 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py': {'after_sha256': 'c9c3923d34f35347097d1d7a9c4cc83d8755a0b3c7d7b7dfb059684c9cebd7e3',
                                                                   'after_size': 25274,
                                                                   'before_sha256': '0fe2d51cb83f4126994f1bfaf1eff50c96469c3b1e285c44d78825f48328e9c0'},
 'peaso/secret_scanning.py': {'after_sha256': '853c402c0362565849c43cbd89cc82d1e5e8b1b5d8d25f6cc15706a48de6f55f',
                              'after_size': 17202,
                              'before_sha256': '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'},
 'peaso/server/app.py': {'after_sha256': '643ac70408126d6e8a978808fefa224754fd248284785b6c5120fb3483a5a388',
                         'after_size': 126331,
                         'before_sha256': '5f2b3dc9bb6f54c56502b22263973c6d1c6f0932af703317d46008dd11732707'},
 'peaso/storage/artifacts.py': {'after_sha256': 'fbeb7402aedd7ac2a252682db02b97957760e2e70e3a4344bec8eb93f3d5b497',
                                'after_size': 8651,
                                'before_sha256': 'de542a6dde456cf0975aa8bd61240933cbdefd2b83a600e3fe9a963c100c549e'},
 'peaso/storage/reports.py': {'after_sha256': '6fffe43fcfa36590d40826d70f97fbc2f5d6d379a813f293d4947d1a6a8b862c',
                              'after_size': 11056,
                              'before_sha256': '2416214b3021e55883fdf8ba1108f90a98f81f1192899b9806e43001eeb4e166'},
 'peaso/storage/runtime.py': {'after_sha256': '980fd107b762399ee3eb13968360e46d547c8a05d78e7ac81b8597312f08710e',
                              'after_size': 2097,
                              'before_sha256': '4a52941e15925e48296da78e3a8386a58a60de5bfb0ad0119d66a397886a2214'},
 'peaso/worker.py': {'after_sha256': '438b994eda0a1d75fc9fef362df7441b34cc66531722e8d1d70c6606331dc337',
                     'after_size': 22028,
                     'before_sha256': '9c1e6d558aad8804996fef249ad3836d39498a23121436aab69cbe0a52384bb0'}}
REVIEWABLE_CURRENT_PATHS = frozenset(['peaso/ai/auth.py', 'peaso/ai/codex_relay_cli.py', 'peaso/ai/fargate.py', 'peaso/ai/model_relay.py', 'peaso/ai/network.py', 'peaso/ai/pipeline.py', 'peaso/ai/runner.py', 'peaso/ai/task_runtime.py', 'peaso/analysis/common.py', 'peaso/attack_detection/aws_kinesis_video_controls_next.py', 'peaso/attack_detection/rules.py', 'peaso/checks/catalog.py', 'peaso/checks/claude_azure_data.py', 'peaso/checks/gcp_artifact_file_secret_review_20261019.py', 'peaso/checks/gcp_composer_source_secret_review_20261019.py', 'peaso/checks/gcp_image_secret_review_20261019.py', 'peaso/checks/gcp_selected_archive_secret_review_20261019.py', 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py', 'peaso/checks/gcp_task_routine_secret_review_20261020.py', 'peaso/cli.py', 'peaso/collectors/aws_additional_secret_indicators.py', 'peaso/collectors/aws_code_log_content_indicators.py', 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py', 'peaso/collectors/aws_codebuild_buildspec_source_20261020.py', 'peaso/collectors/aws_configuration_payload_secret_indicators.py', 'peaso/collectors/aws_configuration_secret_indicators.py', 'peaso/collectors/aws_lambda_environment_secret_indicators.py', 'peaso/collectors/aws_package_content_indicators.py', 'peaso/collectors/aws_s3_selected_source_secret_indicators.py', 'peaso/collectors/aws_selected_configuration_secret_indicators.py', 'peaso/collectors/aws_user_data_secret_indicators.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/aws_workload_command_source_20261020.py', 'peaso/collectors/azure.py', 'peaso/collectors/azure_acr_image_secret_indicators.py', 'peaso/collectors/azure_app_settings_secret_indicators.py', 'peaso/collectors/azure_databricks_notebook_secret_indicators.py', 'peaso/collectors/azure_devops_git_native.py', 'peaso/collectors/azure_devops_selected_content_secret_indicators.py', 'peaso/collectors/azure_function_package_integration_20261020.py', 'peaso/collectors/azure_ml_selected_asset_secret_indicators.py', 'peaso/collectors/azure_ml_selected_job_secret_indicators.py', 'peaso/collectors/azure_selected_configuration_secret_indicators.py', 'peaso/collectors/azure_selected_declaration_secret_indicators.py', 'peaso/collectors/azure_selected_log_sample_secret_indicators.py', 'peaso/collectors/azure_selected_storage_secret_indicators.py', 'peaso/collectors/gcp.py', 'peaso/collectors/gcp_additional_literal_secret_indicators.py', 'peaso/collectors/gcp_appengine_source_secret_indicators.py', 'peaso/collectors/gcp_artifact_file_secret_indicators.py', 'peaso/collectors/gcp_batch_referenced_source_20261020.py', 'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py', 'peaso/collectors/gcp_composer_source_secret_indicators.py', 'peaso/collectors/gcp_configuration_secret_indicators.py', 'peaso/collectors/gcp_dataflow_referenced_source_20261020.py', 'peaso/collectors/gcp_dataform_secret_indicators.py', 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py', 'peaso/collectors/gcp_function_secret_indicators.py', 'peaso/collectors/gcp_function_secret_pairs_20261020.py', 'peaso/collectors/gcp_gke_literal_secret_indicators.py', 'peaso/collectors/gcp_image_secret_indicators.py', 'peaso/collectors/gcp_job_literal_secret_indicators.py', 'peaso/collectors/gcp_log_secret_indicators.py', 'peaso/collectors/gcp_notebook_airflow_secret_indicators.py', 'peaso/collectors/gcp_selected_archive_secret_indicators.py', 'peaso/collectors/gcp_selected_object_secret_indicators.py', 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py', 'peaso/collectors/gcp_sourcerepo_secret_indicators.py', 'peaso/collectors/gcp_workbench_referenced_source_20261020.py', 'peaso/collectors/k8s.py', 'peaso/collectors/k8s_literal_secret_indicators.py', 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py', 'peaso/secret_scanning.py', 'peaso/server/app.py', 'peaso/storage/artifacts.py', 'peaso/storage/reports.py', 'peaso/storage/runtime.py', 'peaso/worker.py'])
INITIALIZER_ADDITION = (
    b"from . import native_admission_cpu_shared_successor_20261020 as _deployed_ai_shared_source\n"
    b"_historical_aws_workload_command_shared_successor_20261020 = aws_workload_command_shared_successor_20261020\n"
    b"aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source\n"
)
HELPER = "peaso/checks/native_admission_cpu_shared_successor_20261020.py"
RECEIPT = HELPER.removesuffix(".py") + ".json"
BRIDGE_IMPORT = "from tests.shared_admission_epoch_compatibility_20261020 import active_shared\nbridge = active_shared()\n"
NATIVE_IDS = {
    "aws.review.workload.selected_command_literal_secret_indicators",
    "gcp.review.cloudrun_job.declared_image_secret_indicators",
}



def _pinned_proof(name, expected):
    raw = (ROOT / 'peaso/checks' / (name + '.json')).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, 'Source-proof receipt changed: ' + name
    return json.loads(raw)


def cpu_receipt():
    """The unchanged canonical CPU proof remains independently testable."""
    return _pinned_proof('native_admission_cpu_shared_successor_20261020',
                         '82c57ad2963785be4ddc5cbb4f029afe19a416800ea5beed748693aa6324fcc8')


def cpu_epoch_bytes(relative, raw):
    """Two finite signed layers, followed by the original CPU source assertions."""
    if relative not in {'peaso/checks/__init__.py', 'peaso/collectors/azure.py'}:
        return raw
    if relative == 'peaso/checks/__init__.py':
        from tests.gcp_positive_conservation_epoch_20261020 import metadata_initializer_bytes
        raw = metadata_initializer_bytes(raw)
    layers = (
        ('azure_metadata_only_shared_successor_20261020',
         '12bf2cd88f943bcb3cdb91a3701cd3197e78d6ba7ed7e956afd854d6d1b292ed',
         'metadata_only_epoch_file_deltas'),
        ('collector_noop_authorization_shared_successor_20261020',
         '7ed26b39498462397e5b02b74552d91336d53f07ea70636d8b0655164f90dafa',
         'native_epoch_file_deltas'))
    for name, expected, section in layers:
        proof = _pinned_proof(name, expected)
        if relative in proof[section]:
            row = proof[section][relative]
            if hashlib.sha256(raw).hexdigest() == row['current_sha256']:
                raw = _reverse(raw.decode(), row).encode()
    expected = cpu_receipt()['integration_file_deltas'][relative]['current_sha256']
    assert hashlib.sha256(raw).hexdigest() == expected, relative
    return raw

def run(code, root=ROOT):
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root),
                       AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE="/nonexistent/bridge-proof",
                       AWS_SHARED_CREDENTIALS_FILE="/nonexistent/bridge-proof")
    return subprocess.run([sys.executable, "-B", "-c", code], cwd=root, env=environment,
                          capture_output=True, text=True, timeout=90)


def green(result):
    assert result.returncode == 0, result.stderr[-9000:]
    return json.loads(result.stdout)


def rejected(result):
    assert result.returncode != 0, "Tampered real source unexpectedly admitted: " + result.stdout
    # Refusal must be an admission/identity failure, not a missing clone input.
    assert "RuntimeError:" in result.stderr, result.stderr[-9000:]
    assert "FileNotFoundError" not in result.stderr and "ModuleNotFoundError" not in result.stderr, result.stderr[-9000:]


@pytest.fixture(scope="module")
def isolated(tmp_path_factory):
    target = tmp_path_factory.mktemp("provider-bridge-hardlinks")
    paths = (subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
             if (ROOT / ".git").exists() else
             [str(path.relative_to(ROOT)) for directory in ("peaso", "tests", "docs", "scripts", "risk_rules", "bluepeass")
              for path in (ROOT / directory).rglob("*") if path.is_file()
              and "__pycache__" not in path.parts and path.suffix != ".pyc"])
    allowed = {"peaso", "tests", "docs", "scripts", "risk_rules", "bluepeass"}
    paths = [p for p in paths if p and p.split("/", 1)[0] in allowed]
    # Git does not list the separately admitted current overlay. Copy its
    # exact receipt-attested source closure alongside the historical package.
    current = _pinned_proof('azure_metadata_only_shared_successor_20261020',
                            '12bf2cd88f943bcb3cdb91a3701cd3197e78d6ba7ed7e956afd854d6d1b292ed')
    closure = set(current['sources']) | {row['path'] for row in current['functions'].values()}
    closure |= {'peaso/checks/azure_metadata_only_shared_successor_20261020.json',
                'peaso/checks/collector_noop_authorization_shared_successor_20261020.json',
                'tests/shared_admission_epoch_compatibility_20261020.py'}
    for name in tuple(closure):
        companion = name.removesuffix('.py') + '.json'
        if name.startswith('peaso/checks/') and name.endswith('.py') and (ROOT / companion).exists():
            closure.add(companion)
    paths = sorted(set(paths) | closure | {HELPER, RECEIPT, BASELINE, "peaso/checks/aws_deployed_ai_shared_successor_20261020.py", "peaso/checks/aws_deployed_ai_shared_successor_20261020.json"})
    assert len(paths) < 6000
    assert sum((ROOT / p).stat().st_size for p in paths) < 600 * 1024 * 1024
    for name in paths:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.link(ROOT / name, destination)
    # Confirm this is the real cloned package, with a successful cold import
    # before any negative proof can be attributed to tampering.
    result = green(run("from pathlib import Path\nfrom peaso.engine import get_catalog\nimport peaso,json\n"
                       "catalog=get_catalog()\nprint(json.dumps({'root':str(Path(peaso.__file__).resolve().parent.parent), 'count':len(catalog['checks'])}))", target))
    assert Path(result["root"]) == target and result["count"] > 1000
    try:
        yield target
    finally:
        shutil.rmtree(target)


@contextmanager
def atomic_change(root, name, changed):
    path = root / name
    before = path.read_bytes()
    source_before = (ROOT / name).read_bytes()
    temporary = path.with_name(path.name + ".bridge-test-atomic")
    try:
        temporary.write_bytes(changed)
        os.replace(temporary, path)
        assert (ROOT / name).read_bytes() == source_before
        yield
    finally:
        temporary.write_bytes(before)
        os.replace(temporary, path)
        assert (ROOT / name).read_bytes() == source_before


def test_catalog_native_registrations_and_deployed_ai_corrections_import_for_real():
    value = green(run("""
import importlib, inspect, json
from peaso.engine import get_catalog
catalog=get_catalog()
from peaso import checks
from peaso.checks import native_admission_cpu_shared_successor_20261020 as canonical_cpu
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge = active_shared()
assert bridge.accepted_native is canonical_cpu
from peaso.checks import aws_ai_recheck_corrections_20261020 as ai
from peaso.checks import aws_workload_command_runtime_consumer_20261020 as command
from peaso.checks import gcp_cloudrun_job_image_secret_review_20261020 as job
from peaso.collectors import aws
registered={c.id:c for c in checks.CHECKS}
assert inspect.unwrap(registered[command.runtime.CHECK].evaluate) is command.evaluate
assert inspect.unwrap(registered[job.CHECK_ID].evaluate) is job.evaluate
for cid in ai.IDS:
    assert registered[cid].evaluate.__code__.co_filename.endswith('aws_ai_recheck_corrections_20261020.py'), cid
canonical=importlib.import_module('peaso.checks.aws_workload_command_shared_successor_20261020')
assert bridge.historical is canonical
assert checks.aws_workload_command_shared_successor_20261020 is bridge
for qualified, fn in bridge._HISTORICAL_FUNCTIONS.items():
    assert getattr(canonical, qualified.split(':')[1]) is fn
bridge.reviewed_inputs(); bridge.s3_reviewed_inputs()
assert 'peaso.collectors.aws_ai_recheck_facts_20261020' in aws.EXTENSION_MODULES
print(json.dumps({'ids':[c['id'] for c in catalog['checks']], 'historical_functions':len(bridge._HISTORICAL_FUNCTIONS)}))
"""))
    assert NATIVE_IDS <= set(value["ids"]) and value["historical_functions"] > 5


def pinned_baseline(raw=None):
    """Retain the complete base package manifest without Git object availability."""
    raw = (ROOT / BASELINE).read_bytes() if raw is None else raw
    assert hashlib.sha256(raw).hexdigest() == BASELINE_SHA256, "Historical baseline fixture changed"
    value = json.loads(gzip.decompress(raw))
    assert value["schema"] == 1 and value["base_commit"] == BASE
    assert len(value["files"]) == 1818
    initializer = value["initializer"].encode()
    row = value["files"]["peaso/checks/__init__.py"]
    assert len(initializer) == row["size"] and hashlib.sha256(initializer).hexdigest() == row["sha256"]
    assert GENERATED_CATALOGS <= value["files"].keys()
    return value


def verify_historical_bytes(root=ROOT, baseline=None):
    baseline = pinned_baseline() if baseline is None else baseline
    assert REVIEWED_CURRENT_CHANGES.keys() <= REVIEWABLE_CURRENT_PATHS
    for name, change in REVIEWED_CURRENT_CHANGES.items():
        assert change.keys() == {"before_sha256", "after_sha256", "after_size"}, name
        assert change["before_sha256"] == baseline["files"][name]["sha256"], name
        assert change["after_sha256"] != change["before_sha256"], name
        assert len(change["after_sha256"]) == 64 and all(c in "0123456789abcdef" for c in change["after_sha256"]), name
        assert type(change["after_size"]) is int and change["after_size"] > 0, name
    for name, row in baseline["files"].items():
        if name in GENERATED_CATALOGS or name == "peaso/checks/__init__.py":
            continue
        raw = retained_upstream_bytes(root) if name == RETAINED_UPSTREAM_PATH else (root / name).read_bytes()
        if name in REVIEWED_CURRENT_CHANGES:
            change = REVIEWED_CURRENT_CHANGES[name]
            assert len(raw) == change["after_size"] and hashlib.sha256(raw).hexdigest() == change["after_sha256"], name
            continue
        assert len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"], name
    # Only the exact three-line alias may differ from the pinned initializer.
    initializer = cpu_epoch_bytes("peaso/checks/__init__.py", (root / "peaso/checks/__init__.py").read_bytes())
    assert initializer.count(INITIALIZER_ADDITION) == 1
    assert initializer.replace(INITIALIZER_ADDITION, b"", 1) == baseline["initializer"].encode()


def verify_generated_catalogs(root=ROOT):
    # Render from the real registry in a cold subprocess. Comparing hashes of
    # complete payloads is exact byte verification, not a JSON subset check.
    value = green(run("""
import hashlib,json
from scripts.peaso_compliance_materialize import ROOT,render_documents
outputs=render_documents()
print(json.dumps({str(path.relative_to(ROOT)):hashlib.sha256(raw).hexdigest()
                  for path,raw in outputs.items()}))
""", root))
    assert GENERATED_CATALOGS <= value.keys()
    for name in GENERATED_CATALOGS:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == value[name], name


def test_every_historical_package_byte_is_unchanged_against_combined_base(monkeypatch):
    # A shallow checkout need not contain BASE. No baseline Git commands may run.
    def forbidden_git(*args, **kwargs):
        raise AssertionError("Conservation must not require Git history")
    monkeypatch.setattr(subprocess, "check_output", forbidden_git)
    verify_historical_bytes()
    verify_generated_catalogs()


def test_portable_baseline_cannot_be_replaced():
    raw = (ROOT / BASELINE).read_bytes()
    with pytest.raises(AssertionError, match="Historical baseline fixture changed"):
        pinned_baseline(raw + b" ")


@pytest.mark.parametrize("name", [
    "peaso/checks/aws_workload_command_shared_successor_20261020.py",
    "peaso/checks/aws_workload_command_runtime_admission_20261020.json",
    "peaso/checks/__init__.py", "peaso/rulepacks/runtime_metadata.json",
])
def test_portable_conservation_rejects_historical_changes(isolated, name):
    with atomic_change(isolated, name, (isolated / name).read_bytes() + b"\n "):
        with pytest.raises(AssertionError):
            verify_historical_bytes(isolated)


@pytest.fixture(scope="module")
def historical_tree(tmp_path_factory):
    target = tmp_path_factory.mktemp("provider-historical-bytes")
    for name in pinned_baseline()["files"]:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.link(ROOT / name, destination)
    try:
        yield target
    finally:
        shutil.rmtree(target)


def test_exact_reviewed_app_successor_keeps_original_hash_and_rejects_other_bytes(historical_tree, monkeypatch):
    isolated = historical_tree
    name = "peaso/ai/network.py"
    before = (isolated / name).read_bytes()
    original_digest = pinned_baseline()["files"][name]["sha256"]
    after = before + b"\n# Exact synthetic reviewed app correction witness.\n"
    row = {"before_sha256": original_digest,
           "after_sha256": hashlib.sha256(after).hexdigest(), "after_size": len(after)}
    monkeypatch.setitem(REVIEWED_CURRENT_CHANGES, name, row)
    with atomic_change(isolated, name, after):
        verify_historical_bytes(isolated)
    with atomic_change(isolated, name, after + b" "):
        with pytest.raises(AssertionError, match=name):
            verify_historical_bytes(isolated)
    monkeypatch.setitem(row, "before_sha256", "0" * 64)
    with pytest.raises(AssertionError, match=name):
        verify_historical_bytes(isolated)


def test_reviewed_app_map_cannot_exempt_historical_guards(historical_tree, monkeypatch):
    isolated = historical_tree
    monkeypatch.setitem(REVIEWED_CURRENT_CHANGES, HELPER, {})
    with pytest.raises(AssertionError):
        verify_historical_bytes(isolated)


@pytest.mark.parametrize("name", sorted(GENERATED_CATALOGS))
def test_generated_catalog_exceptions_require_exact_materialization(isolated, name):
    with atomic_change(isolated, name, (isolated / name).read_bytes() + b"\n "):
        # Semantically identical JSON still cannot bypass exact materialization.
        with pytest.raises(AssertionError, match=name):
            verify_generated_catalogs(isolated)


def test_exact_additions_and_replacements_reconstruct_the_whole_historical_epoch():
    active_shared().reviewed_delta(ROOT)
    receipt = cpu_receipt()
    assert set(receipt["integration_file_deltas"]) == {
        "peaso/checks/__init__.py", "peaso/collectors/aws.py", "peaso/engine.py", "peaso/collectors/aws_facts_swc.py", "peaso/collectors/azure.py"}
    for name, row in receipt["integration_file_deltas"].items():
        current = cpu_epoch_bytes(name, (ROOT / name).read_bytes()).decode()
        assert hashlib.sha256(current.encode()).hexdigest() == row["current_sha256"]
        for before, after in row.get("exact_replacements", []):
            assert current.count(after) == 1
            current = current.replace(after, before, 1)
        for addition in row["exact_additions"]:
            assert current.count(addition) == 1
            current = current.replace(addition, "", 1)
        assert hashlib.sha256(current.encode()).hexdigest() == row["predecessor_sha256"]
    swc = receipt["integration_file_deltas"]["peaso/collectors/aws_facts_swc.py"]
    assert swc["exact_replacements"] == [[
        '    item["Targets"] = _list(read, ["Id", "Arn"])\n',
        '    item["Targets"] = _list(read, ["Id", "Arn", "DeadLetterConfig"])\n']]


@pytest.mark.parametrize("name", [
    "peaso/collectors/aws.py", "peaso/engine.py", "peaso/collectors/aws_facts_swc.py",
    "peaso/collectors/gcp.py", "peaso/checks/aws_ai_recheck_corrections_20261020.py",
    "peaso/checks/aws_workload_command_shared_successor_20261020.py",
    "peaso/checks/aws_workload_command_runtime_admission_20261020.json",
    "peaso/collectors/azure.py",
    "peaso/checks/aws_deployed_ai_shared_successor_20261020.py",
    "peaso/checks/aws_deployed_ai_shared_successor_20261020.json", HELPER, RECEIPT,
])
def test_real_unrelated_edits_and_historical_or_bridge_tamper_are_rejected(isolated, name):
    before = (isolated / name).read_bytes()
    # JSON whitespace is semantic no-op but must still violate byte attestation.
    changed = before + (b"\n " if name.endswith(".json") else b"\n# unrelated source edit\n")
    with atomic_change(isolated, name, changed):
        rejected(run(BRIDGE_IMPORT + "bridge.reviewed_delta()", isolated))


@pytest.mark.parametrize("name,before,after", [
    ("peaso/collectors/aws.py", "'ebs_optimization_facts_requested', 'sqs_dead_letter_sources_requested'", "'ebs_optimization_facts_requested', 'changed_dead_letter_sources_requested'"),
    ("peaso/engine.py", "['_ebs_optimization_facts_requested']", "['_wrong_optimization_facts_requested']"),
    ("peaso/collectors/aws.py", 'EXTENSION_MODULES += ("peaso.collectors.aws_ai_recheck_facts_20261020",)\n', ""),
    ("peaso/collectors/aws_facts_swc.py", '["Id", "Arn", "DeadLetterConfig"]', '["Id", "Arn"]'),
])
def test_missing_or_changed_deployed_flags_extensions_and_replacements_fail(isolated, name, before, after):
    value = (isolated / name).read_text()
    assert value.count(before) == 1
    with atomic_change(isolated, name, value.replace(before, after, 1).encode()):
        rejected(run(BRIDGE_IMPORT + "bridge.reviewed_inputs()", isolated))


@pytest.mark.parametrize("owner,name,mode", [
    ("peaso.collectors.aws", "collect", "identity"),
    ("peaso.collectors.aws", "collect", "code"),
    ("peaso.collectors.aws", "_safe", "identity"),
    ("peaso.collectors.aws", "_safe", "code"),
    ("peaso.checks.aws_workload_command_shared_successor_20261020", "reviewed_delta", "identity"),
    ("peaso.checks.native_admission_cpu_shared_successor_20261020", "reviewed_delta", "code"),
])
def test_executing_callable_identity_and_code_replacements_fail(owner, name, mode):
    # The positive import is real. Only the negative attempt changes runtime
    # state, in its own subprocess, with no source readers mocked or replaced.
    script = BRIDGE_IMPORT + f"""
import importlib
owner=importlib.import_module({owner!r})
function=getattr(owner,{name!r})
if {mode!r} == 'identity':
    setattr(owner,{name!r},lambda *args,**kwargs: None)
else:
    # Use real file-backed code so 3.12 inspect reaches the admission guard.
    function.__code__=bridge._reverse.__code__
bridge.reviewed_inputs()
"""
    rejected(run(script))


def test_bridge_alias_must_precede_first_shared_installer(isolated):
    name = "peaso/checks/__init__.py"
    value = (isolated / name).read_text()
    alias = "aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source"
    first = "aws_workload_command_shared_successor_20261020.install_s3()"
    assert value.count(alias) == 1 and value.index(alias) < value.index(first)
    changed = value.replace(alias, "# delayed bridge alias", 1).replace(first, first + "\n" + alias, 1)
    with atomic_change(isolated, name, changed.encode()):
        rejected(run("from peaso.engine import get_catalog\nget_catalog()", isolated))


@pytest.mark.parametrize('relative', [
    'peaso/checks/__init__.py', 'peaso/collectors/azure.py'])
def test_finite_cpu_epoch_reversals_reject_unknown_current_source_bytes(relative):
    raw = (ROOT / relative).read_bytes()
    cpu_epoch_bytes(relative, raw)
    with pytest.raises(AssertionError, match=relative):
        cpu_epoch_bytes(relative, raw + b'\n# unreviewed source proof bytes\n')

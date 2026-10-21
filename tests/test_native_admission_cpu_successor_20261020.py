"""Full frozen epoch, exact current admission and signed source-cache proof."""
from copy import deepcopy
import gzip, hashlib, importlib, inspect, json, linecache, os, pathlib, shutil, socket, subprocess, sys, types
import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
from tests.test_provider_combined_source_bridge_20261020 import cpu_epoch_bytes, cpu_receipt
from tests.retained_upstream_manifest_20261020 import ORIGINAL as RETAINED_UPSTREAM_PATH, original_bytes as retained_upstream_bytes
from peaso.checks import native_admission_cpu_shared_successor_20261020 as bridge
from peaso.checks import azure_function_package_callable_cpu_successor_20261020 as package
from peaso import checks
SOURCE=pathlib.Path(__file__).resolve().parents[1]
EPOCH='tests/fixtures/native_admission_cpu_predecessor_epoch_20261020.json.gz'
EPOCH_SHA256='0e05bc9cad9da6947c2054107d8d49bc1a1b4777a740f3a0b7fc0b6bd6a83192'
# Integration may add only exact reviewed successor bytes here; before hashes
# must always retain the immutable predecessor epoch.
REVIEWED_CURRENT_CHANGES = {'.github/workflows/tests.yml': {'after_sha256': 'a39b069c4a723fb08f08a3efee046a51e9b44fd4e8e33a41b7135a0da571ed78',
                                 'after_size': 9340,
                                 'before_sha256': '9037ba9dac836655384bbb0d19370609cfd16098f314cf49c8634ab560bec2eb'},
 'Dockerfile.peaso': {'after_sha256': '1b9d1750fc298de3be684cf25928d2299e8abe7eaa10256641b0a88901167221',
                      'after_size': 3269,
                      'before_sha256': '40fc0168fd51321bfee2e846dcbd25e87fc93dec9a8c4b410b466de449d7d2ba'},
 'docs/ai-review/README.md': {'after_sha256': '89e4f520d67915fd26a06d9e9a3b33a3745371e362026c28c0e43983a292a394',
                              'after_size': 32632,
                              'before_sha256': '20f1efc520acf6e2e5bab25250ba14b406ff5cf27a2520e8b4cb732890b735c8'},
 'docs/aws-review/field-producers.json': {'after_sha256': 'd53d256e0ab705f82d08970fc9feefedde002d87f9e162a296ecc7fb052d7767',
                                          'after_size': 13554725,
                                          'before_sha256': 'b3ca13d264da99c32d8f9ae621b25f2a4b30d5447895f12296b6693d87859937'},
 'docs/aws-review/field-producers.md': {'after_sha256': '045653236d36dffc2e9bade6bea555fd36a24bdd9f1cd8a7113a9b98661ecdbf',
                                        'after_size': 219524,
                                        'before_sha256': '04247063cc36363189cdd96a88453ba86ef01def28a2e0e48c3faf2a9eaa8f20'},
 'docs/peaso-aws-selected-codebuild-buildspecs.md': {'after_sha256': 'c673b8eca773ff24cb418a15ddf70175e699a732472b76538406436071bd3e7c',
                                                     'after_size': 2093,
                                                     'before_sha256': 'e552e65271110cef4b1d987183ee88a7b8330485bfec6cc8e58a3582e778ab4b'},
 'docs/peaso-aws-selected-workload-commands.md': {'after_sha256': '3a6eccb7f6d0caaaa4a0d6e338dc63f5bace265fb170b5d05391d3be1d83a9ce',
                                                  'after_size': 2473,
                                                  'before_sha256': 'cdb2881b9913e6300514e43d510dc1a450afadb6b1611fef432d00625619f8ac'},
 'docs/peaso-gcp-selected-job-images.md': {'after_sha256': 'bca08798758cd75258beb8130270c5afc3e5e58a8163789b0602b4762aa590a4',
                                           'after_size': 2757,
                                           'before_sha256': '3661731829acd70f67f9ca90da1c8d73faa16ba9bcdd3b4f82a8f32474f30b49'},
 'docs/peaso-local.md': {'after_sha256': 'c35adaecc7c1d7369c6e6ac75ab21f4ea4760a525b6728a755a99c580ee55b40',
                         'after_size': 21799,
                         'before_sha256': 'eef6cca3020fd4becc1c07132bb44eed1f63b51436380da141d4f3343d6afae6'},
 'docs/secret-content-permissions.md': {'after_sha256': '59757fab0fa505ad46eafc0b0a39b4d07bd3cbf8d2dce40c721b96be8c710002',
                                        'after_size': 21258,
                                        'before_sha256': '4402965d17df1e3db34e6d3f9827ce207f2e6483ecb1b3d47b2221359386c36e'},
 'frontend/src/App.tsx': {'after_sha256': 'ae89b8227ba95317f29d3190005c2760c26fbd9f3947d1bb4266528522d60526',
                          'after_size': 21111,
                          'before_sha256': 'dfe8f0934540bfb730d296701f0514c212a0b6e0d09d91b11eef15ddf850c855'},
 'frontend/src/CodexSettings.tsx': {'after_sha256': 'cd96ac9871227a10e50cbd82b9f8636250cbd1f35c4347b25602258ebcc5b727',
                                    'after_size': 8555,
                                    'before_sha256': 'ef87d186406c01bb8d50dbf47c9cbd53837ccb8b4810bb3a428c1d7a5b375f9a'},
 'frontend/src/Scans.tsx': {'after_sha256': '34eb2b4342db2b4e46e84cf31f18a4a8f0c73b49b33787727240cff9ae0b341b',
                            'after_size': 24613,
                            'before_sha256': 'ccebc6f1e7eb5a5606dc62303c5e4658dcad637a5032e5e7e9fc967e894b0aee'},
 'frontend/tests/ai-access.spec.ts': {'after_sha256': '4eeba2a31ecd0241ab01720819782f7f7d9d68d83c2e4d41a87b6a32431883b5',
                                      'after_size': 1852,
                                      'before_sha256': '390e2ec277f41ae9b7e5f806ec1c2257f7e774f9f33bd6000663e10c616efbf3'},
 'frontend/tests/ai-review.spec.ts': {'after_sha256': '7fe1d81c76fcf12dcd3354ffba6efe21e66ad9e0bf19ce03a654fd28bcca864a',
                                      'after_size': 25602,
                                      'before_sha256': '834bb6f3759a27202b168dc1684f1e9cb51816b8067329a3e2177547e2111734'},
 'infra/aws/Dockerfile.worker': {'after_sha256': '2ba1b1820a711ce4348e5ff42d6274885ee95c6ecaef1e9e231604910031dfb2',
                                 'after_size': 2441,
                                 'before_sha256': 'e069d24c79065ac126c7c130cedea5da2c461ac6c72cc5fd7630aa99fbebf17b'},
 'infra/aws/iam.tf': {'after_sha256': '319e90d9f2f377be919c815ed27f433ae4f45868bbf3bb984f36c9fddfc213a2',
                      'after_size': 9503,
                      'before_sha256': '119086927a14a48dc52f0180eb10a75f0d6355a848de200b8028a1325d268e39'},
 'peaso/ai/auth.py': {'after_sha256': 'c1879bc238710478fea7fcebbe38200c2b6c601f14970765956d42f4b18d9658',
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
 'peaso/ai/pipeline.py': {'after_sha256': 'aa72ae893f8aba748440beeaeac25d78736afb66413dbf210e4146cd128585a1',
                          'after_size': 22845,
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
 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py': {'after_sha256': '70e9d13e572bc77bae366e7bbcadee51c5a2e32dcba9c87043385c7013a9081d',
                                                                  'after_size': 11526,
                                                                  'before_sha256': '50be001febf5a568b2b2ffbe7c295edafeb3f34a5e395a4bf29a6bc94f58b01f'},
 'peaso/collectors/aws_workload_command_runtime_20261020.py': {'after_sha256': '22252144a2f21c517684ec0f25f362abaa145196dd59f23c4606674b3d1acc5c',
                                                               'after_size': 6719,
                                                               'before_sha256': '9dc132a81388ee3b228b8b1de0820aefe9bfb741be37ea4c082920254e5c96b5'},
 'peaso/collectors/azure.py': {'after_sha256': 'd27a5f2b861fef622c20bff80bf5e8f559d7f5d70604606643eb9267254101e5',
                               'after_size': 243608,
                               'before_sha256': 'b69db967e65722174e847116620b63c7de4f0da835e3edde1a882456dc37afea'},
 'peaso/collectors/azure_function_package_integration_20261020.py': {'after_sha256': '9eb8c15ad1052795777ae95960f7c65a8062d5555e2456a9c34a9f2aa6d1e58c',
                                                                     'after_size': 12770,
                                                                     'before_sha256': '678fc74f19156541992b9ce3536cf642253842b34583e6408005a4e38858c0e0'},
 'peaso/collectors/gcp_artifact_file_secret_indicators.py': {'after_sha256': 'da4edfdac77dda5c80891ac7d812c1859e536e4786360b8d5656f64af289d4ff',
                                                             'after_size': 16516,
                                                             'before_sha256': '30606f70908536e1fd5a710ccd5f62d0fb953fa1eeac474341c7f38c01db2e5b'},
 'peaso/collectors/gcp_composer_source_secret_indicators.py': {'after_sha256': '2b357152018fc33b6cf31bba99ac52c2bd5bd9390a9c9c60233c26b66915f903',
                                                               'after_size': 16342,
                                                               'before_sha256': 'fbe60d18f2ec81fd014ed8b1650daf194f49166324c01e0d5d9ab09c4f062257'},
 'peaso/collectors/gcp_image_secret_indicators.py': {'after_sha256': '2022bbd2816bfe82679b160c12b90d674c12746e14d95138bb3bb236dc0514c3',
                                                     'after_size': 22560,
                                                     'before_sha256': '7891365e7a5ecd82734dd385d1ed64b56b11e1283e07dc2f3b9e16cbee2e104e'},
 'peaso/collectors/gcp_selected_archive_secret_indicators.py': {'after_sha256': '4dc9fd5feb8b193f5a119ee7b2f2b387d5eaf9f3c04fe2502c5df7e7ed07a4d3',
                                                                'after_size': 11655,
                                                                'before_sha256': '5da0da030a5d7be256956f7126f5a8b5aaed8c552b49185a8d6ed7d4e1badd23'},
 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py': {'after_sha256': '393720df111585dfd41e586f548ce35140a01e86dd980564805552b1b085cc66',
                                                                     'after_size': 15943,
                                                                     'before_sha256': 'b424bf05b428b54914baad891b272151351284c630b62c72d3ae1c826ccf8530'},
 'peaso/collectors/gcp_sourcerepo_secret_indicators.py': {'after_sha256': 'ba809b97f9e9b36674b2938c74a1f9ee874e3121cbef947008db66091dbaf9e4',
                                                          'after_size': 15969,
                                                          'before_sha256': '34f0c7eaf42626d7da2bbeac98ce912e792000aa28e42bea91c6fbc3f0591069'},
 'peaso/rulepacks/api_catalog.json.gz': {'after_sha256': '898be91909f846add88e983c16b69e6c2fdfe0a668ad43201091b6a4ac7aecd5',
                                         'after_size': 2556279,
                                         'before_sha256': 'bcf67724b2321eb218932408384988a07ddbaa7aefa9755cc70268ec83c481c6'},
 'peaso/rulepacks/api_catalog_manifest.json': {'after_sha256': '9aeea9b6b5f2bbaf1ae9213a9c339c9c5bf7b97f8a241f062efa04fe7cdabbbd',
                                               'after_size': 1062,
                                               'before_sha256': '48cb640816c19924fe377871b73a525ea74552f0435676e41143387bdc935755'},
 'peaso/rulepacks/native_catalog.json': {'after_sha256': '5316190126e37021084f6ca1f21762aa6d0a9c2078332b0224bd7f3943a6e7b6',
                                         'after_size': 25797523,
                                         'before_sha256': '9172d6194c7d985ea72df522e0cb458d6313ab25b3d724fe5c29625e366e9e1b'},
 'peaso/secret_scanning.py': {'after_sha256': '3897b64c134f88e7ad17c3c1f31df2b5497d34df6c1340d04e536313652f94f6',
                              'after_size': 16017,
                              'before_sha256': '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'},
 'peaso/server/app.py': {'after_sha256': '45192b68c74f5b3019dd44cadc8276d3fdc8614586311bc83a43a3c92bec1180',
                         'after_size': 124659,
                         'before_sha256': '3cd6d5053c9522ce2842ac59778f087115a1e076b8ea14dbdf03c5e6e1d5ff9e'},
 'peaso/server/materialized_catalog.py': {'after_sha256': '75b92f49d0ed1f2f358995980991c979ac63fdddbce4dcbddd99105b77b4f0c9',
                                          'after_size': 19272,
                                          'before_sha256': 'e57df7092383505b4c571df107fbe6b0c8c4b8c343da22e4044691b61e664876'},
 'peaso/storage/runtime.py': {'after_sha256': '980fd107b762399ee3eb13968360e46d547c8a05d78e7ac81b8597312f08710e',
                              'after_size': 2097,
                              'before_sha256': '4a52941e15925e48296da78e3a8386a58a60de5bfb0ad0119d66a397886a2214'},
 'pyproject.toml': {'after_sha256': 'ad55a767c20d66dc60de70db938cc2e3f2c2a8aa2d4cf2df1ce1bbe2752a5377',
                    'after_size': 2447,
                    'before_sha256': 'd38efdc14025653b6f2f34c4da130341bd66f7c7b6ce3b94699e1289f894a9ce'},
 'scripts/peaso_compliance_materialize.py': {'after_sha256': '8250538565202f93298d7911301eab4345bdd4abc17c3079246c807757abb9e4',
                                             'after_size': 16230,
                                             'before_sha256': 'b3d313f14a727384e7ba6f18ec875aa05155b39e52fcc59ea51c20a1084b6e65'},
 'scripts/peaso_deploy.py': {'after_sha256': 'c6c234eb39c62fb26d7296a84a8b49596528ec55b06e07c9b68588afa0e16f39',
                             'after_size': 213914,
                             'before_sha256': '45dbcebc0e1162fa4a75498a232e5b7fb92e169dee60a356fb32446353d03af4'},
 'tests/gcp_referenced_source_historical_compatibility_20261020.py': {'after_sha256': '10fb7df3d7203823fe543019f91b67a5452b0ef176405ed3d716fe834bf702b9',
                                                                      'after_size': 14234,
                                                                      'before_sha256': '4a10826eaed04a02fefa686431f4cee55a29995ffb520d750b835b128f6ff1fd'},
 'tests/reviewed_guidance_presentation.py': {'after_sha256': 'c852e5d61be3fe789f2a371ce6e7b8a5c402c0d838cf6960dd8d592096990454',
                                             'after_size': 6440,
                                             'before_sha256': 'dae6b5aeef153c3eefa79334a0b2d518fa5c1b5bba36aefc6190f030e2b7c5ad'},
 'tests/test_aws_content_scan_selection_review.py': {'after_sha256': 'f701e3fd4595bcbb1ac8063c6f868ce2192e942a20e048c4e20bad210b1d452e',
                                                     'after_size': 10969,
                                                     'before_sha256': '0b8a4ea2651f649475ac6e63ba4343290795e4e6483a0032b6de14ae3bfe1027'},
 'tests/test_aws_s3_runtime_admission_20261020.py': {'after_sha256': '4b5883cbf591e3a2341028542d9c141bcc6095c9536020e4559c427c9bc1f5e3',
                                                     'after_size': 19832,
                                                     'before_sha256': '46dcb6929fa9b03431c526d56b7f316d9f53703995280ad014ce2679fa053cc3'},
 'tests/test_azure_declaration_secret_integration_20261020.py': {'after_sha256': '58947cd18ed2932dc7d542807adbadbc9877eb6d8b745c723d27c910998af256',
                                                                 'after_size': 11170,
                                                                 'before_sha256': 'ac42c2dd3d94eec7e2636061933183a9a13ce2276b518f0eaf753f3df7c9702f'},
 'tests/test_azure_function_package_runtime_20261020.py': {'after_sha256': 'bc1b1a82b9317ae6283bf577f9227a0903752833572a28fa0bd0faf72c9a1fca',
                                                           'after_size': 2756,
                                                           'before_sha256': '92bedccd8373aaf0700d19b47b623c11f9fcd88947e07ab708ff9513b8e859d1'},
 'tests/test_azure_function_settings_production_integration_20261020.py': {'after_sha256': 'd5179795768a1e6f29a59bbbfdb58945a84cd87ca9dc67e156487c99bcb37bd9',
                                                                           'after_size': 17726,
                                                                           'before_sha256': '2d1dcfd635c436ad5bd360d54570aad300b84218d4d582df1b0ec5ece4a196df'},
 'tests/test_azure_jit_parent_type_successor_20261020.py': {'after_sha256': '49f9c6ff92c6f2d9aadcd897f2f0e078d8f619b16333cfd40034b307ef618b5b',
                                                            'after_size': 8539,
                                                            'before_sha256': '9f666515645ef0a6aed92470592aafb9172a8c810fc0f84c4a419c29599a37e2'},
 'tests/test_azure_k8s_current_review_bindings_20261020.py': {'after_sha256': 'b06bad1773d93397e7a664d827d1a1906d65f0c362012e3a2f4ac51043027715',
                                                              'after_size': 4636,
                                                              'before_sha256': '9e3da65c8e67c0cce14cfd12e36b781202c14ccb6fcde7864c56cb419de97255'},
 'tests/test_azure_log_sample_secret_integration_20261020.py': {'after_sha256': '85182a62f0b8383dd85686369ea9401b9453fcd78c001b4421ed80724b84adfd',
                                                                'after_size': 12113,
                                                                'before_sha256': '50b79b395ee07aa77b1c20b4ef226e84443797717a8608dc64c42db6e90ef912'},
 'tests/test_azure_metadata_transport_fix_20261020.py': {'after_sha256': 'cf8e355131e162822b602b5366c5144b1925c93c52f1c01db764ce7a799ba7e8',
                                                         'after_size': 12518,
                                                         'before_sha256': '755a7b5f147008970562121bae32b36cce52022685415eb55ef5cf6a738d3f3f'},
 'tests/test_azure_ml_selected_asset_secret_integration_20261020.py': {'after_sha256': '351749ace6c903101c5d4a31120b1731af0ea464580b05419c4ec66347eb2730',
                                                                       'after_size': 12766,
                                                                       'before_sha256': 'b228d21c9340c9702e53c1918ceb8998e78f6009c0a69a42b2a4735d51bda5f7'},
 'tests/test_azure_monitoring_contacts_native_review_20261020.py': {'after_sha256': '5af7007332e67a3acd38a0b886f57c6382011febf21631502d5f5c9353bc9fa3',
                                                                    'after_size': 7213,
                                                                    'before_sha256': '2d0550d47d380e8399beff1d0cde139e8790f7a1c19f8a83b21d5c2d376777a4'},
 'tests/test_azure_nsp_query_cmk_metadata_admission_20261020.py': {'after_sha256': '25eb999a21ed93d057193e09ffe89305569227d34a5b28e05922d49cdacb58ae',
                                                                   'after_size': 14224,
                                                                   'before_sha256': '5c38e6a22bd59d2774daca2c17775a6e935b2e81768da596c9eb383c70fd8d5b'},
 'tests/test_cross_cloud_secret_surface_audit_20261020.py': {'after_sha256': '62f55fc9c0ec20664989b21f0bdd20e65d0df53a09bfab9c84ae22754b8caeb8',
                                                             'after_size': 21154,
                                                             'before_sha256': '25bc1849405817bc5023f12a614f9409700f643ac5004b69bda40bafc9c67e07'},
 'tests/test_gcp_appengine_source_secret_review_20261019.py': {'after_sha256': 'a52e8ecc4d54364d203169f81d02fab96cf59e847ca285712418b692104eccee',
                                                               'after_size': 18725,
                                                               'before_sha256': '506404c7c650d44402100e42f531057323e95f0e24bb4dd9c8efe1ee03155a51'},
 'tests/test_gcp_artifact_file_secret_review_20261019.py': {'after_sha256': '8c70102c5525b3cba5e97632f63dabb7f1c6f993cd082a02994556026a4fd13d',
                                                            'after_size': 18829,
                                                            'before_sha256': '21e070d3a30934d9a62e4fc710d7f3848fcb0a3ce976f755e9ec5716e7b02bd3'},
 'tests/test_gcp_cloudbuild_log_secret_review_20261019.py': {'after_sha256': '67ca2859c33bdfd978e9fd797eba297d958afd171233bf9be648e047c6316da3',
                                                             'after_size': 19346,
                                                             'before_sha256': '73c36e4a88d62a29f227cf6b3e74d2dcc4e25cdcfda9af6cd5487131d105eb21'},
 'tests/test_gcp_clouddeploy_source_secret_review_20261019.py': {'after_sha256': 'd1e44aef7dbb050696cff81801141c11c287bdeb3c38f3e66487c4fa33866f0b',
                                                                 'after_size': 16571,
                                                                 'before_sha256': 'f12df988c5e02a9bdf4f7867171377a544d1550ad6b395fec8df14bab925486b'},
 'tests/test_gcp_composer_source_secret_review_20261019.py': {'after_sha256': '35e43f3422d64bed8061563bc6db2a4c5783360dc77bf8ce57b104d6dc60c57b',
                                                              'after_size': 24962,
                                                              'before_sha256': 'aeb0b20c5c389d801313360c1ff6651d0bb2c4bc7475edecdcb43608e8842ac9'},
 'tests/test_gcp_configuration_secret_review_20261019.py': {'after_sha256': 'fd987b253c281f92cf90fbb8fd60b105fbe4b041cb86c64fd734694a72159c9e',
                                                            'after_size': 20619,
                                                            'before_sha256': '7596762bd7d0f339c059d14bea11e0f888df607ef727c2d458f287400372f7b5'},
 'tests/test_gcp_dataflow_batch_source_runtime_20261020.py': {'after_sha256': '734c2c7142848e91145173e047a8a3b9ad5fc71c08aa308c87a5e6f6cb02a29f',
                                                              'after_size': 32571,
                                                              'before_sha256': 'c648ac70644469b0008e53f8c759206c907fc265995d6b8c673627ca86de20b1'},
 'tests/test_gcp_dataform_secret_review_20261019.py': {'after_sha256': 'c55768eaa730d896eb96e63ec788f4af72b9e56203c932702b8322c0f234fd81',
                                                       'after_size': 27022,
                                                       'before_sha256': 'e2605d7805e533bb4b1052d4007041b87e295d6224b256e53c20bcea48860cd6'},
 'tests/test_gcp_final_services_fix_review_20261020.py': {'after_sha256': 'a0be28be2be33450252233f066c3f3a2cfb0df341ef68d3ec659175807060c7f',
                                                          'after_size': 22213,
                                                          'before_sha256': 'ad458cd6c41cc48d0cc8747e6b05cafecfe4fca26c69c340d5adcbfcb2a64682'},
 'tests/test_gcp_final_services_review_20261020.py': {'after_sha256': 'fbb69d2f2aee09c5b2141396d956469619661ce5ea3604e76b76e2001f3af20e',
                                                      'after_size': 40560,
                                                      'before_sha256': '509bab905c44b26c8079356380076c02a4273341a77b9a1895a8128b5df4f6be'},
 'tests/test_gcp_function_secret_paired_candidate_20261020.py': {'after_sha256': '7c96d140c196243cec592d70d053bfe3ff239cd15148e600af3ec9bbb9ee99ea',
                                                                 'after_size': 11132,
                                                                 'before_sha256': '1ff9c5867979c36cc7bb674f4c5bfa78dda36918ecf0b803132657070514c619'},
 'tests/test_gcp_function_secret_paired_integration_20261020.py': {'after_sha256': '9b6747f0b3b25cc01071e07403d820c48c0873f509127f8ea327398f462a7be4',
                                                                   'after_size': 20389,
                                                                   'before_sha256': '8c5b49815e8d5748b45afdc684beeeb2d0a60cf0903ba8292394fa0339d7d6f4'},
 'tests/test_gcp_function_secret_partial_positive_20261020.py': {'after_sha256': 'e78aa133ac5c79ccd3f60ff24e35a681ed671dd837c54e86202b005d9208173c',
                                                                 'after_size': 16708,
                                                                 'before_sha256': 'bbca5cce749be8aa0d4815318411b75d0109f13e34e76e52bc324cbcc6f9ecce'},
 'tests/test_gcp_function_source_secret_review_20261019.py': {'after_sha256': '8b2b9e116a8418a2f48254367b5e30407e13cd09e128c9484692a798433d3bd8',
                                                              'after_size': 27474,
                                                              'before_sha256': '7f86d99ff0d806294560de145c09c93a7747662c859238df57a53ad74d1b0670'},
 'tests/test_gcp_image_secret_review_20261019.py': {'after_sha256': '2b5389b650c5a1077c05766082e39917da1f05260477b53b273ef4bfe3270ef8',
                                                    'after_size': 22460,
                                                    'before_sha256': '932b6e48f12e25bf6016420b84a7b81922af50ae14748b52526a5f3bb0fb4281'},
 'tests/test_gcp_secret_integration_acceptance_review.py': {'after_sha256': '90fefd70c78ce5c4ef7be0596f4d18bc961f2000c3a48a608032c00866d91412',
                                                            'after_size': 35545,
                                                            'before_sha256': 'ff8e072a1f5c5d6d705b82342713b89098d5e372c0fa53ef6203c6cf88ac5246'},
 'tests/test_gcp_secret_surface_audit_20261020.py': {'after_sha256': '6ab370784ebf2adcb2d88974c2412f435cbbd6e6b3ac3387323f8cd313330166',
                                                     'after_size': 7456,
                                                     'before_sha256': '873fa62fa35d191a5c3a408c66fee9d81c0ed5ff8d4d0be4733d7ae91e53eb45'},
 'tests/test_gcp_sourcerepo_secret_review_20261019.py': {'after_sha256': '14354d79e2bbf8e974dda7472ebc01af540dc3ba8bd565449e52524efaaa83df',
                                                         'after_size': 20934,
                                                         'before_sha256': 'ef811df7a35391b690f9b346f201a6f11046328ac493dc5bc9f84094a736727e'},
 'tests/test_gcp_workbench_head3_runtime_admission_20261020.py': {'after_sha256': '29542f1978626a6de962e68f3e5521feb0c0119e07eea65957eabed0996a1c77',
                                                                  'after_size': 13761,
                                                                  'before_sha256': 'dd2a6c40ed57c51bd9fa22895efd70c415aba1a9fb63db0e3d9faccc32527092'},
 'tests/test_gcp_workbench_source_runtime_20261020.py': {'after_sha256': '82c8e1a833fea6f28c33e736289fca08e5dcfa04faaef361040de5aceb699e62',
                                                         'after_size': 32795,
                                                         'before_sha256': '58ff0cd36d8dbcabf406916c6ad795e7d3ee4f3429250d63271aab4753972df4'},
 'tests/test_k8s_annotation_native_admission_portable_20261020.py': {'after_sha256': 'fa257d9cca65237366b00eb968474471fc1a653d51ac62d1484bed57a2f810ac',
                                                                     'after_size': 9637,
                                                                     'before_sha256': 'c53f414fd7fde54ace3895cff774235031958ca3506e64ae2ce67c2052be0b62'},
 'tests/test_k8s_kubelet_configmap_production_20261020.py': {'after_sha256': 'b5d3c48b73a8447e39a450aef69db84e612812ba6db753531e12a6ccb9d2e15e',
                                                             'after_size': 10856,
                                                             'before_sha256': '4c1ec5eb082cee471af7ac46dadfa379ea0c3d603cc81fcc5c204208879764dc'},
 'tests/test_k8s_network_inventory_successor_20261020.py': {'after_sha256': 'ddd7334548d54a36a56d9639449cf4784a7f92a87d85479df57d73ae19959e5f',
                                                            'after_size': 10087,
                                                            'before_sha256': 'c1de397bdce09bcf5bd83c73fa9b73d51237d207ac37ee04aded498fdbb9614d'},
 'tests/test_k8s_selected_log_sample_production_20261020.py': {'after_sha256': 'daf1f801791f850a59a4812a04cc85530cd2f26975be510c76b2cee1da016977',
                                                               'after_size': 17727,
                                                               'before_sha256': '0b9ea82915ec55b0682f2a8c00e32fdcd074ff36cb076ce12aa04ab5737a99bb'},
 'tests/test_k8s_selected_log_sample_secret_review_20261020.py': {'after_sha256': '5fc506bbf591330db5d8702d152698654cb93e3433379e17a44dcd7347af5b57',
                                                                  'after_size': 44512,
                                                                  'before_sha256': 'ff98e83ade19b2963ab40e97595003b9d232f921d899b7db6b69c3241396e3a3'},
 'tests/test_k8s_selected_metadata_secret_review_20261020.py': {'after_sha256': '38ab2d1490cc373472627cf641a05123062b4b7c82948ace3b80aeb12b8e82a3',
                                                                'after_size': 22935,
                                                                'before_sha256': '11ffb2c4e2e45ff425b647a08581525d40f227baecfbc9b8b5eb6062ddc5ae4b'},
 'tests/test_peaso_ai_deadlines.py': {'after_sha256': '0957fac1d5c5b160184198d1cb05d7f798383fc9f635db192f0a5955979fe170',
                                      'after_size': 6772,
                                      'before_sha256': 'd56fd098d8eb6f7b3681fa1b93a51c93708aac627971805b65f0a0a162098090'},
 'tests/test_peaso_ai_fargate.py': {'after_sha256': '8370c8da36f0717f65f6f0acd68ee52994c068056dada6680e89d7816f4ffa26',
                                    'after_size': 19828,
                                    'before_sha256': '9dc6def19413e0716f69782bf0f2b7119316bc9eb6ffcd8a64a9b39acbb245ae'},
 'tests/test_peaso_ai_output_validation.py': {'after_sha256': '6226934cb6495952a5e9b68abbfcddc0ce192409f47b1dbc8705f2cad93c4dc9',
                                              'after_size': 7715,
                                              'before_sha256': '0f2af34ed70992f63bff0ace636cbb0cee9b19d81886ea4aa8d07a1f476ce770'},
 'tests/test_peaso_ai_review.py': {'after_sha256': '3b8d7d02b9e5f9120f3c50886356e6c26ee57762715057bb23b1181f090c4208',
                                   'after_size': 83911,
                                   'before_sha256': '4a719b6f27a279bb8de46180f7f111d4d97ac5e2f92f7dbb7bebb9d44fb5d3df'},
 'tests/test_peaso_aws_ecr_artifacts_native.py': {'after_sha256': '491b36fb3311cf63977d561a3e8a617f136c25e6ed11945bd9fe02f3c4966b43',
                                                  'after_size': 19543,
                                                  'before_sha256': '13f72dfe846f15559a7665d11447c2ac1b75bcd29d55bb832d0ca86767541365'},
 'tests/test_peaso_aws_finding_clarity_reviewed.py': {'after_sha256': '830f2383cc069edd53cb4d0acffdc43dcc4942d7d34a6e73e1e58a87005b268d',
                                                      'after_size': 18676,
                                                      'before_sha256': 'deb6dcfcfaa5a95bdd67b6f2e26d9abe02ec8fff644e9362dd17aaae0a873f04'},
 'tests/test_peaso_azure_detection_telemetry.py': {'after_sha256': '66473790f9dac04be10c2e5109b6a889733cde7ca4dac9490d8a729da06b783e',
                                                   'after_size': 19919,
                                                   'before_sha256': '5612f2d74cec0cb7ae637d81ed7e7f0dc2d48be4896dd0954d062ab6d0e5490e'},
 'tests/test_peaso_azure_devops_git_native.py': {'after_sha256': '91b49c4302a231c8729130a222547ff895ceddc539676a85580a2f3576871d9b',
                                                 'after_size': 15480,
                                                 'before_sha256': 'd8a324537780604b4fa0c6e6aee18d3fc7c4364337a9973140fb310269b33bbf'},
 'tests/test_peaso_azure_evidence_explanations.py': {'after_sha256': 'c2f49518729ea0c4e0c84ba54feb3183f3e8e75a69554365fc8b79af7f5cc4fe',
                                                     'after_size': 142839,
                                                     'before_sha256': '211cdd26ebe5570c86c0c407691b44440335b0eedee9d812ffbc90b1951273d2'},
 'tests/test_peaso_azure_guest_configuration_native.py': {'after_sha256': '9654677b3600d10379481e76f72a879f873a3b37dbeb7fd555e4c5b4f3ab8b33',
                                                          'after_size': 8065,
                                                          'before_sha256': '08ed685c52a53bdf0fa0df6e3a005142fea557f609548e580bf120d5ead425e6'},
 'tests/test_peaso_azure_native_disclosures.py': {'after_sha256': '99cd56fc176d13e4caf27321c464dbc5133ed94afef00e35fff48dd6946dd642',
                                                  'after_size': 22349,
                                                  'before_sha256': 'f4f54229b5afb0c4d46a56a2c4cbb672eb4420dbd286345098b0ec4865414193'},
 'tests/test_peaso_azure_tls_owner_policy.py': {'after_sha256': '0fe36cdc951d0f60454c264b3004def1ee16a000d6b9a0f545897d9a24340e10',
                                                'after_size': 13850,
                                                'before_sha256': '074c36f88bd273eba704b43b56a3de68c5721eb05318339145a625e5fb7dbeb4'},
 'tests/test_peaso_checks_azure_ports_services.py': {'after_sha256': 'a8edc7522c133e07f9ce62c1c9029126566e98ba8ae9b2a87b25dca575d06b4a',
                                                     'after_size': 23355,
                                                     'before_sha256': 'cd940ae03f3bd441c161397b34b6b5c94175ebe8e080049230349a90e1abeaa6'},
 'tests/test_peaso_checks_claude2_azure_behavior.py': {'after_sha256': 'd0eb9ad4f9dfd56d63b0571f1375675bb5ab2bb2f389abdc2ca72fd3c123603d',
                                                       'after_size': 11060,
                                                       'before_sha256': 'd2c23b1254d20698f271a6b2adab7d21c1f59585ccbcaddbb99007738a68bb15'},
 'tests/test_peaso_checks_claude_azure_data.py': {'after_sha256': '963a539dbdb42435228a92078681495258fb95ac79899e7f914c7def3b9a4a39',
                                                  'after_size': 10696,
                                                  'before_sha256': 'b1dadbc8d86191cdd748f327e676066dc3f21c2c61b034119a98a0984f24bd4b'},
 'tests/test_peaso_checks_claude_gcp_k8s_behavior.py': {'after_sha256': 'e24d3c9da0593ecc28e5d9158020fa6491c277117eed4a1488d486da3ab39a19',
                                                        'after_size': 7616,
                                                        'before_sha256': '2d5ed6d032cad09430f9e06c03af2dd9c01bd843ab13bd2a70f13db279787097'},
 'tests/test_peaso_checks_gcp_ports_services.py': {'after_sha256': '3dd01e6c68c6b88c7f1a1d750048cebdc64f24b5703f70abcf7b4bdae84e0c53',
                                                   'after_size': 3473,
                                                   'before_sha256': 'b3d6d33611f94d679ce73995d5a3df16e0845d5846aaa04b5c31f20b1fcea672'},
 'tests/test_peaso_collector_swc2_azure_native.py': {'after_sha256': 'c1e74338463ca770d079f6bf29bc394e786931abbc679f4af9ea8aac839611ae',
                                                     'after_size': 29421,
                                                     'before_sha256': 'addfd568a0a12f8225c63719bc07caf4ebc8d99d28c50b2a265c71734ceb12d7'},
 'tests/test_peaso_collector_swc2_gcp_core.py': {'after_sha256': 'e3c890fde28e3362b35a94ecf276865c880ac61b0736605aebaecc0a2ebd55fb',
                                                 'after_size': 17960,
                                                 'before_sha256': 'a3853008091549446aa9d021acc194bbd221ac5582d6b89ef96b452452bfa790'},
 'tests/test_peaso_collector_swc_gcp_wave.py': {'after_sha256': 'd4bb8f396d4884a6401a1b77354f2b98e9bcfc3bab215b2a4c54726b9e0324c7',
                                                'after_size': 15813,
                                                'before_sha256': '9c4f72addc463a5c9b247f94bec5d208a81b4661c90ff3c7899b29ef9d98ebb5'},
 'tests/test_peaso_gcp_observation_source_parity.py': {'after_sha256': 'c72ffe2c90926b9da50394249184d0d6cc74cfe50b2a42a9ca435c08b2b478ba',
                                                       'after_size': 10690,
                                                       'before_sha256': 'e60b0f51c4f46b4fdbe22effc10298b769639601a5d17a69a38a9f1ce2d33075'},
 'tests/test_peaso_gcp_project_alias_pipeline.py': {'after_sha256': 'e4d4d6c7fdcc2d902fbb30a9da54ee072818b570d5e45a7591ff9f7b72b8df30',
                                                    'after_size': 14982,
                                                    'before_sha256': 'd30b785d6a82eac1a4a379beeaa671b9af5d9301ec72708fa27be4eb25018bdf'},
 'tests/test_peaso_platform_security.py': {'after_sha256': 'b5aee6900bcd6794fbac6c4dc005c0ca06446de49c0d23114815ba0072aeded8',
                                           'after_size': 8988,
                                           'before_sha256': '684495be8c336be407ad49e25663186a302fb208ee621b0037b0e9d4e9cb48f9'},
 'tests/test_peaso_provider_scope_observed_evidence.py': {'after_sha256': '99b41b9a0b597aa25ef3ef42c20643b6168f076f1d5b877d6b6de07968b329a2',
                                                          'after_size': 3139,
                                                          'before_sha256': '7ff96a647af758e07d15e724cb15a8ab773d8f8f5f94b39c2f2593813aa9f590'},
 'tests/test_provider_bridge_compiler_portability_20261020.py': {'after_sha256': '583a3f3da42b7f5cd5e979b0f60d4e0dfab860398b78996afca25e2e1eb9611c',
                                                                 'after_size': 8243,
                                                                 'before_sha256': 'a1acf42b56cc74db0afb07c7f91eb8f73fe76298d0f42dba024f2118f8c4fc89'},
 'tests/test_provider_bridge_prepared_ast_portability_20261020.py': {'after_sha256': 'f6ae8081883877f1e268105007ebd3a4a606531edfa122a817b576c1490aa970',
                                                                     'after_size': 4321,
                                                                     'before_sha256': '6dfff0916a69ec958320ed8d222ab7237fe99769dfdd4d5d85f0e99da514c28f'},
 'tests/test_provider_combined_source_bridge_20261020.py': {'after_sha256': '1d2979579e2f68c7fc2d1b2a74f7df949e343943b36e92b652981c3f6cd9173e',
                                                            'after_size': 32608,
                                                            'before_sha256': '2a795bf08cf52ce103d4e978f2f66e64cf1229e2f9bc2ccc4766dd6fa385aaf8'}}
REVIEWABLE_CURRENT_PATHS = frozenset(['.github/workflows/tests.yml', 'Dockerfile.peaso', 'docs/ai-review/README.md', 'docs/aws-review/field-producers.json', 'docs/aws-review/field-producers.md', 'docs/peaso-aws-selected-codebuild-buildspecs.md', 'docs/peaso-aws-selected-workload-commands.md', 'docs/peaso-gcp-selected-job-images.md', 'docs/peaso-local.md', 'docs/secret-content-permissions.md', 'frontend/src/App.tsx', 'frontend/src/CodexSettings.tsx', 'frontend/src/Scans.tsx', 'frontend/tests/ai-access.spec.ts', 'frontend/tests/ai-review.spec.ts', 'infra/aws/Dockerfile.worker', 'infra/aws/iam.tf', 'peaso/ai/auth.py', 'peaso/ai/codex_relay_cli.py', 'peaso/ai/fargate.py', 'peaso/ai/model_relay.py', 'peaso/ai/pipeline.py', 'peaso/ai/runner.py', 'peaso/ai/task_runtime.py', 'peaso/analysis/common.py', 'peaso/attack_detection/aws_kinesis_video_controls_next.py', 'peaso/attack_detection/rules.py', 'peaso/checks/claude_azure_data.py', 'peaso/checks/gcp_artifact_file_secret_review_20261019.py', 'peaso/checks/gcp_composer_source_secret_review_20261019.py', 'peaso/checks/gcp_image_secret_review_20261019.py', 'peaso/checks/gcp_selected_archive_secret_review_20261019.py', 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py', 'peaso/checks/gcp_task_routine_secret_review_20261020.py', 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure.py', 'peaso/collectors/azure_function_package_integration_20261020.py', 'peaso/collectors/gcp_artifact_file_secret_indicators.py', 'peaso/collectors/gcp_composer_source_secret_indicators.py', 'peaso/collectors/gcp_image_secret_indicators.py', 'peaso/collectors/gcp_selected_archive_secret_indicators.py', 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py', 'peaso/collectors/gcp_sourcerepo_secret_indicators.py', 'peaso/rulepacks/api_catalog.json.gz', 'peaso/rulepacks/api_catalog_manifest.json', 'peaso/rulepacks/native_catalog.json', 'peaso/secret_scanning.py', 'peaso/server/app.py', 'peaso/server/materialized_catalog.py', 'peaso/storage/runtime.py', 'pyproject.toml', 'scripts/peaso_compliance_materialize.py', 'scripts/peaso_deploy.py', 'tests/gcp_referenced_source_historical_compatibility_20261020.py', 'tests/reviewed_guidance_presentation.py', 'tests/test_aws_content_scan_selection_review.py', 'tests/test_aws_s3_runtime_admission_20261020.py', 'tests/test_azure_declaration_secret_integration_20261020.py', 'tests/test_azure_function_package_runtime_20261020.py', 'tests/test_azure_function_settings_production_integration_20261020.py', 'tests/test_azure_jit_parent_type_successor_20261020.py', 'tests/test_azure_k8s_current_review_bindings_20261020.py', 'tests/test_azure_log_sample_secret_integration_20261020.py', 'tests/test_azure_metadata_transport_fix_20261020.py', 'tests/test_azure_ml_selected_asset_secret_integration_20261020.py', 'tests/test_azure_monitoring_contacts_native_review_20261020.py', 'tests/test_azure_nsp_query_cmk_metadata_admission_20261020.py', 'tests/test_cross_cloud_secret_surface_audit_20261020.py', 'tests/test_gcp_appengine_source_secret_review_20261019.py', 'tests/test_gcp_artifact_file_secret_review_20261019.py', 'tests/test_gcp_cloudbuild_log_secret_review_20261019.py', 'tests/test_gcp_clouddeploy_source_secret_review_20261019.py', 'tests/test_gcp_composer_source_secret_review_20261019.py', 'tests/test_gcp_configuration_secret_review_20261019.py', 'tests/test_gcp_dataflow_batch_source_runtime_20261020.py', 'tests/test_gcp_dataform_secret_review_20261019.py', 'tests/test_gcp_final_services_fix_review_20261020.py', 'tests/test_gcp_final_services_review_20261020.py', 'tests/test_gcp_function_secret_paired_candidate_20261020.py', 'tests/test_gcp_function_secret_paired_integration_20261020.py', 'tests/test_gcp_function_secret_partial_positive_20261020.py', 'tests/test_gcp_function_source_secret_review_20261019.py', 'tests/test_gcp_image_secret_review_20261019.py', 'tests/test_gcp_secret_integration_acceptance_review.py', 'tests/test_gcp_secret_surface_audit_20261020.py', 'tests/test_gcp_sourcerepo_secret_review_20261019.py', 'tests/test_gcp_workbench_head3_runtime_admission_20261020.py', 'tests/test_gcp_workbench_source_runtime_20261020.py', 'tests/test_k8s_annotation_native_admission_portable_20261020.py', 'tests/test_k8s_kubelet_configmap_production_20261020.py', 'tests/test_k8s_network_inventory_successor_20261020.py', 'tests/test_k8s_selected_log_sample_production_20261020.py', 'tests/test_k8s_selected_log_sample_secret_review_20261020.py', 'tests/test_k8s_selected_metadata_secret_review_20261020.py', 'tests/test_peaso_ai_deadlines.py', 'tests/test_peaso_ai_fargate.py', 'tests/test_peaso_ai_output_validation.py', 'tests/test_peaso_ai_review.py', 'tests/test_peaso_aws_ecr_artifacts_native.py', 'tests/test_peaso_aws_finding_clarity_reviewed.py', 'tests/test_peaso_azure_detection_telemetry.py', 'tests/test_peaso_azure_devops_git_native.py', 'tests/test_peaso_azure_evidence_explanations.py', 'tests/test_peaso_azure_guest_configuration_native.py', 'tests/test_peaso_azure_native_disclosures.py', 'tests/test_peaso_azure_tls_owner_policy.py', 'tests/test_peaso_checks_azure_ports_services.py', 'tests/test_peaso_checks_claude2_azure_behavior.py', 'tests/test_peaso_checks_claude_azure_data.py', 'tests/test_peaso_checks_claude_gcp_k8s_behavior.py', 'tests/test_peaso_checks_gcp_ports_services.py', 'tests/test_peaso_collector_swc2_azure_native.py', 'tests/test_peaso_collector_swc2_gcp_core.py', 'tests/test_peaso_collector_swc_gcp_wave.py', 'tests/test_peaso_gcp_observation_source_parity.py', 'tests/test_peaso_gcp_project_alias_pipeline.py', 'tests/test_peaso_platform_security.py', 'tests/test_peaso_provider_scope_observed_evidence.py', 'tests/test_provider_bridge_compiler_portability_20261020.py', 'tests/test_provider_bridge_prepared_ast_portability_20261020.py', 'tests/test_provider_combined_source_bridge_20261020.py'])
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def test_every_frozen_file_is_exact_except_single_reversible_initializer_alias():
 raw_epoch=(SOURCE/EPOCH).read_bytes()
 assert sha(raw_epoch)==EPOCH_SHA256
 epoch=json.loads(gzip.decompress(raw_epoch))
 assert epoch['schema']==1 and epoch['commit']=='332f1f4825ab5ec17305f60dc85e6d2bffe99f6b'
 manifest=epoch['files']
 assert len(manifest)==4917
 assert set(REVIEWED_CURRENT_CHANGES)<=set(manifest)
 assert set(REVIEWED_CURRENT_CHANGES)<=REVIEWABLE_CURRENT_PATHS
 changed=[]
 for name,row in manifest.items():
  raw=retained_upstream_bytes(SOURCE) if name==RETAINED_UPSTREAM_PATH else (SOURCE/name).read_bytes()
  if sha(raw)!=row['sha256']:
   changed.append(name)
   if name in REVIEWED_CURRENT_CHANGES:
    change=REVIEWED_CURRENT_CHANGES[name]
    assert set(change)=={'before_sha256','after_sha256','after_size'}
    assert change['before_sha256']==row['sha256']
    assert sha(raw)==change['after_sha256'] and len(raw)==change['after_size']
    continue
   assert name=='peaso/checks/__init__.py'
   receipt=json.loads((SOURCE/'peaso/checks'/bridge.RECEIPT).read_bytes())
   raw=cpu_epoch_bytes(name,raw)
   restored=bridge._reverse(raw.decode(),receipt['prior_epoch_file_deltas'][name]).encode()
   assert sha(restored)==row['sha256'] and len(restored)==row['size']
 assert set(changed)=={'peaso/checks/__init__.py'}|set(REVIEWED_CURRENT_CHANGES)

def test_every_predecessor_receipt_proof_is_preserved():
 prior=json.loads((SOURCE/'peaso/checks'/bridge.prior_bridge.RECEIPT).read_bytes())
 active=active_shared();active.reviewed_delta(SOURCE)
 current=cpu_receipt()
 assert set(current['functions'])>=set(prior['functions'])
 assert all(current['functions'][key]==value for key,value in prior['functions'].items())
 for section in ('shared_functions','integration_functions','azure_collect'):
  assert current[section]==prior[section]
 for section in ('file_deltas','integration_file_deltas','parent_file_deltas'):
  for name,row in prior[section].items():
   now=deepcopy(current[section][name])
   if name=='peaso/checks/__init__.py':
    now['current_sha256']=row['current_sha256']
    now['exact_additions']=[s.replace('native_admission_cpu_shared_successor_20261020','azure_jit_parent_type_shared_successor_20261020') for s in now['exact_additions']]
    now['exact_replacements']=[[a,b.replace('native_admission_cpu_shared_successor_20261020','azure_jit_parent_type_shared_successor_20261020')]for a,b in now['exact_replacements']]
   assert now==row
 for qualified,fn in bridge._PRIOR_FUNCTIONS.items():assert getattr(bridge.prior_bridge,qualified.split(':')[1]) is fn
 for qualified,fn in package.original._FUNCTIONS.items():
  name=qualified.split(':')[1]
  if name=='reviewed_inputs':
   assert active._PACKAGE_SUCCESSOR.HISTORICAL_REVIEWED_INPUTS is fn
   assert getattr(package.original,name) is active._PACKAGE_SUCCESSOR.reviewed_inputs
  else:assert getattr(package.original,name) is fn
 assert checks.aws_workload_command_shared_successor_20261020 is active
 assert active.accepted_native is bridge

def test_catalog_is_exact_apart_from_deliberate_source_epoch_fingerprint():
 from peaso.engine import get_catalog
 from peaso.finding_presentation import evaluator_contract_fingerprint
 value=get_catalog();fingerprints=[]
 assert len(value['checks'])==3496
 for row in value['checks']:
  if 'clarity_evaluation_contract' in row:fingerprints.append(row.pop('clarity_evaluation_contract'))
 assert len(fingerprints)==3489 and set(fingerprints)=={evaluator_contract_fingerprint()}
 assert sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())=='55e4ef383df3d4408654b95b46789264d024bb8eb4197ca926f37b7eb0d7a718'

@pytest.mark.parametrize('relative',sorted({r['path']for r in json.loads((SOURCE/'peaso/checks'/package.RECEIPT).read_bytes())['functions'].values()}))
@pytest.mark.parametrize('optimize',[0,1,2])
def test_full_package_compiler_record_parity(relative,optimize):
 path=SOURCE/relative;raw=path.read_bytes()
 consume=lambda rows:[(r['qualname'],r['source_sha256'],c)for r,c in rows]
 assert consume(bridge._compiled_source(raw,str(path),optimize))==consume(bridge.original.proof._compiled_source(raw,str(path),optimize))

SAMPLE='def selected(value=1, *, flag=True):\n    return value if flag else 0\n'
@pytest.fixture
def source_cache(tmp_path,monkeypatch):
 path=tmp_path.resolve()/'sample.py';path.write_text(SAMPLE)
 module=types.ModuleType('native_cpu_source_cache_sample');module.__file__=str(path)
 monkeypatch.setitem(sys.modules,module.__name__,module)
 exec(compile(SAMPLE,str(path),'exec'),vars(module))
 fn=module.selected;row=dict(path='sample.py',qualname='selected',sha256=sha(SAMPLE.encode()),defaults=[1],kwdefaults={'flag':True})
 compiler=bridge._transaction_compiler();token=bridge._COMPILED_TRANSACTION.set(compiler)
 try:
  bridge._check_function(fn,row,path.parent,{})
  bridge._check_function(fn,row,path.parent,{})
  yield fn,row,path,compiler
 finally:
  bridge._COMPILED_TRANSACTION.reset(token);linecache.cache.pop(str(path),None)

@pytest.mark.parametrize('mutation',['source_digest','code','signature'])
def test_signed_source_cache_poisoning_rejected(source_cache,mutation):
 fn,row,path,compiler=source_cache
 cache=inspect.getclosurevars(compiler).nonlocals['source_cache'];assert len(cache)==1
 key=next(iter(cache));code,digest,signature=cache[key]
 if mutation=='source_digest':digest='0'*64
 elif mutation=='code':code=code.replace(co_consts=(None,999))
 else:signature=hashlib.sha256(digest.encode()).digest()
 cache[key]=(code,digest,signature)
 with pytest.raises(RuntimeError,match='source cache artifact changed'):bridge._check_function(fn,row,path.parent,{})

@pytest.mark.parametrize('mutation',['code','defaults','kwdefaults','globals','receipt','source','linecache','location'])
def test_warm_source_cache_live_tampering_rejected(source_cache,mutation):
 fn,row,path,compiler=source_cache
 if mutation=='code':fn.__code__=fn.__code__.replace(co_consts=(None,999))
 elif mutation=='defaults':fn.__defaults__=(2,)
 elif mutation=='kwdefaults':fn.__kwdefaults__={'flag':False}
 elif mutation=='globals':
  fn=types.FunctionType(fn.__code__,dict(fn.__globals__),fn.__name__,fn.__defaults__);fn.__kwdefaults__={'flag':True}
 elif mutation=='receipt':row=dict(row,sha256='0'*64)
 elif mutation=='source':path.write_text(SAMPLE.replace('else 0','else 8'))
 elif mutation=='linecache':linecache.cache[str(path)][2][-1]='    return value if flag else 8\n'
 else:fn.__code__=fn.__code__.replace(co_filename=str(path.parent/'foreign.py'))
 with pytest.raises((RuntimeError,OSError,IndexError)):bridge._check_function(fn,row,path.parent,{})

def test_warm_source_cache_reuses_inspect_hash_without_caching_verdict(source_cache,monkeypatch):
 fn,row,path,compiler=source_cache
 before=inspect.getclosurevars(compiler).nonlocals['source_cache'].copy()
 original=inspect.getsource
 def forbidden(function):
  if function is fn:raise AssertionError('source cache missed unchanged exact inputs')
  return original(function)
 monkeypatch.setattr(inspect,'getsource',forbidden)
 bridge._check_function(fn,row,path.parent,{})
 assert inspect.getclosurevars(compiler).nonlocals['source_cache']==before
 fn.__defaults__=(3,)
 with pytest.raises(RuntimeError):bridge._check_function(fn,row,path.parent,{})

@pytest.fixture(scope='module')
def isolated_package(tmp_path_factory):
 target=tmp_path_factory.mktemp('native-cpu-source-copies').resolve()
 for directory in ('peaso','bluepeass','risk_rules','tests','docs','scripts'):
  shutil.copytree(SOURCE/directory,target/directory,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
 for name in ('aws_permissions_cat.yaml','azure_permissions_cat.yaml','gcp_permissions_cat.yaml'):
  shutil.copy2(SOURCE/name,target/name)
 return target

@pytest.mark.parametrize('relative',[
 'peaso/checks/azure_jit_parent_type_shared_successor_20261020.py',
 'peaso/checks/azure_jit_parent_type_shared_successor_20261020.json',
 'peaso/checks/azure_function_package_integration_admission_20261020.py',
 'peaso/checks/azure_function_package_callable_cpu_successor_20261020.py',
 'peaso/checks/native_admission_cpu_shared_successor_20261020.py',
 'peaso/collectors/aws.py',
])
def test_real_historical_and_current_bytes_still_rejected_after_warm_admission(isolated_package,relative):
 code="""
import pathlib,socket,sys

def blocked(*args,**kwargs):raise AssertionError('Network forbidden')
for owner,names in ((socket,('create_connection','getaddrinfo')),(socket.socket,('connect','connect_ex','sendto'))):
 for name in names:setattr(owner,name,blocked)
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
bridge=active_shared();package=bridge._PACKAGE_SUCCESSOR
root=pathlib.Path.cwd();path=root/sys.argv[1];raw=path.read_bytes()
token=bridge._COMPILED_TRANSACTION.set(bridge._transaction_compiler())
try:
 package.reviewed_inputs(root)
 path.write_bytes(raw+b'\\n# deliberate directed tamper\\n')
 try:package.reviewed_inputs(root)
 except RuntimeError:print('rejected')
 else:raise AssertionError('Tamper unexpectedly admitted')
finally:
 path.write_bytes(raw);bridge._COMPILED_TRANSACTION.reset(token)
"""
 env=dict(os.environ,PYTHONPATH=str(isolated_package),PYTHONDONTWRITEBYTECODE='1',AWS_EC2_METADATA_DISABLED='true',AWS_CONFIG_FILE='/nonexistent/offline',AWS_SHARED_CREDENTIALS_FILE='/nonexistent/offline')
 result=subprocess.run([sys.executable,'-B','-c',code,relative],cwd=isolated_package,env=env,capture_output=True,text=True,timeout=90)
 assert result.returncode==0,result.stderr[-9000:]
 assert result.stdout.strip()=='rejected'

@pytest.mark.parametrize('owner,name',[(package,'reviewed_inputs'),(package,'install'),(bridge,'verify_package_successor')])
@pytest.mark.parametrize('mutation',['identity','code'])
def test_new_admission_helpers_independently_attested(owner,name,mutation,monkeypatch):
 current=active_shared();current.reviewed_delta(SOURCE)
 if mutation=='identity':monkeypatch.setattr(owner,name,lambda *args,**kwargs:None)
 else:monkeypatch.setattr(getattr(owner,name),'__code__',(lambda *args,**kwargs:None).__code__)
 with pytest.raises(RuntimeError):current.reviewed_delta(SOURCE)

def test_package_existing_native_branches_and_registration_are_idempotent():
 current=active_shared();live_package=current._PACKAGE_SUCCESSOR
 assert live_package.original is package.original
 before=tuple(checks.CHECKS);canonical=package.original.reviewed_inputs
 receipt,cases=live_package.reviewed_inputs(SOURCE)
 assert len(cases)==9
 live_package.install();live_package.install()
 assert tuple(checks.CHECKS)==before
 assert package.original.reviewed_inputs is canonical
 assert live_package._INSTALLED is package.original._INSTALLED

def test_whole_bundle_failure_restores_canonical_package_state(monkeypatch):
 current=active_shared();live_package=current._PACKAGE_SUCCESSOR
 from peaso.checks import gcp_function_secret_page_admission_20261020 as pairs
 before=tuple(checks.CHECKS);installed=package.original._INSTALLED
 target=pairs.install.__code__
 def refuse(frame,event,arg):
  if event=='call' and frame.f_code is target:raise RuntimeError('deliberate post-package failure')
 previous=sys.getprofile()
 try:
  sys.setprofile(refuse)
  with pytest.raises(RuntimeError,match='deliberate post-package failure'):current.install_bundle()
 finally:sys.setprofile(previous)
 assert tuple(checks.CHECKS)==before
 assert live_package._INSTALLED is package.original._INSTALLED is installed
 assert current._COMPILED_TRANSACTION.get() is None

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
 'Dockerfile.peaso': {'after_sha256': '4c9d5881afbb9d6cd7609731976e0bfa54a067b8ce2409899f78f3b891f56611',
                      'after_size': 3528,
                      'before_sha256': '40fc0168fd51321bfee2e846dcbd25e87fc93dec9a8c4b410b466de449d7d2ba'},
 'docs/ai-review/README.md': {'after_sha256': 'd9e5acff28017bb7d019208e3bd03cbbe4c1e04ebef94099fd8ca941a802ac42',
                              'after_size': 33799,
                              'before_sha256': '20f1efc520acf6e2e5bab25250ba14b406ff5cf27a2520e8b4cb732890b735c8'},
 'docs/aws-review/field-producers.json': {'after_sha256': 'd53d256e0ab705f82d08970fc9feefedde002d87f9e162a296ecc7fb052d7767',
                                          'after_size': 13554725,
                                          'before_sha256': 'b3ca13d264da99c32d8f9ae621b25f2a4b30d5447895f12296b6693d87859937'},
 'docs/aws-review/field-producers.md': {'after_sha256': '045653236d36dffc2e9bade6bea555fd36a24bdd9f1cd8a7113a9b98661ecdbf',
                                        'after_size': 219524,
                                        'before_sha256': '04247063cc36363189cdd96a88453ba86ef01def28a2e0e48c3faf2a9eaa8f20'},
 'docs/aws-selected-s3-source-secret-permissions-20261020.md': {'after_sha256': '2038d7a7c0b5b0ae64c89dfd4098bf6d2000c9f02c40b9c1ab950aa2641cf13e',
                                                                'after_size': 4751,
                                                                'before_sha256': '25e2df2b3e887b297f18cdc2e0006ff86154eb9a3a69b0d939ac6aeb5483778e'},
 'docs/compliance-ledgers/descriptions/implemented-new-checks.json': {'after_sha256': 'd14e64e1e0159815f4ae1ea7a460ea3ab90e22157fde492ba2e68396e8386544',
                                                                      'after_size': 1479674,
                                                                      'before_sha256': '851bd2d3c62dacd6c3b0b721065aebc3f5a39a72496a885db3afc8188ada4cc9'},
 'docs/compliance-ledgers/manifest.json': {'after_sha256': '9bee24013d92976c77d41b3a0f09fb4c1d95a31226bc09a702acf1e2f2bfc88b',
                                           'after_size': 16080,
                                           'before_sha256': '3e315ea8bb35bd290d796016b66e0836d261dff8a3b0d192c7ec0acb6ca34320'},
 'docs/peaso-api-keys.md': {'after_sha256': 'd3dbc5205b516fdb237d7e9b7b82bffd3fb8864aa1af17f6459c22d95f83129e',
                            'after_size': 3570,
                            'before_sha256': '297029ca0bbaea768caa8de79a24c2fac09891c726755b6bc9f6f9033b04ae31'},
 'docs/peaso-aws-collector.md': {'after_sha256': 'e1267a63fd8f18e1369aec9a7bbad3d46071d8ba9ed6b328f682eff2a2d7e282',
                                 'after_size': 105944,
                                 'before_sha256': '90d1f4bc1d4e63321be43c6bb9e9edad935c894e272a9d607f044ac29f96002d'},
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
 'docs/secret-content-permissions.md': {'after_sha256': 'ed58768795f0ee8635c85b191cd946cfabc8502ae082572efa1b7a0057e32b63',
                                        'after_size': 27290,
                                        'before_sha256': '4402965d17df1e3db34e6d3f9827ce207f2e6483ecb1b3d47b2221359386c36e'},
 'frontend/src/AiReview.css': {'after_sha256': '0078fa46f6c4c4df287b7d556a2b33c91f00e714b9c0a2c61d547cbd90914c5a',
                               'after_size': 3343,
                               'before_sha256': 'eb60dd8d8dad12fd2c079d384fce4187fdf8bec7b9ed1984c1a59afb87c6637d'},
 'frontend/src/AiReview.tsx': {'after_sha256': 'c7d3f8361ee220c692397b64d9afa23563ba989424e8786b8348edf5169d1d8d',
                               'after_size': 13859,
                               'before_sha256': 'cf2662e9918a2bc27d86a163fedf99cd9665166f5cc195f7a07992c68dc25e61'},
 'frontend/src/ApiKeys.tsx': {'after_sha256': '1d91681f3066db42639eb580cdc2c3b3a49e6a90d5a5d8676b4d4137a5f9b8d3',
                              'after_size': 6101,
                              'before_sha256': '10835c3dc424453da4335e13dd78af770f5edf6edf61bdd98e2a9319128f8455'},
 'frontend/src/App.tsx': {'after_sha256': 'fc031652fd9bad2754542bc601ee59b8bd17d31e62635a5c1c5e9439af52f134',
                          'after_size': 22157,
                          'before_sha256': 'dfe8f0934540bfb730d296701f0514c212a0b6e0d09d91b11eef15ddf850c855'},
 'frontend/src/CodexSettings.tsx': {'after_sha256': '68e7f289b49b7fb71b9249be0838270e5c944c80c60f7a79a5665d3ce74e2467',
                                    'after_size': 10257,
                                    'before_sha256': 'ef87d186406c01bb8d50dbf47c9cbd53837ccb8b4810bb3a428c1d7a5b375f9a'},
 'frontend/src/ConnectorFieldHelp.tsx': {'after_sha256': '64241f81b243f4709a5be96178e9965dd3c3bcda6bdd2c1928f0b992194c5a4e',
                                         'after_size': 31262,
                                         'before_sha256': '94b347aa6026cd750773e984b0a241fc4c71dbbd01319cb9d417051e313c913f'},
 'frontend/src/FindingInspector.css': {'after_sha256': 'd4260cd6722cd5db41c749955dc2e5097c10600432644d2a1ea266c9569a4532',
                                       'after_size': 6642,
                                       'before_sha256': 'ff40a352ae34b9b885f1999eb0d7efa81b465d5ff2a21f6606ade37942b115ef'},
 'frontend/src/Findings.tsx': {'after_sha256': '1a1dad68d15b88066a5413ea93666f5e435ba516ee17312b52173bb998cdeedf',
                               'after_size': 42215,
                               'before_sha256': 'eedb7801b620866140ce2343cd102fde93ad7524e6cc280a11a6ccf3bb2de4da'},
 'frontend/src/GroupedFindingEvidence.tsx': {'after_sha256': '71a892c16f82a42e00809ce26cb7da99b8ad4460f058c430f94bae70f1e55c41',
                                             'after_size': 4258,
                                             'before_sha256': 'c1a5ff2437ff6b4a05b02aab9e3b98160fb2f4f3aa1c786dd27db14298d11795'},
 'frontend/src/Help.tsx': {'after_sha256': 'd1f7b0566001ca5a9ee7a5122ae2c1d45e48a6d9e8bf6755542854863f33249b',
                           'after_size': 18108,
                           'before_sha256': 'fabea81016902ee3775bcd086a7fdaf33c95bb53b7e94ae51d37d8a47da0d8e6'},
 'frontend/src/LeastPrivilege.css': {'after_sha256': '6e73bae9a3d40bba0309aa7fc244c22831a04109ace0b847e91e66cc15802394',
                                     'after_size': 5326,
                                     'before_sha256': '7916c1a5b067c078bc68a0177e1edc7c7ceca7c5af8e6927aaaeacca58aa42c1'},
 'frontend/src/LeastPrivilege.tsx': {'after_sha256': '586b19d1cd79cb4ca982f68a831332f08443a9e2882503751775f2a6c1efa3a8',
                                     'after_size': 11401,
                                     'before_sha256': 'e842a15bc0954b93e2cfc11512f9e807c250c547ee590ce35d28e4695042a69b'},
 'frontend/src/PrincipalExposure.tsx': {'after_sha256': 'e4ab316a4aec052f6b19a8852e52288d4501add09c2b237f4995598f931db537',
                                        'after_size': 3971,
                                        'before_sha256': '62c71be4f6bff0e38b7d29f845484de3cab844857c7a6e0e30a3986db8192d31'},
 'frontend/src/Scans.tsx': {'after_sha256': 'accd408c579a3a52388c65995efa3d642aad81cd465c8247db567acb6d281e0c',
                            'after_size': 24710,
                            'before_sha256': 'ccebc6f1e7eb5a5606dc62303c5e4658dcad637a5032e5e7e9fc967e894b0aee'},
 'frontend/src/Settings.tsx': {'after_sha256': '2cb3afcaaa580102fddbb5c22d61823c7eef629cdc3d351feb56bb8ed9d6afa5',
                               'after_size': 8713,
                               'before_sha256': '1a73319d37a713ec27a5ec37d09107183276935509784c7a9a5b4cf07614c222'},
 'frontend/src/api.ts': {'after_sha256': 'c9ba659d2da223da06e799b174bcefaed2f4cb59586ad5c692617fb46ecdbb04',
                         'after_size': 10628,
                         'before_sha256': '4da8704c963fe6e77ef1fcfbf9fe55b30284a60528767c011af453552bef9aff'},
 'frontend/src/authGuides.ts': {'after_sha256': '76881051b37606584b3c26c03e1a18daae45bd499a9ab1cd6a11182e6a80de26',
                                'after_size': 36164,
                                'before_sha256': '2da12d60c8a7345edbb58f3ab271c3a8c5b9b0b8f82ca1120ae55d9c0e1310ea'},
 'frontend/src/frameworkCatalog.json': {'after_sha256': 'd96055b51462bcae0cc09ed0db643c7e13467848eb8f8968b1f42bf9225bba89',
                                        'after_size': 127697,
                                        'before_sha256': '28ff79b4d96835ec0c191d9555efbbe8b61a146589574cbb12eff9d7b9d35650'},
 'frontend/src/styles.css': {'after_sha256': 'be45472eaaca19a121ae198b6f3de1543329b7aff91644acf3a89d4db3518ae3',
                             'after_size': 80648,
                             'before_sha256': '3be2d12484abbc3358bea03ee6f13b8a187e753f84b6a3dfd28046e33d0483e4'},
 'frontend/src/theme.css': {'after_sha256': '5993ac8804e0c60656df6fb8df3499f7e5d55d9b765bf8b223b8fb6aba2a16bf',
                            'after_size': 29557,
                            'before_sha256': 'a6320497f64a4fd21c8e7e9ab37e384acbc71c002d5bcc90ca587b878b641d93'},
 'frontend/src/types.ts': {'after_sha256': 'f3dff84c506da590686d5966a1629cd71a3572cdfa252440aa8df2cead979e98',
                           'after_size': 10943,
                           'before_sha256': '16da4d56687014db9fe4ba14b52b76b34399fd8050350a2a356e1e8db765bb32'},
 'frontend/tests/ai-access.spec.ts': {'after_sha256': '4eeba2a31ecd0241ab01720819782f7f7d9d68d83c2e4d41a87b6a32431883b5',
                                      'after_size': 1852,
                                      'before_sha256': '390e2ec277f41ae9b7e5f806ec1c2257f7e774f9f33bd6000663e10c616efbf3'},
 'frontend/tests/ai-review.spec.ts': {'after_sha256': '07e2ec729963cc2ee5ae6c7267f41b65d0bfee221c872491d81debaac9fdb880',
                                      'after_size': 30785,
                                      'before_sha256': '834bb6f3759a27202b168dc1684f1e9cb51816b8067329a3e2177547e2111734'},
 'frontend/tests/compose-api.spec.ts': {'after_sha256': 'd47836a4f78419ed11e5978d24d6903eb0e99a553925d3150273e2659ca92c8f',
                                        'after_size': 11087,
                                        'before_sha256': '17c8f0292af34908c492a246ba1d59184b69db931210e320b4a9833cbedf956d'},
 'frontend/tests/findings-presentation.spec.ts': {'after_sha256': 'fa31a5cd1709c250dd1a017cd24918dc3ef7687b00e89a49cf52343c56d44b6c',
                                                  'after_size': 41684,
                                                  'before_sha256': '33511e285ccb1b29d3e8423bd0966013c495a7ca1388c7a2ee9f468da1e92d18'},
 'frontend/tests/full-report-live.spec.ts': {'after_sha256': '2be041043227a85669809a1a17b53b8ff266b1560bb2a8410270f38061247b65',
                                             'after_size': 9248,
                                             'before_sha256': '8bfaa2d06cf01b9ed54a29836832c76a3860dab0a8775424f729efe2ce00f626'},
 'frontend/tests/grouped-finding-evidence.spec.ts': {'after_sha256': '71283ef9b06e600c5df96e9430b595951d3aec396f03ae9b5d89d719d7d26a8e',
                                                     'after_size': 5452,
                                                     'before_sha256': '77c695757730bcb239a5732d12d0be0bc8182801755fcad541fad6367bceba9b'},
 'frontend/tests/principal-exposure.spec.ts': {'after_sha256': '1dc21202cb750761133dceaa0e9ac668699eb1a1955fe3275e24d51813e2ab37',
                                               'after_size': 9108,
                                               'before_sha256': '573da2fb7f44f79e60359a2cd55f2329f2d8e342028915375c9c8484ab898e8a'},
 'frontend/tests/session-map.spec.ts': {'after_sha256': 'a446a66e7ca2635daf5a61689835d5bd7d9b798afd4dfa2cb8b076c5fa2ff0a5',
                                        'after_size': 9272,
                                        'before_sha256': '13e8a43b75015dc3eab14bb97143ca3a6a3b566b68e63d7ab2c4292caf6bff8f'},
 'frontend/tests/ui.spec.ts': {'after_sha256': '6ef7cbf4315156d6762434fc89971e2addf187ba5b37b68901f47a2b4debced2',
                               'after_size': 53443,
                               'before_sha256': 'f6ef5565ec9a91d615bfb6510bd1632561446ba5d28a1f3eed52ea97247be3ec'},
 'infra/aws/Dockerfile.worker': {'after_sha256': '9462e695d8f5de996a289d8f267b9e73219d251c799494549bccfb0e310ae6c1',
                                 'after_size': 2782,
                                 'before_sha256': 'e069d24c79065ac126c7c130cedea5da2c461ac6c72cc5fd7630aa99fbebf17b'},
 'infra/aws/iam.tf': {'after_sha256': '319e90d9f2f377be919c815ed27f433ae4f45868bbf3bb984f36c9fddfc213a2',
                      'after_size': 9503,
                      'before_sha256': '119086927a14a48dc52f0180eb10a75f0d6355a848de200b8028a1325d268e39'},
 'peaso/ai/agents/priorities.yaml': {'after_sha256': '82e77a4090dec82b866eee6df225684f4c60ae22c6c829990bb915d8ca229dbc',
                                     'after_size': 10777,
                                     'before_sha256': '950de2a095ee25219fe6770fc8913bcf5f4f6f17320a68adad4722924605916a'},
 'peaso/ai/auth.py': {'after_sha256': '417d70fe80bf510b3482c679f9b547272be77379546b3183fe771fd42bc613cf',
                      'after_size': 18371,
                      'before_sha256': '4698a34f11d32f5d61dfa62ed2abd82dbf7f484d7c88af3903ea59a0038ee9d9'},
 'peaso/ai/codex_relay_cli.py': {'after_sha256': 'a1e8c519b624ab30d131f1a4a070deb2eea8e780584a41b405f6212592539fb9',
                                 'after_size': 1571,
                                 'before_sha256': 'eb21e350afa98e319676e12b5b60dbe9b9ef516fbc203970267798a66e5d6aee'},
 'peaso/ai/contracts.py': {'after_sha256': '59edf654ad40e0f7afa06514eefd4d3635840083bfc47d7b2b76ebe656dd9052',
                           'after_size': 8414,
                           'before_sha256': '34b025dcb642d07f1c7a586437cdda006d4a34cb75f6de219f6511610a685df2'},
 'peaso/ai/fargate.py': {'after_sha256': '9b39ddbb3844744c81fff421ed643c912ab61339071700c69e01af8ad7ccb176',
                         'after_size': 9071,
                         'before_sha256': 'f619a772d49642fb32453f6b9c18038e7573ba0370671f7e43581fe507cf76c5'},
 'peaso/ai/model_relay.py': {'after_sha256': '38b983c2a628e0b8d67aff0c58cdc3dabf5569262386c3124edfbd26b760cb6a',
                             'after_size': 12638,
                             'before_sha256': 'c8ffb7196454a6b1214fe9a47deb014b3d1679a59855494a0069125ab4bf9c4a'},
 'peaso/ai/pipeline.py': {'after_sha256': '08ae9810b4436dbfec65b668362c342244e3fb9b776130b4b87730287b578134',
                          'after_size': 23075,
                          'before_sha256': 'cff1e0a4e346c407ddef53a3e3b984b9eed0ff965acb9fb54329bcdb6751aa56'},
 'peaso/ai/recommendations.schema.json': {'after_sha256': '816d9c36f3671973b9e8ca13f790732b28c8ac296c107582e517d581f2d9026b',
                                          'after_size': 1734,
                                          'before_sha256': '0006dee24add1dc64094eec8d8f93e3fe597a58a63cedabed70f0f0f99cd1d70'},
 'peaso/ai/runner.py': {'after_sha256': '34283810a05c9f06cb4046a98fc8b2689c0e85c2beb019caa9e658132c4b0197',
                        'after_size': 6065,
                        'before_sha256': 'd789f8a65af278d089bd9eaf18dc88d2dfa348b67f4f2d486a6b51f0aae9b997'},
 'peaso/ai/task_runtime.py': {'after_sha256': '85d5cd47ca3a586fc623dbd008ac1279784ebcd43d57fe0e696f4748012cea91',
                              'after_size': 7439,
                              'before_sha256': '1a8fd2234bcd145f08683449c0748fdf2a7741fb01b1e412799f85991366c02f'},
 'peaso/analysis/__init__.py': {'after_sha256': '4c253cf7b3ade56bd81bf02db0d5b57e3725bfcaa2b8041af1d66fc2962cd4fe',
                                'after_size': 15923,
                                'before_sha256': 'ddb92b18186d677c4297b40069b4b7e039d61e154aeb290b70b47e91922e2e73'},
 'peaso/analysis/common.py': {'after_sha256': '43f5f66f4ab5d99ea96fe122108ff04e2e8fe857c964bf755cdfe6d5772054d9',
                              'after_size': 13921,
                              'before_sha256': '3895ba27f4a153bfa6ed88dfef7d3628dfa1ec4786e4d319d29a0ca42981a656'},
 'peaso/analysis/iam.py': {'after_sha256': '851da1533afa9ec352964c65c26a08ae38d731bf9c4342e522564195fe350750',
                           'after_size': 39438,
                           'before_sha256': 'e78c5f41644b8ed2bd3adcc0cfb1346fa9a20f80c30fd63d067b94643745faa2'},
 'peaso/attack_detection/aws_apigateway_controls_next.py': {'after_sha256': '7630d9b580fe82027f7ad6c18fbc56d00bc31431e8d02b03f09a7d8f782f11d1',
                                                            'after_size': 8082,
                                                            'before_sha256': '889f18f39ecb7d2420e73ed649766b6b116c7ec8de4cceb5938e90a2a101d095'},
 'peaso/attack_detection/aws_apigateway_rest_next.py': {'after_sha256': '5ee85a40ba8adf61767eda6d0a51fa17955659bc73906c2c9b13f6a2b7ae1fbf',
                                                        'after_size': 14584,
                                                        'before_sha256': '18ab31e8b5b5e1307edb587f7a053c07f1729988414a7eb75998381f2aa11892'},
 'peaso/attack_detection/aws_kinesis_video_controls_next.py': {'after_sha256': 'bd468a871700f24b6ef3dd967bfc64cb507e28b7da7649f9d2ac2ac4286ff549',
                                                               'after_size': 5861,
                                                               'before_sha256': '51cb1690457da6ec9cb370cf3c4c015504a382acaada0d15426e2ec127e5725b'},
 'peaso/attack_detection/rules.py': {'after_sha256': '5dd59324f4d280feff8a8cfd4faad273a6ea959decb736f9a4722b2db5008053',
                                     'after_size': 88596,
                                     'before_sha256': 'c65b53b8f01ecfca2e4dbfc15d31f72f5915002c7a4b137aefb6c6cdbccf00a9'},
 'peaso/check_services.json': {'after_sha256': '4c632711a6d3cce98032390470ac2e2f4d05c07d576c7d074dfee0ff23e91ebf',
                               'after_size': 26769,
                               'before_sha256': '1a9c0705c8c95e5d100ef951d0f0689fa6685021a0f39a7159c6c38e95cd4458'},
 'peaso/checks/aws_bulk_clarity_reviewed.py': {'after_sha256': 'ef68d3aa110be7e5abd42f0f0bc9f2b859e332743c0048eb03035cdb7262fb55',
                                               'after_size': 204834,
                                               'before_sha256': 'af2d8d2bea36aec498658b5c559d489153f49a99fcd338ea44e961bd26ee8e18'},
 'peaso/checks/aws_compute_storage_clarity_reviewed.py': {'after_sha256': '6e960216a22a00ab7096c62a260c8d0cb64388ed2dc9b1753a986c55380f2c2b',
                                                          'after_size': 304457,
                                                          'before_sha256': '6cadd7cc05d873ed44e2c0a4848aea8c93adee16e12051274007785bca57807d'},
 'peaso/checks/aws_database_clarity_reviewed.py': {'after_sha256': '8863773e66615e1bfee1e3f63267726986abfcacdad0fe761c44d80f21177991',
                                                   'after_size': 122547,
                                                   'before_sha256': '51d749640427e40b41fbc91408e9a21b27dc581a013c77a32699eccbd2f6975c'},
 'peaso/checks/aws_final_clarity_reviewed.py': {'after_sha256': 'a5dabbd95b6f2c313aec83a5343d4724ed8c872fe3e4c1a567ab75b1bf03f12b',
                                                'after_size': 85560,
                                                'before_sha256': '1fac121f5b486fc4c063b94e9fa9f7850ac856ab42aff4b71573966d5336852e'},
 'peaso/checks/aws_finding_clarity_reviewed.py': {'after_sha256': '61c480f4d44dc4e1e79ae10ba234b31192e93ab606a9b94295d97739d0a65eae',
                                                  'after_size': 2150915,
                                                  'before_sha256': '6b20d911d7060a34d3e24dfb3716454a3a34b78bd4d36aa7a56b96351a9dc1a2'},
 'peaso/checks/aws_remaining_clarity_reviewed.py': {'after_sha256': '3278304ee70acd4f9a05fb77cec3dacbc084b3c1c3772d646bd0a923219fb960',
                                                    'after_size': 377167,
                                                    'before_sha256': '795e494658b989eecbd141fdcad1ce99e97dc81d9a18f06424c3068600d69775'},
 'peaso/checks/azure_finding_clarity_reviewed.py': {'after_sha256': '7534a2168774d272d1108c6f87c691880af7586d66d0822e067d37423b717675',
                                                    'after_size': 2633484,
                                                    'before_sha256': '747074079138e16c5c795a779a85bb59d8263981f7a3c88547be6a8df95a070d'},
 'peaso/checks/catalog.py': {'after_sha256': 'd13bf63e3f4071846ef27adb992711fea783ad410359901cfa531f928552391c',
                             'after_size': 29453,
                             'before_sha256': 'c24821bee09ad54f650825c43886bd69e9c7b3143b75f380fef370857fac4568'},
 'peaso/checks/claude_azure_data.py': {'after_sha256': 'e8fd6583fe2d61fd07a2001a3d91c1a7983998e0e76b33add898f8a097af377b',
                                       'after_size': 76299,
                                       'before_sha256': 'd4013488f1536f9be4425a690d3cb87ef73ae35c08e02b356d1ff1324c00d472'},
 'peaso/checks/finding_types.json': {'after_sha256': 'bbb5b22a1dd5f4c9d1029d7c1ddcada0ec85b31ef8e0aff50ffa83738d7396d6',
                                     'after_size': 284584,
                                     'before_sha256': 'cfd4550d48fea23c8b0a8ee91efb51de7d0db3dea516475eccc32bb10a9dd2a0'},
 'peaso/checks/gcp_artifact_file_secret_review_20261019.py': {'after_sha256': '83b18b9e43d88c7fa4271defd6cb9d1111e320814e7e4d8f191f010fba7ba0b2',
                                                              'after_size': 7137,
                                                              'before_sha256': '0fe7d4fcbcd953d913e2ffa1df5b08573f01c8527ff333d351ddd3e037b36e54'},
 'peaso/checks/gcp_composer_source_secret_review_20261019.py': {'after_sha256': '4d792063c7dfde93400aa5ca89c5637f978fbca645aae51aaba7e06ae7aa12b7',
                                                                'after_size': 10867,
                                                                'before_sha256': 'd176034b246ff2f901e767f52d3c02832ec192766f361e552852d579dd567027'},
 'peaso/checks/gcp_image_secret_review_20261019.py': {'after_sha256': '0c0e9e68f1a7a39457822e3f7a20195f21c1f61948efa5c4e6b3fa926872263b',
                                                      'after_size': 11222,
                                                      'before_sha256': '83fe957437bdb4a8142361bc4329af903dede65cb2e0242d2c35cda5211c79fd'},
 'peaso/checks/gcp_remaining_clarity_reviewed.py': {'after_sha256': 'c258932f160622ad8de576f2269b01b84d7b536881a4da9f946d8703690fa46c',
                                                    'after_size': 760769,
                                                    'before_sha256': '12a3e9449ce2495485533f19b512dc2454605a1abd2eaaa0fbe6b0f788fa8820'},
 'peaso/checks/gcp_scalar_clarity_reviewed.py': {'after_sha256': '9c329178ade3a675237bd1d362267ce95e41fc9de32f5deef97bbba7b4ad8246',
                                                 'after_size': 22139,
                                                 'before_sha256': '7286bbb8882867de213b1fee23d9834a0e85c67324bc033787d12642ae510b42'},
 'peaso/checks/gcp_selected_archive_secret_review_20261019.py': {'after_sha256': 'cde1fe3ec267ef201f7b9fbe432dd2266b36164b3ee6e20fa55d589f77388cfb',
                                                                 'after_size': 7805,
                                                                 'before_sha256': 'd7636cee350ce0aa0c9fc32f3a71ef141f960050abb0757af082772a4f315a6a'},
 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py': {'after_sha256': '1edae1338a7f2a7f8b13e5939b4e33ad01c79c7fe3d80f634c69f5243d2664ac',
                                                           'after_size': 12892,
                                                           'before_sha256': 'f397ee93b511f396bb49fb467e05a88e23a741e492a22dcb93d9f8d99aded5d0'},
 'peaso/checks/gcp_task_routine_secret_review_20261020.py': {'after_sha256': '7deb55ddf182adade8f6f0e2beb52a019ed30e62908698de5758fef7b99fa63b',
                                                             'after_size': 10779,
                                                             'before_sha256': '18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1'},
 'peaso/checks/hacktricks_scope.json': {'after_sha256': '9ee1a03f0cdd495c7b8a2e4e4ad2f138f22758d0aad574654c71eb9d2f0d1c77',
                                        'after_size': 534309,
                                        'before_sha256': 'd5badbc9699697ebb59fec66f9f320560182d8265105b7135c42e755ab497292'},
 'peaso/checks/hacktricks_scope.py': {'after_sha256': 'b0bf0b60e2b246de12b5ab646e6ac889eb82e007e05e7caa4b5fd3206ec6fcf2',
                                      'after_size': 1589,
                                      'before_sha256': '8c208ef4d137cc7a6409b2c4cdabcdb6d1818ec88b4f09d5e75e89e7aa1bb95f'},
 'peaso/checks/k8s_workload_clarity_reviewed.py': {'after_sha256': '4faad1de0c73c2fd38f87f0f384a111047373281aba51182e3c298e585c03fb5',
                                                   'after_size': 1546661,
                                                   'before_sha256': '03cb86e0f0b2aff3919c7acd99f96fdf0605405201fdd7952e0009df3d74e344'},
 'peaso/cli.py': {'after_sha256': '2b18af259c1cfc16c43041a1f7f9a9d53c93d3bbd935af307c842acded98c879',
                  'after_size': 12643,
                  'before_sha256': '64abe6b8c5128ffb41e92811766d8e6b263e683172ce754875958745cbe6a312'},
 'peaso/collectors/aws.py': {'after_sha256': '8c44955646e5f600a46f808157694411bd828e77989a37d70a73778ccd13011b',
                             'after_size': 199099,
                             'before_sha256': '6895fefeb9374e42df4f39234de826615f4660ed7d830027b6b91621dedd3255'},
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
 'peaso/collectors/aws_lambda_environment_secret_indicators.py': {'after_sha256': '52fbb1b2ba632e43fc40ff00ebc159271febfb2ec3a6d7785a8f9b354e54bd08',
                                                                  'after_size': 12667,
                                                                  'before_sha256': '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289'},
 'peaso/collectors/aws_package_content_indicators.py': {'after_sha256': '368f52e8d782d68a879b8badcdfd3fba02bee6b8d5c24f1b483e18a9d3584433',
                                                        'after_size': 33897,
                                                        'before_sha256': 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6'},
 'peaso/collectors/aws_s3_selected_source_secret_indicators.py': {'after_sha256': '1c109e57f899b62c5e8189f96e6a4153294000c59dc7ef789ffc024a9d5a908c',
                                                                  'after_size': 30080,
                                                                  'before_sha256': 'b040a3b23746561fe913b1bd985669a0820fdde72b12fd864c5f6b5b894e3053'},
 'peaso/collectors/aws_selected_configuration_secret_indicators.py': {'after_sha256': '5433b64154d3b98e59ef7c4590c32a4d624b024a5e0fc237894ef4b12f991e77',
                                                                      'after_size': 38979,
                                                                      'before_sha256': 'c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f'},
 'peaso/collectors/aws_user_data_secret_indicators.py': {'after_sha256': '28eeada41f9d1b10d31ccd469e1eec85d38c53def87fd520b2556bd598ee5161',
                                                         'after_size': 2201,
                                                         'before_sha256': '077b5d258d6728c0b712935d34899c0feb27e3d11f758a81e793a6a240016205'},
 'peaso/collectors/aws_workload_command_runtime_20261020.py': {'after_sha256': 'de543276807257ff814980b78e523be21de02cecab7f9b31b2cb7dfb0940b09d',
                                                               'after_size': 6824,
                                                               'before_sha256': '9dc132a81388ee3b228b8b1de0820aefe9bfb741be37ea4c082920254e5c96b5'},
 'peaso/collectors/aws_workload_command_source_20261020.py': {'after_sha256': 'a5aa7cba18e0acc377a505abed400d82d835eb9bf7650460d0623fea0b1d6778',
                                                              'after_size': 22948,
                                                              'before_sha256': 'c5c5c24b7fbd4b696903d38b6e84a02ad3ebfa35616e6378a67afb97b8ae757e'},
 'peaso/collectors/azure.py': {'after_sha256': '6704fed81629cf8b42c52569128b11c727ffefda8c54e4376ff65a30cf3f9dc1',
                               'after_size': 244144,
                               'before_sha256': 'b69db967e65722174e847116620b63c7de4f0da835e3edde1a882456dc37afea'},
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
 'peaso/collectors/gcp.py': {'after_sha256': 'ce4641f0a0de8163ca29dcb2c44df1e8e9e1dbfdf7df5eb4cfc1d0745e0540fe',
                             'after_size': 256770,
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
 'peaso/engine.py': {'after_sha256': 'ada6f16ead82cd450b11d0381bd48bc267de246fda67a5d4c25e37af091eb211',
                     'after_size': 144371,
                     'before_sha256': '8e00227aa81c91869e025f7f4c18426e6a2383c3eff05ae7d904fd63c34bfe5b'},
 'peaso/finding_observation.py': {'after_sha256': '2232b4bc5c705ed8afdec0dadfc6ad1b1b28517938325450f318ee3851231254',
                                  'after_size': 4596,
                                  'before_sha256': '5bbf65a0174ebdf613daafa280050ac37f22d36dd256842843234fdbd00e281c'},
 'peaso/finding_types.py': {'after_sha256': '2103ac2bfe7a1f1feaa852e2547db064a6184f1ea764a75dd9c6dcc98619f299',
                            'after_size': 1957,
                            'before_sha256': 'c8f13d627a6a1420b871b7cb2e5fd0684505788caaca7cef65c72c93e784111f'},
 'peaso/least_privilege.py': {'after_sha256': '7bc492c39c8592827ec583175bbe432d6f69e7cf8fba156e12a94d87fb336f50',
                              'after_size': 10927,
                              'before_sha256': '61e9aaf18953054eeee37e130f515a12d9f180cd06dc25f723345aaeb0b0ddf1'},
 'peaso/rulepacks/api_catalog.json.gz': {'after_sha256': '57bd8818096393ea56c7d721722232e0e2504f2474b5a5725a6ae96caca944c4',
                                         'after_size': 2560824,
                                         'before_sha256': 'bcf67724b2321eb218932408384988a07ddbaa7aefa9755cc70268ec83c481c6'},
 'peaso/rulepacks/api_catalog_manifest.json': {'after_sha256': 'a56300bbf39469f4e07f414878176eba09941a0fdc68fae5ae7a4e93310e5529',
                                               'after_size': 1062,
                                               'before_sha256': '48cb640816c19924fe377871b73a525ea74552f0435676e41143387bdc935755'},
 'peaso/rulepacks/catalog_summary.json': {'after_sha256': '280162c75538c856a8eb1646c7ef3db5ef54c4eef0f5873685bb9548ef31e533',
                                          'after_size': 50487,
                                          'before_sha256': 'd7e7b64aa8143e105869bcd64dd94d0f8df39d11bc7047ef310e228ef4f10116'},
 'peaso/rulepacks/check_descriptions.json': {'after_sha256': '84a5ebc5d41e6e507c3b27023bfebc9dd40c51b6fd024770e08da45376bc35fc',
                                             'after_size': 4398547,
                                             'before_sha256': 'e9efda68fd352ec174d406b66d17525a8df3d0e217427cb0cca063b9e232d096'},
 'peaso/rulepacks/compliance_lookup.json': {'after_sha256': '95c2fc3e31c8730aaa49ff827db504432db6e8e1aa78a3090c3323e7872bd9f8',
                                            'after_size': 3568494,
                                            'before_sha256': '75d3b6a1a454577bc82e1e71bd4ac5394f5365f38547af5e6b3d4d22b92b7f63'},
 'peaso/rulepacks/compliance_requirements.json': {'after_sha256': '02f8addfaacfcb475676bd02834ac0589321b8dbb5e3cb3d1ecbfa1d6605c649',
                                                  'after_size': 20188172,
                                                  'before_sha256': '7824cdc5e17d3900892d0f066576b8b6bc726adb6d754b6fcfdf50961be1f363'},
 'peaso/rulepacks/framework_catalog.json': {'after_sha256': '804eed918c8239e95cc74562d93141f1372852f6fcac11f52eae46bdd0018c86',
                                            'after_size': 939351,
                                            'before_sha256': '20b7add1167c5e0d12964cb2f3e1f021e0fdb3180e3c03677f0beba61d7f144f'},
 'peaso/rulepacks/native_catalog.json': {'after_sha256': '8a5137800c5af6f48f9a89573469e4431de812eef9223134af4b2f8ac826bfca',
                                         'after_size': 25807460,
                                         'before_sha256': '9172d6194c7d985ea72df522e0cb458d6313ab25b3d724fe5c29625e366e9e1b'},
 'peaso/rulepacks/remediation_aws_families_reviewed.json': {'after_sha256': '2bc00a89cbafef9555941ee3d2edbca4a8112bfb95f24ff5210509a3e7583e4c',
                                                            'after_size': 1563338,
                                                            'before_sha256': '6577458b6149df569672f777594f3c267a6a572bff2b63d88db0d9d60e545fda'},
 'peaso/rulepacks/remediation_aws_reviewed.json': {'after_sha256': '44b7a839e07512625ee5597315c5d3f5b3a51ed0fd094e3988bd0a355c72049b',
                                                   'after_size': 1745331,
                                                   'before_sha256': 'b19eef2e094da960355bfa3d1a78a2f4618742aa7d1eda18c4e0da1fe857fa8c'},
 'peaso/rulepacks/remediation_azure_reviewed.json': {'after_sha256': '79125774225588425ac791bcfe24ea1fc29d91edd69dd05c9e086f50cd4c0d7c',
                                                     'after_size': 381373,
                                                     'before_sha256': '07a2e7b7fe86d2203e9fe990a063874c08aa118a3084e8850136aadf36f40fa7'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json': {'after_sha256': '70acf720532286acc5f7f8fdfee14928dce45237a2e4b344edd5650c0e9dac2a',
                                                                     'after_size': 53374,
                                                                     'before_sha256': 'ebe28d47a1880fa09acc7f42022a1e199ac9c27992049d2ca074670b41d6d490'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json': {'after_sha256': 'f14498d67d8abf30da78d5209bb6a0ecd003a0aa3a21bc69d7d23511705e6cc0',
                                                                       'after_size': 42909,
                                                                       'before_sha256': 'a8f76c1a53926fa6cbbda666e80108b494d7933d77d9d39f6d1226f02937b91a'},
 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json': {'after_sha256': '10c964fa627bea08572001bcf8ecf298095c0c0a84ffce0e75c4f366b4444cfb',
                                                                     'after_size': 73974,
                                                                     'before_sha256': '5485734fd0351e2dc8f6862b65472164e05df802e32d9c08d061826d1f1492ca'},
 'peaso/rulepacks/remediation_compliance_new_azure.json': {'after_sha256': '895b06ddfe288462798d3f0641072570677994fc894f2fd8c34c0bd0a8e46887',
                                                           'after_size': 9020,
                                                           'before_sha256': 'ac2130282b35c03d408d4af20b8a05d34642d401746b25e2aa5d7fef1d2d1c53'},
 'peaso/rulepacks/remediation_compliance_new_k8s.json': {'after_sha256': '5f1ed90f96a88a9679b5d1da3726faac8d8d222707f58d88c9f5229783f1ac7a',
                                                         'after_size': 25902,
                                                         'before_sha256': '2edc3719ee1883f91b482eb5c89f31702b4286ed5066a20ad0adb018a516314e'},
 'peaso/rulepacks/remediation_curated.json': {'after_sha256': 'b00eac2c6c2bae62a3d926ed42fd93fc219a31bc293bfc44594d736cd98634d7',
                                              'after_size': 204445,
                                              'before_sha256': 'b425e641bb9b46c42c78d17821f37a9789031d6aa4cc2c52bd90ecd4a996f34b'},
 'peaso/rulepacks/remediation_details.json': {'after_sha256': '5c8749627b4f20e61274a6cae2cc19ddd44fc4d7528940b43237f99874bd3c25',
                                              'after_size': 1753119,
                                              'before_sha256': '9bd958901b844eda3d4a21d088ee952bbd4f76c46d904f9880b88fec34638dca'},
 'peaso/rulepacks/remediation_native_azure_review_20261020.json': {'after_sha256': 'e26592e05250ea4eb78113dc48059412274ab6a62eca0d4dd3cc9d7e4e3d5582',
                                                                   'after_size': 28050,
                                                                   'before_sha256': '8cb77c6ff3c9e529e66b2728b1ea01fc3f20f9a4358f34532d8144bbd52946ac'},
 'peaso/rulepacks/runtime_metadata.json': {'after_sha256': 'beac20cba53702566001e5912c0f5cf707ddef3200b5519c16a971914af5eae8',
                                           'after_size': 18535738,
                                           'before_sha256': 'a792979ad0ecac951ad23acc765b93a9414a023bc1a2aeba63988e65a366d3c7'},
 'peaso/secret_scanning.py': {'after_sha256': '853c402c0362565849c43cbd89cc82d1e5e8b1b5d8d25f6cc15706a48de6f55f',
                              'after_size': 17202,
                              'before_sha256': '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19'},
 'peaso/server/app.py': {'after_sha256': '7d45cb0273a2fc2e7e725e91d8933117855f5bbdebbff0e2ae003376ad514c90',
                         'after_size': 128250,
                         'before_sha256': '3cd6d5053c9522ce2842ac59778f087115a1e076b8ea14dbdf03c5e6e1d5ff9e'},
 'peaso/server/materialized_catalog.py': {'after_sha256': 'b88d07b9c091f2ed8446504290e0e4584eb66967c5903f9018ca793e7e888c7f',
                                          'after_size': 19272,
                                          'before_sha256': 'e57df7092383505b4c571df107fbe6b0c8c4b8c343da22e4044691b61e664876'},
 'peaso/server/validation.py': {'after_sha256': '4138d24864f709c2df457a81e9e9cc97e43aebf7327c6c3f34a809d1cf688c81',
                                'after_size': 60870,
                                'before_sha256': '71060735cab0da2e358c89bbd00963e63fa7166ede9089bc9f111a860e1b794d'},
 'peaso/storage/artifacts.py': {'after_sha256': 'fbeb7402aedd7ac2a252682db02b97957760e2e70e3a4344bec8eb93f3d5b497',
                                'after_size': 8651,
                                'before_sha256': 'de542a6dde456cf0975aa8bd61240933cbdefd2b83a600e3fe9a963c100c549e'},
 'peaso/storage/reports.py': {'after_sha256': 'fe66c4a8d509a8425b0739510d281ad01b580767c309c69012fea8b4d992edf9',
                              'after_size': 11779,
                              'before_sha256': '2416214b3021e55883fdf8ba1108f90a98f81f1192899b9806e43001eeb4e166'},
 'peaso/storage/runtime.py': {'after_sha256': '980fd107b762399ee3eb13968360e46d547c8a05d78e7ac81b8597312f08710e',
                              'after_size': 2097,
                              'before_sha256': '4a52941e15925e48296da78e3a8386a58a60de5bfb0ad0119d66a397886a2214'},
 'peaso/worker.py': {'after_sha256': '002f030ce1289e147eb4146b0e5a1a40535847a72cefe1c38ba045979c8c0030',
                     'after_size': 22285,
                     'before_sha256': '9c1e6d558aad8804996fef249ad3836d39498a23121436aab69cbe0a52384bb0'},
 'pyproject.toml': {'after_sha256': '8b7a1277aa568ec51ed611d9338c855175dcdac18e9e4d085273c97580da4260',
                    'after_size': 3073,
                    'before_sha256': 'd38efdc14025653b6f2f34c4da130341bd66f7c7b6ce3b94699e1289f894a9ce'},
 'scripts/peaso_compliance_materialize.py': {'after_sha256': '36b04f0ae9a9f3f2b3b39af32d6e62f0cce376f2b99b3fe07e7cd260b52628c8',
                                             'after_size': 16386,
                                             'before_sha256': 'b3d313f14a727384e7ba6f18ec875aa05155b39e52fcc59ea51c20a1084b6e65'},
 'scripts/peaso_deploy.py': {'after_sha256': '3e22307edd3748a7f66947002231b5a764fe7c45c77d2720885b9065e1295b70',
                             'after_size': 216100,
                             'before_sha256': '45dbcebc0e1162fa4a75498a232e5b7fb92e169dee60a356fb32446353d03af4'},
 'tests/gcp_referenced_source_historical_compatibility_20261020.py': {'after_sha256': '10fb7df3d7203823fe543019f91b67a5452b0ef176405ed3d716fe834bf702b9',
                                                                      'after_size': 14234,
                                                                      'before_sha256': '4a10826eaed04a02fefa686431f4cee55a29995ffb520d750b835b128f6ff1fd'},
 'tests/reviewed_guidance_presentation.py': {'after_sha256': 'ada663a6e52caf7e730841143894cf243ad46b0bb16d29770239fb75bb92b946',
                                             'after_size': 7029,
                                             'before_sha256': 'dae6b5aeef153c3eefa79334a0b2d518fa5c1b5bba36aefc6190f030e2b7c5ad'},
 'tests/test_attack_rule_source_selection.py': {'after_sha256': 'f7fba1f6679ac3baa1713a664c274e7faa92d0b9c5fadfe02472d4535139edfe',
                                                'after_size': 3313,
                                                'before_sha256': 'c50a6ac5ddc2572a680a9a6524ef07729dbd7bb9d6b59abd355cfcf6ebaf3bfc'},
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
 'tests/test_gcp_function_secret_paired_integration_20261020.py': {'after_sha256': '5617a459c76577a0fb9994c14775d23f879e821436d8a4fa2563e29f4f3025a3',
                                                                   'after_size': 20704,
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
 'tests/test_peaso_ai_output_validation.py': {'after_sha256': '74d2575acb0ed1ae8e6b1b87ca5292cd4fdcac7622c0a1f9d3f4d36147343657',
                                              'after_size': 7692,
                                              'before_sha256': '0f2af34ed70992f63bff0ace636cbb0cee9b19d81886ea4aa8d07a1f476ce770'},
 'tests/test_peaso_ai_review.py': {'after_sha256': '18e9743db2d5a9d7541486c251c239678f93e9df87a724d608353a92d87c1ac2',
                                   'after_size': 83828,
                                   'before_sha256': '4a719b6f27a279bb8de46180f7f111d4d97ac5e2f92f7dbb7bebb9d44fb5d3df'},
 'tests/test_peaso_analysis.py': {'after_sha256': 'c8203c5088c12aa239157cc33e5bd3ece860a358dbfa809c3ac6d88d466da7ee',
                                  'after_size': 22662,
                                  'before_sha256': '5a1c615950c60bfd0748f9b3565e7e3180c15f7894e6d510eca7949c0beac9b2'},
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
 'tests/test_peaso_finding_group_api.py': {'after_sha256': '4a563b95a9dcf2f33441b72764eeb26a81f86bed304ec494e7db01cc450b1e30',
                                           'after_size': 14681,
                                           'before_sha256': '25584e083bfcdc221cc7146e8c9ad2fb73eff42624a01cfb098c6e0977c216ac'},
 'tests/test_peaso_gcp_observation_source_parity.py': {'after_sha256': 'c72ffe2c90926b9da50394249184d0d6cc74cfe50b2a42a9ca435c08b2b478ba',
                                                       'after_size': 10690,
                                                       'before_sha256': 'e60b0f51c4f46b4fdbe22effc10298b769639601a5d17a69a38a9f1ce2d33075'},
 'tests/test_peaso_gcp_project_alias_pipeline.py': {'after_sha256': 'e4d4d6c7fdcc2d902fbb30a9da54ee072818b570d5e45a7591ff9f7b72b8df30',
                                                    'after_size': 14982,
                                                    'before_sha256': 'd30b785d6a82eac1a4a379beeaa671b9af5d9301ec72708fa27be4eb25018bdf'},
 'tests/test_peaso_least_privilege.py': {'after_sha256': '5e11a6340103a0bede88d5aa28360eaf693ca3df36b5fe543fe626b54a026add',
                                         'after_size': 8456,
                                         'before_sha256': '07156d5b2d2ef0f497bbdc778cd6122b98c758344c9ff872b1bbad83f0768df8'},
 'tests/test_peaso_perf_benchmark.py': {'after_sha256': '9d5c3f37d6609c0742b2a2fa043497717db77241a08d42a70be68ff0ca9080e8',
                                        'after_size': 21083,
                                        'before_sha256': '1750c6a1c2fc39a95f69d2d210c82946fd7ec84ab67333c64a26a172bb85721f'},
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
 'tests/test_provider_combined_source_bridge_20261020.py': {'after_sha256': '5a234fb04ec8e121bfd80c63ce69420b8df2da104c2b6eefcb93f34cc1a55e8e',
                                                            'after_size': 68437,
                                                            'before_sha256': '2a795bf08cf52ce103d4e978f2f66e64cf1229e2f9bc2ccc4766dd6fa385aaf8'}}
REVIEWABLE_CURRENT_PATHS = frozenset(['.github/workflows/tests.yml', 'Dockerfile.peaso', 'docs/ai-review/README.md', 'docs/aws-review/field-producers.json', 'docs/aws-review/field-producers.md', 'docs/aws-selected-s3-source-secret-permissions-20261020.md', 'docs/compliance-ledgers/descriptions/implemented-new-checks.json', 'docs/compliance-ledgers/manifest.json', 'docs/peaso-api-keys.md', 'docs/peaso-aws-collector.md', 'docs/peaso-aws-selected-codebuild-buildspecs.md', 'docs/peaso-aws-selected-workload-commands.md', 'docs/peaso-gcp-selected-job-images.md', 'docs/peaso-local.md', 'docs/secret-content-permissions.md', 'frontend/src/AiReview.css', 'frontend/src/AiReview.tsx', 'frontend/src/ApiKeys.tsx', 'frontend/src/App.tsx', 'frontend/src/CodexSettings.tsx', 'frontend/src/ConnectorFieldHelp.tsx', 'frontend/src/FindingInspector.css', 'frontend/src/Findings.tsx', 'frontend/src/GroupedFindingEvidence.tsx', 'frontend/src/Help.tsx', 'frontend/src/LeastPrivilege.css', 'frontend/src/LeastPrivilege.tsx', 'frontend/src/PrincipalExposure.tsx', 'frontend/src/Scans.tsx', 'frontend/src/Settings.tsx', 'frontend/src/api.ts', 'frontend/src/authGuides.ts', 'frontend/src/frameworkCatalog.json', 'frontend/src/styles.css', 'frontend/src/theme.css', 'frontend/src/types.ts', 'frontend/tests/ai-access.spec.ts', 'frontend/tests/ai-review.spec.ts', 'frontend/tests/compose-api.spec.ts', 'frontend/tests/findings-presentation.spec.ts', 'frontend/tests/full-report-live.spec.ts', 'frontend/tests/grouped-finding-evidence.spec.ts', 'frontend/tests/principal-exposure.spec.ts', 'frontend/tests/session-map.spec.ts', 'frontend/tests/ui.spec.ts', 'infra/aws/Dockerfile.worker', 'infra/aws/iam.tf', 'peaso/ai/agents/priorities.yaml', 'peaso/ai/auth.py', 'peaso/ai/codex_relay_cli.py', 'peaso/ai/contracts.py', 'peaso/ai/fargate.py', 'peaso/ai/model_relay.py', 'peaso/ai/pipeline.py', 'peaso/ai/recommendations.schema.json', 'peaso/ai/runner.py', 'peaso/ai/task_runtime.py', 'peaso/analysis/__init__.py', 'peaso/analysis/common.py', 'peaso/analysis/iam.py', 'peaso/attack_detection/aws_apigateway_controls_next.py', 'peaso/attack_detection/aws_apigateway_rest_next.py', 'peaso/attack_detection/aws_kinesis_video_controls_next.py', 'peaso/attack_detection/rules.py', 'peaso/check_services.json', 'peaso/checks/aws_bulk_clarity_reviewed.py', 'peaso/checks/aws_compute_storage_clarity_reviewed.py', 'peaso/checks/aws_database_clarity_reviewed.py', 'peaso/checks/aws_final_clarity_reviewed.py', 'peaso/checks/aws_finding_clarity_reviewed.py', 'peaso/checks/aws_remaining_clarity_reviewed.py', 'peaso/checks/azure_finding_clarity_reviewed.py', 'peaso/checks/catalog.py', 'peaso/checks/claude_azure_data.py', 'peaso/checks/finding_types.json', 'peaso/checks/gcp_artifact_file_secret_review_20261019.py', 'peaso/checks/gcp_composer_source_secret_review_20261019.py', 'peaso/checks/gcp_image_secret_review_20261019.py', 'peaso/checks/gcp_remaining_clarity_reviewed.py', 'peaso/checks/gcp_scalar_clarity_reviewed.py', 'peaso/checks/gcp_selected_archive_secret_review_20261019.py', 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py', 'peaso/checks/gcp_task_routine_secret_review_20261020.py', 'peaso/checks/hacktricks_scope.json', 'peaso/checks/hacktricks_scope.py', 'peaso/checks/k8s_workload_clarity_reviewed.py', 'peaso/cli.py', 'peaso/collectors/aws.py', 'peaso/collectors/aws_additional_secret_indicators.py', 'peaso/collectors/aws_code_log_content_indicators.py', 'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py', 'peaso/collectors/aws_codebuild_buildspec_source_20261020.py', 'peaso/collectors/aws_configuration_payload_secret_indicators.py', 'peaso/collectors/aws_configuration_secret_indicators.py', 'peaso/collectors/aws_lambda_environment_secret_indicators.py', 'peaso/collectors/aws_package_content_indicators.py', 'peaso/collectors/aws_s3_selected_source_secret_indicators.py', 'peaso/collectors/aws_selected_configuration_secret_indicators.py', 'peaso/collectors/aws_user_data_secret_indicators.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/aws_workload_command_source_20261020.py', 'peaso/collectors/azure.py', 'peaso/collectors/azure_acr_image_secret_indicators.py', 'peaso/collectors/azure_app_settings_secret_indicators.py', 'peaso/collectors/azure_databricks_notebook_secret_indicators.py', 'peaso/collectors/azure_devops_git_native.py', 'peaso/collectors/azure_devops_selected_content_secret_indicators.py', 'peaso/collectors/azure_function_package_integration_20261020.py', 'peaso/collectors/azure_ml_selected_asset_secret_indicators.py', 'peaso/collectors/azure_ml_selected_job_secret_indicators.py', 'peaso/collectors/azure_selected_configuration_secret_indicators.py', 'peaso/collectors/azure_selected_declaration_secret_indicators.py', 'peaso/collectors/azure_selected_log_sample_secret_indicators.py', 'peaso/collectors/azure_selected_storage_secret_indicators.py', 'peaso/collectors/gcp.py', 'peaso/collectors/gcp_additional_literal_secret_indicators.py', 'peaso/collectors/gcp_appengine_source_secret_indicators.py', 'peaso/collectors/gcp_artifact_file_secret_indicators.py', 'peaso/collectors/gcp_batch_referenced_source_20261020.py', 'peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py', 'peaso/collectors/gcp_composer_source_secret_indicators.py', 'peaso/collectors/gcp_configuration_secret_indicators.py', 'peaso/collectors/gcp_dataflow_referenced_source_20261020.py', 'peaso/collectors/gcp_dataform_secret_indicators.py', 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py', 'peaso/collectors/gcp_function_secret_indicators.py', 'peaso/collectors/gcp_function_secret_pairs_20261020.py', 'peaso/collectors/gcp_gke_literal_secret_indicators.py', 'peaso/collectors/gcp_image_secret_indicators.py', 'peaso/collectors/gcp_job_literal_secret_indicators.py', 'peaso/collectors/gcp_log_secret_indicators.py', 'peaso/collectors/gcp_notebook_airflow_secret_indicators.py', 'peaso/collectors/gcp_selected_archive_secret_indicators.py', 'peaso/collectors/gcp_selected_object_secret_indicators.py', 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py', 'peaso/collectors/gcp_sourcerepo_secret_indicators.py', 'peaso/collectors/gcp_workbench_referenced_source_20261020.py', 'peaso/collectors/k8s.py', 'peaso/collectors/k8s_literal_secret_indicators.py', 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py', 'peaso/engine.py', 'peaso/finding_observation.py', 'peaso/finding_types.py', 'peaso/least_privilege.py', 'peaso/rulepacks/api_catalog.json.gz', 'peaso/rulepacks/api_catalog_manifest.json', 'peaso/rulepacks/catalog_summary.json', 'peaso/rulepacks/check_descriptions.json', 'peaso/rulepacks/compliance_lookup.json', 'peaso/rulepacks/compliance_requirements.json', 'peaso/rulepacks/framework_catalog.json', 'peaso/rulepacks/native_catalog.json', 'peaso/rulepacks/remediation_aws_families_reviewed.json', 'peaso/rulepacks/remediation_aws_reviewed.json', 'peaso/rulepacks/remediation_azure_reviewed.json', 'peaso/rulepacks/remediation_compliance_batch_remaining_aws.json', 'peaso/rulepacks/remediation_compliance_batch_remaining_azure.json', 'peaso/rulepacks/remediation_compliance_batch_remaining_k8s.json', 'peaso/rulepacks/remediation_compliance_new_azure.json', 'peaso/rulepacks/remediation_compliance_new_k8s.json', 'peaso/rulepacks/remediation_curated.json', 'peaso/rulepacks/remediation_details.json', 'peaso/rulepacks/remediation_native_azure_review_20261020.json', 'peaso/rulepacks/runtime_metadata.json', 'peaso/secret_scanning.py', 'peaso/server/app.py', 'peaso/server/materialized_catalog.py', 'peaso/server/validation.py', 'peaso/storage/artifacts.py', 'peaso/storage/reports.py', 'peaso/storage/runtime.py', 'peaso/worker.py', 'pyproject.toml', 'scripts/peaso_compliance_materialize.py', 'scripts/peaso_deploy.py', 'tests/gcp_referenced_source_historical_compatibility_20261020.py', 'tests/reviewed_guidance_presentation.py', 'tests/test_attack_rule_source_selection.py', 'tests/test_aws_content_scan_selection_review.py', 'tests/test_aws_s3_runtime_admission_20261020.py', 'tests/test_azure_declaration_secret_integration_20261020.py', 'tests/test_azure_function_package_runtime_20261020.py', 'tests/test_azure_function_settings_production_integration_20261020.py', 'tests/test_azure_jit_parent_type_successor_20261020.py', 'tests/test_azure_k8s_current_review_bindings_20261020.py', 'tests/test_azure_log_sample_secret_integration_20261020.py', 'tests/test_azure_metadata_transport_fix_20261020.py', 'tests/test_azure_ml_selected_asset_secret_integration_20261020.py', 'tests/test_azure_monitoring_contacts_native_review_20261020.py', 'tests/test_azure_nsp_query_cmk_metadata_admission_20261020.py', 'tests/test_cross_cloud_secret_surface_audit_20261020.py', 'tests/test_gcp_appengine_source_secret_review_20261019.py', 'tests/test_gcp_artifact_file_secret_review_20261019.py', 'tests/test_gcp_cloudbuild_log_secret_review_20261019.py', 'tests/test_gcp_clouddeploy_source_secret_review_20261019.py', 'tests/test_gcp_composer_source_secret_review_20261019.py', 'tests/test_gcp_configuration_secret_review_20261019.py', 'tests/test_gcp_dataflow_batch_source_runtime_20261020.py', 'tests/test_gcp_dataform_secret_review_20261019.py', 'tests/test_gcp_final_services_fix_review_20261020.py', 'tests/test_gcp_final_services_review_20261020.py', 'tests/test_gcp_function_secret_paired_candidate_20261020.py', 'tests/test_gcp_function_secret_paired_integration_20261020.py', 'tests/test_gcp_function_secret_partial_positive_20261020.py', 'tests/test_gcp_function_source_secret_review_20261019.py', 'tests/test_gcp_image_secret_review_20261019.py', 'tests/test_gcp_secret_integration_acceptance_review.py', 'tests/test_gcp_secret_surface_audit_20261020.py', 'tests/test_gcp_sourcerepo_secret_review_20261019.py', 'tests/test_gcp_workbench_head3_runtime_admission_20261020.py', 'tests/test_gcp_workbench_source_runtime_20261020.py', 'tests/test_k8s_annotation_native_admission_portable_20261020.py', 'tests/test_k8s_kubelet_configmap_production_20261020.py', 'tests/test_k8s_network_inventory_successor_20261020.py', 'tests/test_k8s_selected_log_sample_production_20261020.py', 'tests/test_k8s_selected_log_sample_secret_review_20261020.py', 'tests/test_k8s_selected_metadata_secret_review_20261020.py', 'tests/test_peaso_ai_deadlines.py', 'tests/test_peaso_ai_fargate.py', 'tests/test_peaso_ai_output_validation.py', 'tests/test_peaso_ai_review.py', 'tests/test_peaso_analysis.py', 'tests/test_peaso_aws_ecr_artifacts_native.py', 'tests/test_peaso_aws_finding_clarity_reviewed.py', 'tests/test_peaso_azure_detection_telemetry.py', 'tests/test_peaso_azure_devops_git_native.py', 'tests/test_peaso_azure_evidence_explanations.py', 'tests/test_peaso_azure_guest_configuration_native.py', 'tests/test_peaso_azure_native_disclosures.py', 'tests/test_peaso_azure_tls_owner_policy.py', 'tests/test_peaso_checks_azure_ports_services.py', 'tests/test_peaso_checks_claude2_azure_behavior.py', 'tests/test_peaso_checks_claude_azure_data.py', 'tests/test_peaso_checks_claude_gcp_k8s_behavior.py', 'tests/test_peaso_checks_gcp_ports_services.py', 'tests/test_peaso_collector_swc2_azure_native.py', 'tests/test_peaso_collector_swc2_gcp_core.py', 'tests/test_peaso_collector_swc_gcp_wave.py', 'tests/test_peaso_finding_group_api.py', 'tests/test_peaso_gcp_observation_source_parity.py', 'tests/test_peaso_gcp_project_alias_pipeline.py', 'tests/test_peaso_least_privilege.py', 'tests/test_peaso_perf_benchmark.py', 'tests/test_peaso_platform_security.py', 'tests/test_peaso_provider_scope_observed_evidence.py', 'tests/test_provider_bridge_compiler_portability_20261020.py', 'tests/test_provider_bridge_prepared_ast_portability_20261020.py', 'tests/test_provider_combined_source_bridge_20261020.py'])
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
 from tests.provider_group_catalog_history_20261021 import predecessor_catalog
 value=predecessor_catalog(get_catalog());fingerprints=[]
 assert len(value['checks'])==3496
 for row in value['checks']:
  if 'clarity_evaluation_contract' in row:fingerprints.append(row.pop('clarity_evaluation_contract'))
 assert len(fingerprints)==3489 and set(fingerprints)=={evaluator_contract_fingerprint()}
 # Reverse only the exact source-reviewed single-control prose erratum.
 row=next(row for row in value['checks'] if row['id']=='aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis')
 expected={'description': 'Checks any internet-open port on in-use security groups with customer-managed ENIs; a single TCP 22 rule from 0.0.0.0/0 or ::/0 qualifies. API Gateway, VPC endpoint and amazon-elb interfaces are exempt. Reachability is not tested.', 'description_correction': {'version': 'aws-sg-any-port-description-20261021-v1', 'base_row_sha256': '33fa9afe7b6d4535d68c120c26369b4e5a83795e1035eb2ac35f78d3e8f5a147', 'source_revision': '7f9eb2cb11ea931f54acccb6e49152358ccf949d', 'source_url': 'https://github.com/prowler-cloud/prowler/blob/7f9eb2cb11ea931f54acccb6e49152358ccf949d/prowler/providers/aws/services/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port/ec2_securitygroup_allow_ingress_from_internet_to_any_port.py', 'helper_url': 'https://github.com/prowler-cloud/prowler/blob/7f9eb2cb11ea931f54acccb6e49152358ccf949d/prowler/providers/aws/services/ec2/lib/security_groups.py', 'source_relationship': 'Corrects descriptive all-ports prose to the existing any-port predicate. With an empty ports list, all_ports=True accepts a single matching ingress port; evaluator and managed-interface exceptions are unchanged. Frozen description history is retained.'}, 'fail_when': 'For an in-use group, any matching ingress rule from 0.0.0.0/0 or ::/0 (including a single TCP or UDP port, such as TCP 22) exists and at least one attached ENI is neither api_gateway_managed nor vpc_endpoint and is not owned by amazon-elb. Opening every port is not required.', 'pass_when': 'For an in-use group, no matching world-source ingress exists, or every attached ENI is api_gateway_managed, vpc_endpoint, or owned by amazon-elb.', 'rationale': 'Checks any internet-open port on in-use security groups with customer-managed ENIs; a single TCP 22 rule from 0.0.0.0/0 or ::/0 qualifies. API Gateway, VPC endpoint and amazon-elb interfaces are exempt. Reachability is not tested.'}
 assert {key:row[key] for key in expected}==expected
 row.update({'description': 'For in-use groups, checks world ingress and customer-managed interface attachments; selected API Gateway, endpoint and load-balancer-managed interfaces are exempt. A complete reachable path is not tested.', 'fail_when': 'FAIL when a world-source ingress rule opens all ports and the group is on an ENI other than API Gateway, VPC endpoint, or amazon-elb owned.', 'pass_when': 'PASS when a world-source ingress rule opens all ports and the group is on an ENI other than API Gateway, VPC endpoint, or amazon-elb owned is false.', 'rationale': 'For in-use groups, checks world ingress and customer-managed interface attachments; selected API Gateway, endpoint and load-balancer-managed interfaces are exempt. A complete reachable path is not tested.'})
 row.pop('description_correction')
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

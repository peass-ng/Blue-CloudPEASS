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
CURRENT_MANIFEST = 'd7605097dbcd5220cad0aecd2bbf4b2b08b839a442fed67644ba9161782556fd'
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
CURRENT_TREE = 'a5b712f658ccaed3b962839c3e7e634652db05f5f297def720002f3e65a72ea7'
PRIOR_CURRENT_TREE = "99207e6469fc5e5b3daf21324e6860599b116ffcf7d30600643bd229b0f11494"
CURRENT_ENTRY_COUNT = 690
CURRENT_EXCLUDED_COUNT = 3723
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

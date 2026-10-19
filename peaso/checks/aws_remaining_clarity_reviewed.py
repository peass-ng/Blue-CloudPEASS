"""250 individually bound AWS predicate reviews: concise guidance and risk.

Only wording and presentation risk change; signed criteria and native callbacks
remain intact. Observations describe configuration, not effective runtime access.
"""
from copy import deepcopy
import hashlib
import json
VERSION = "aws-remaining-clarity-v1"
ROWS = json.loads(r'''
{
  "aws.b.acm.expiry_thirty_days": {
    "description_base_sha256": "83c04e56bb0e6824dd7f5e439bdeef8ea5bff6ff97d454fa9617073a977dafaa",
    "description_fields": {
      "description": "Compares renewal-eligible ACM certificate expiry with the snapshot date; requires at least 30 calendar days."
    },
    "remediation_base_sha256": "f48017a484cec53dc6602044768e1af405c65511a1ba8d12ba76009b8f284fc6",
    "remediation_fields": {
      "caveats": [
        "The calendar-date check does not verify renewal progress or the certificate served by an endpoint."
      ],
      "steps": [
        "Renew or replace this certificate before dependent endpoints lose validity."
      ],
      "summary": "Renew or replace this certificate before dependent endpoints lose validity."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.expiry": "75e5a0250d16f61d9bb079db595a43fa745d26cf1f9fcf27fbb3fbfe1e39e7c8",
        "peaso.checks.aws_b_loadbalancing.timestamp": "befec2d97aa99ccea825c8ed08b79eeaa2efe3f49cbefd714b18d1afeea98b06"
      },
      "source_qualname": "expiry"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The renewal-eligible ACM certificate expires in fewer than 30 calendar days."
  },
  "aws.b.acm.no_failed_validation": {
    "description_base_sha256": "4cce7a033fb8203fceb23cf31cd348f618969c4a4c5731f58e123938a492420c",
    "description_fields": {
      "description": "Finds ACM certificates with FAILED or VALIDATION_TIMED_OUT status."
    },
    "remediation_base_sha256": "44974dc04cd82000d671d473a616a661eff729f0d18c1ce8f129a75db95bb691",
    "remediation_fields": {
      "caveats": [
        "This predicate does not assess endpoint deployment or flag every non-issued status."
      ],
      "steps": [
        "Resolve the reported validation or issuance problem if this certificate is still needed."
      ],
      "summary": "Resolve the reported validation or issuance problem if this certificate is still needed."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.failed_certificate": "a6dad9f89536a45c0ed01c1314e55c6e35182614f8c7be8db496ada8dc71b79c"
      },
      "source_qualname": "failed_certificate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ACM certificate failed validation or reached its validation timeout."
  },
  "aws.b.acm.no_wildcard_domain": {
    "description_base_sha256": "58ffcef2e60e00b3299cc84f9987d53df31e7ad55130d8f6fbe12e4316e8d174",
    "description_fields": {
      "description": "Checks whether the ACM certificate\u2019s primary DomainName begins with a wildcard."
    },
    "remediation_base_sha256": "c698054df5fa8eec5659c1413ade6b1915918d166cc3216fb8cc4c2c5bf90675",
    "remediation_fields": {
      "caveats": [
        "Wildcard certificates are often legitimate; this profile does not inspect SAN coverage."
      ],
      "steps": [
        "Consider a narrower certificate name if broad wildcard coverage is unnecessary."
      ],
      "summary": "Consider a narrower certificate name if broad wildcard coverage is unnecessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.wildcard": "1cbe9c03b3dff9f983b22ef3be232676bc285a8e1813a8c0c5b42364c440e117"
      },
      "source_qualname": "wildcard"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The certificate\u2019s primary domain begins with a wildcard."
  },
  "aws.b.acm.not_past_expiry_date": {
    "description_base_sha256": "9cfab45d2af1906863f521590122db2a64bac6798f24b4480765df875607429b",
    "description_fields": {
      "description": "Checks whether a renewal-eligible ACM certificate\u2019s expiry date is before the snapshot\u2019s calendar date."
    },
    "remediation_base_sha256": "3530d98f781db60a67ec6ad4ab15c1dfac12b6eceeb5f63fbd0a685965c2b5d8",
    "remediation_fields": {
      "caveats": [
        "Expiry earlier on the same day does not fail this calendar-date source comparison."
      ],
      "steps": [
        "Renew or replace the certificate if it is still required."
      ],
      "summary": "Renew or replace the certificate if it is still required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.not_expired": "79ccaa7281d053029c4103bdba7ce1340886bb6aede428ff9dbbd8ab5ce2a6ca",
        "peaso.checks.aws_b_loadbalancing.timestamp": "befec2d97aa99ccea825c8ed08b79eeaa2efe3f49cbefd714b18d1afeea98b06"
      },
      "source_qualname": "not_expired"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The certificate\u2019s expiry date is before the snapshot date."
  },
  "aws.b.acm.pending_validation_review": {
    "description_base_sha256": "ca799c3d1fd1f6c3f5701669e7a3e7cd7d76aab53f80e563a064b423076e72fc",
    "description_fields": {
      "description": "Reports ACM certificates pending validation for manual review; other recognized statuses pass this narrow check."
    },
    "remediation_base_sha256": "da622639f1a238cbeeb835440900060003474d1757762dcc7874972628ec4623",
    "remediation_fields": {
      "caveats": [
        "This check has no failing verdict and does not establish certificate validity."
      ],
      "steps": [
        "Complete validation if the pending certificate is still required; remove obsolete requests."
      ],
      "summary": "Complete validation if the pending certificate is still required; remove obsolete requests."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.pending_certificate": "5ae6745812207c868c7497a58ac53a34512ae79a6607ed6fbd262614fc89a200"
      },
      "source_qualname": "pending_certificate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ACM certificate requires validation review."
  },
  "aws.b.acm.rsa_minimum_2048": {
    "description_base_sha256": "7efee0c3df4abe255d504bc9744a4848e92575088bfeea01b92f7e3f86e3c2b1",
    "description_fields": {
      "description": "Parses the declared RSA key algorithm and requires at least 2048 bits; recognized EC algorithms are outside scope."
    },
    "remediation_base_sha256": "e002582a2d3f7955c67a5246a1dff4518cc97aa0b6a5492d77942fdb90384ec8",
    "remediation_fields": {
      "caveats": [
        "The API key-algorithm declaration does not identify the certificate actually served by endpoints."
      ],
      "steps": [
        "Replace this certificate with an RSA key of at least 2048 bits or a suitable supported EC certificate."
      ],
      "summary": "Replace this certificate with an RSA key of at least 2048 bits or a suitable supported EC certificate."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.rsa": "fed88e9526824b6e0275c6ac0d568651b66c898b6db9d6150643bb30f3fb8cb7"
      },
      "source_qualname": "rsa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ACM certificate declares an RSA key smaller than 2048 bits."
  },
  "aws.b.acm.transparency_logging": {
    "description_base_sha256": "99deef44d5e77043b48b4b6897f4a69b0cf2f7dc42773da2f245ba0c3aa8e132",
    "description_fields": {
      "description": "Checks the transparency-logging preference on non-imported ACM certificates."
    },
    "remediation_base_sha256": "2e7787712683d20e19ce0d212bb5a29a22b64751ad7399094b34fd93ccaf8b7d",
    "remediation_fields": {
      "caveats": [
        "This preference does not prove successful publication or establish certificate trust."
      ],
      "steps": [
        "Enable certificate transparency logging where applicable to this certificate\u2019s issuance policy."
      ],
      "summary": "Enable certificate transparency logging where applicable to this certificate\u2019s issuance policy."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "acm_certificate",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.certificate": "b88df4c27423f53890791460b8edffeef72359782619801301ea0526b60e1003",
        "peaso.checks.aws_b_loadbalancing.transparency": "3eb8f3ab58a1995aa6bf868696ab6ace02e8734293a350ea4fa4a852b97a60f2"
      },
      "source_qualname": "transparency"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The non-imported ACM certificate disables transparency logging."
  },
  "aws.b.alb.access_logs": {
    "description_base_sha256": "ce77bc0efda1ecce481bdd8e77eea8c5aaa041ca067aa79a036e5e7016341d17",
    "description_fields": {
      "description": "Checks the S3 access logging attribute on application load balancers."
    },
    "remediation_base_sha256": "0123c5e164f64748bd571d4b712ff2f8f89b08f57d3e6b9b5525d9d30d1abfad",
    "remediation_fields": {
      "caveats": [
        "This declared setting does not establish log delivery, healthy traffic or recovery."
      ],
      "steps": [
        "Enable S3 access logging where required for this application load balancer."
      ],
      "summary": "Enable S3 access logging where required for this application load balancer."
    },
    "reviewed_binding": {
      "closure": {
        "key": "access_logs.s3.enabled"
      },
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing._attribute.<locals>.evaluate": "fc75bd86e5e07b7139c35704767d9b0ce9ed03ef46ccb98bcac329c1662341ba",
        "peaso.checks.aws_b_loadbalancing.lb_attrs": "b80ae8885f5f9a9eddba0f0f6a3e58e292ab043bd4f8e1a3f019c3010f8774e5"
      },
      "source_qualname": "_attribute.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application load balancer has S3 access logging disabled."
  },
  "aws.b.alb.deletion_protection": {
    "description_base_sha256": "553bc43ddc6acf031d06b79312bb905adc6b6f8ca2835b40eaa1bdcc0196f5fe",
    "description_fields": {
      "description": "Checks the deletion protection attribute on application load balancers."
    },
    "remediation_base_sha256": "a56a014da3feddbe1e7fc99158c581dd85caa5e29dfc6ecc51df80cb6f46f339",
    "remediation_fields": {
      "caveats": [
        "This declared setting does not establish log delivery, healthy traffic or recovery."
      ],
      "steps": [
        "Enable deletion protection where required for this application load balancer."
      ],
      "summary": "Enable deletion protection where required for this application load balancer."
    },
    "reviewed_binding": {
      "closure": {
        "key": "deletion_protection.enabled"
      },
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing._attribute.<locals>.evaluate": "fc75bd86e5e07b7139c35704767d9b0ce9ed03ef46ccb98bcac329c1662341ba",
        "peaso.checks.aws_b_loadbalancing.lb_attrs": "b80ae8885f5f9a9eddba0f0f6a3e58e292ab043bd4f8e1a3f019c3010f8774e5"
      },
      "source_qualname": "_attribute.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application load balancer has deletion protection disabled."
  },
  "aws.b.alb.desync_mode": {
    "description_base_sha256": "ec7ed14ee24b7a3093dcc8f4e6ce68f0569cadb35b15bdc9e4e9d306ebc17dff",
    "description_fields": {
      "description": "Checks that the application load balancer uses defensive or strictest HTTP desync mitigation."
    },
    "remediation_base_sha256": "268fd031881294ec0777c33c6d0e1c26e28fe18e06e2a793d8f16477f4fe6815",
    "remediation_fields": {
      "caveats": [
        "Header dropping alone does not satisfy this exact mitigation-mode profile."
      ],
      "steps": [
        "Use defensive or strictest desync mitigation after checking application compatibility."
      ],
      "summary": "Use defensive or strictest desync mitigation after checking application compatibility."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.desync": "8c9e3ff71f920838c1c1c4db38009e2609a1214257dcb9b0f3d9ac594b71c617",
        "peaso.checks.aws_b_loadbalancing.lb_attrs": "b80ae8885f5f9a9eddba0f0f6a3e58e292ab043bd4f8e1a3f019c3010f8774e5"
      },
      "source_qualname": "desync"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application load balancer uses monitor-only HTTP desync mitigation."
  },
  "aws.b.alb.invalid_header_dropping": {
    "description_base_sha256": "5a86de6cd96a9cede9cfe414b43cfd1ffa6f4cd3572adb0fd03e1ce10b199b20",
    "description_fields": {
      "description": "Checks the invalid HTTP-header dropping attribute on application load balancers."
    },
    "remediation_base_sha256": "49721a7d08b90f9f0d1e6bb8521f0d4f47c2946a6dab1f50217aa06177db5da2",
    "remediation_fields": {
      "caveats": [
        "This declared setting does not establish log delivery, healthy traffic or recovery."
      ],
      "steps": [
        "Enable invalid HTTP-header dropping where required for this application load balancer."
      ],
      "summary": "Enable invalid HTTP-header dropping where required for this application load balancer."
    },
    "reviewed_binding": {
      "closure": {
        "key": "routing.http.drop_invalid_header_fields.enabled"
      },
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing._attribute.<locals>.evaluate": "fc75bd86e5e07b7139c35704767d9b0ce9ed03ef46ccb98bcac329c1662341ba",
        "peaso.checks.aws_b_loadbalancing.lb_attrs": "b80ae8885f5f9a9eddba0f0f6a3e58e292ab043bd4f8e1a3f019c3010f8774e5"
      },
      "source_qualname": "_attribute.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application load balancer has invalid HTTP-header dropping disabled."
  },
  "aws.b.apigateway.client_certificate": {
    "description_base_sha256": "01e43cea44393819aecdaf9a3c1267d4b16fc9450d6e295709a25c5770b23d27",
    "description_fields": {
      "description": "Checks whether the REST API stage includes a client-certificate identifier."
    },
    "remediation_base_sha256": "c3c86dfe6e5ad2fdd16bf347d0ee0b0966b087011f732b445e7061269a621f0c",
    "remediation_fields": {
      "caveats": [
        "Reference presence does not establish certificate validity, backend use or WAF effectiveness."
      ],
      "steps": [
        "Configure a suitable client-certificate identifier if this API requires it."
      ],
      "summary": "Configure a suitable client-certificate identifier if this API requires it."
    },
    "reviewed_binding": {
      "closure": {
        "field": "clientCertificateId"
      },
      "constants": {},
      "kind": "rest_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway._presence.<locals>.evaluate": "55864754352f18bd010f311737ea66c23fa877b67158bb7529e4f79f375c4356",
        "peaso.checks.aws_b_apigateway.stage": "275a2b4af23bd8bc74c3d722cbe50f6e39b199bf30cb58b95891ba7b448fbd3d"
      },
      "source_qualname": "_presence.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST API stage omits its client-certificate identifier."
  },
  "aws.b.apigateway.http_execution_logging": {
    "description_base_sha256": "dd775606219f38492e8541fb32d842bed4248a3ceafaea43b1400a6ed1ec365f",
    "description_fields": {
      "description": "Checks the APIv2 default-route execution-logging level for INFO or ERROR."
    },
    "remediation_base_sha256": "68a920e09b9dcca2c1a2511d746c1590545ac4c075145fb428bc774fbdee6147",
    "remediation_fields": {
      "caveats": [
        "A logging-level declaration does not prove delivery or coverage of individual overrides."
      ],
      "steps": [
        "Enable appropriate execution logging if this API/stage supports and needs it."
      ],
      "summary": "Enable appropriate execution logging if this API/stage supports and needs it."
    },
    "reviewed_binding": {
      "closure": {
        "family": "http"
      },
      "constants": {},
      "kind": "http_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway._logging.<locals>.evaluate": "e6c8709470626dabbfe811957fc4db37ba1202080e66c9429a0eac1a46dc1447",
        "peaso.checks.aws_b_apigateway.method_settings": "d9e9529621fe3b8937fd5eb6aa7cf60d87b9590ec62e5caeabfb1dca95d40070",
        "peaso.checks.aws_b_apigateway.stage": "275a2b4af23bd8bc74c3d722cbe50f6e39b199bf30cb58b95891ba7b448fbd3d"
      },
      "source_qualname": "_logging.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The APIv2 default-route settings disable execution logging."
  },
  "aws.b.apigateway.private_endpoint_type": {
    "description_base_sha256": "ba5ed96fa287f5ce9a1f7a97c3e2dbb74588dea01d740b414b92b292cf6b86fa",
    "description_fields": {
      "description": "Checks whether REST API endpoint types include PRIVATE."
    },
    "remediation_base_sha256": "d30c679d386ee68be58452965ca19509396633df9a8f584b0d7377f5050d6582",
    "remediation_fields": {
      "caveats": [
        "Public APIs can be intentional; endpoint type does not assess authentication or network reachability."
      ],
      "steps": [
        "Use a private endpoint when the API does not need public clients."
      ],
      "summary": "Use a private endpoint when the API does not need public clients."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rest_api",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway.private_api": "70dc30469a2295a31b9c86dd8536542daccd36afbfae56dd4c26c9c3d529a43e"
      },
      "source_qualname": "private_api"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST API does not declare a PRIVATE endpoint type."
  },
  "aws.b.apigateway.rest_execution_logging": {
    "description_base_sha256": "018a093c596f482580a7cea621f632319adcafd8bc534d885d5a00c2058a77e7",
    "description_fields": {
      "description": "Checks the REST wildcard-method execution-logging level for INFO or ERROR."
    },
    "remediation_base_sha256": "ebf82d0ae460b0560554c950212265713af8c27fcfc0bbc08e8976d29c5472b1",
    "remediation_fields": {
      "caveats": [
        "A logging-level declaration does not prove delivery or coverage of individual overrides."
      ],
      "steps": [
        "Enable appropriate execution logging if this API/stage supports and needs it."
      ],
      "summary": "Enable appropriate execution logging if this API/stage supports and needs it."
    },
    "reviewed_binding": {
      "closure": {
        "family": "rest"
      },
      "constants": {},
      "kind": "rest_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway._logging.<locals>.evaluate": "e6c8709470626dabbfe811957fc4db37ba1202080e66c9429a0eac1a46dc1447",
        "peaso.checks.aws_b_apigateway.method_settings": "d9e9529621fe3b8937fd5eb6aa7cf60d87b9590ec62e5caeabfb1dca95d40070",
        "peaso.checks.aws_b_apigateway.stage": "275a2b4af23bd8bc74c3d722cbe50f6e39b199bf30cb58b95891ba7b448fbd3d"
      },
      "source_qualname": "_logging.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST wildcard-method settings disable execution logging."
  },
  "aws.b.apigateway.rest_xray": {
    "description_base_sha256": "28848dcaf5159b46c4a2bddd2c9a01f40c3d0a099abec1871448118eb37a039c",
    "description_fields": {
      "description": "Reads the REST API stage X-Ray tracing flag."
    },
    "remediation_base_sha256": "357329f8f71b2eed5e6ced0afe357f17e392961aeea79b9727313b510d88adac",
    "remediation_fields": {
      "caveats": [
        "Tracing is optional and does not replace access or security audit logs."
      ],
      "steps": [
        "Enable X-Ray if distributed tracing is needed for this API."
      ],
      "summary": "Enable X-Ray if distributed tracing is needed for this API."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rest_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway.stage": "275a2b4af23bd8bc74c3d722cbe50f6e39b199bf30cb58b95891ba7b448fbd3d",
        "peaso.checks.aws_b_apigateway.xray": "3d90cf1d49b9b1e7b5eccd9c4c2baf6fb351c8a9d33dd2441a9f85efe1401fdf"
      },
      "source_qualname": "xray"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST API stage disables X-Ray tracing."
  },
  "aws.b.apigateway.waf_reference": {
    "description_base_sha256": "77da3ccaa58f7e6d7281d85a9da9100a960385b0e5e3c009fcfa82434a725969",
    "description_fields": {
      "description": "Checks whether the REST API stage includes a WAF ACL ARN."
    },
    "remediation_base_sha256": "969a1ca83ea9d9efc4f279c3cafb41249da51f282db15db9e265f5cdf91874ae",
    "remediation_fields": {
      "caveats": [
        "Reference presence does not establish certificate validity, backend use or WAF effectiveness."
      ],
      "steps": [
        "Configure a suitable WAF ACL ARN if this API requires it."
      ],
      "summary": "Configure a suitable WAF ACL ARN if this API requires it."
    },
    "reviewed_binding": {
      "closure": {
        "field": "webAclArn"
      },
      "constants": {},
      "kind": "rest_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway._presence.<locals>.evaluate": "55864754352f18bd010f311737ea66c23fa877b67158bb7529e4f79f375c4356",
        "peaso.checks.aws_b_apigateway.stage": "275a2b4af23bd8bc74c3d722cbe50f6e39b199bf30cb58b95891ba7b448fbd3d"
      },
      "source_qualname": "_presence.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST API stage omits its WAF ACL ARN."
  },
  "aws.b.apigateway.wildcard_cache_encryption": {
    "description_base_sha256": "d3a1fecfa6c6cf16f5d0a9eb643ba64ff06eccc1c6a22f6c4e8664d151139f11",
    "description_fields": {
      "description": "Checks that REST API wildcard method settings explicitly enable both caching and cache encryption."
    },
    "remediation_base_sha256": "00a259881208b6b6021309e0cdbb6354e9c74bee3da31d41356f1f24e9515a33",
    "remediation_fields": {
      "caveats": [
        "This literal profile also fails disabled caching, which does not mean unencrypted cached data exists."
      ],
      "steps": [
        "Enable cache encryption if caching is needed; retain uncached behavior when caching is unsuitable."
      ],
      "summary": "Enable cache encryption if caching is needed; retain uncached behavior when caching is unsuitable."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rest_api_stage",
      "module": "peaso.checks.aws_b_apigateway",
      "predicate_sources": {
        "peaso.checks.aws_b_apigateway.cache": "6772bf5852681536413bfce44a47d0bd51b83e69346eac46c84463f7eeaf90f2",
        "peaso.checks.aws_b_apigateway.method_settings": "d9e9529621fe3b8937fd5eb6aa7cf60d87b9590ec62e5caeabfb1dca95d40070"
      },
      "source_qualname": "cache"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "REST API wildcard settings do not enable both caching and cache encryption."
  },
  "aws.b.aurora.mysql_audit_export": {
    "description_base_sha256": "af60d6a6a93a50bba5302374e052f38b092f380412e86c1ac7990aadb4970df4",
    "description_fields": {
      "description": "Checks that Aurora MySQL declares the audit CloudWatch log export."
    },
    "remediation_base_sha256": "9d748bb4fdd9759edbfa847e1d2754b83a7bed192a413dabdfb63c0ba3c0fba8",
    "remediation_fields": {
      "caveats": [
        "An export declaration does not prove audit generation or delivery."
      ],
      "steps": [
        "Enable the audit log export if database auditing is required."
      ],
      "summary": "Enable the audit log export if database auditing is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_cluster",
      "module": "peaso.checks.aws_b_storage",
      "predicate_sources": {
        "peaso.checks.aws_b_storage.audit_export": "b1e78b0f545e6f0e2538f8b5d621edd28182db9fb7712970acf65015f8484f09"
      },
      "source_qualname": "audit_export"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Aurora MySQL cluster does not declare the audit log export."
  },
  "aws.b.aurora.mysql_copy_snapshot_tags": {
    "description_base_sha256": "fc476f11416639048e6cb9511b7696e11480bead5e8f50c57d6fc4cd3de3d18c",
    "description_fields": {
      "description": "Checks CopyTagsToSnapshot on aurora-mysql clusters."
    },
    "remediation_base_sha256": "36a14806e02093c94334f7373853d4183a4dd7d8af0b939e7a64cb78a73f724b",
    "remediation_fields": {
      "caveats": [
        "Tag copying does not create backups or prove recovery."
      ],
      "steps": [
        "Enable snapshot tag copying if these tags are needed for ownership or backup management."
      ],
      "summary": "Enable snapshot tag copying if these tags are needed for ownership or backup management."
    },
    "reviewed_binding": {
      "closure": {
        "engine": "aurora-mysql"
      },
      "constants": {},
      "kind": "rds_cluster",
      "module": "peaso.checks.aws_b_storage",
      "predicate_sources": {
        "peaso.checks.aws_b_storage._copy_tags.<locals>.evaluate": "54bd954c53ab10102403b97241401315f515c5d5ff23e3b16e1f67177c9a80e6"
      },
      "source_qualname": "_copy_tags.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The aurora-mysql cluster does not copy tags to snapshots."
  },
  "aws.b.aurora.postgres_copy_snapshot_tags": {
    "description_base_sha256": "25a6b1dd0b506ae231e1a67a462c1a5f6095485ec2dac75fa47503a382a94dfc",
    "description_fields": {
      "description": "Checks CopyTagsToSnapshot on aurora-postgresql clusters."
    },
    "remediation_base_sha256": "e7af0d6fdadbb4f9cde390e245851e4b585899f71230f38b5a4497c1f7f4aebf",
    "remediation_fields": {
      "caveats": [
        "Tag copying does not create backups or prove recovery."
      ],
      "steps": [
        "Enable snapshot tag copying if these tags are needed for ownership or backup management."
      ],
      "summary": "Enable snapshot tag copying if these tags are needed for ownership or backup management."
    },
    "reviewed_binding": {
      "closure": {
        "engine": "aurora-postgresql"
      },
      "constants": {},
      "kind": "rds_cluster",
      "module": "peaso.checks.aws_b_storage",
      "predicate_sources": {
        "peaso.checks.aws_b_storage._copy_tags.<locals>.evaluate": "54bd954c53ab10102403b97241401315f515c5d5ff23e3b16e1f67177c9a80e6"
      },
      "source_qualname": "_copy_tags.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The aurora-postgresql cluster does not copy tags to snapshots."
  },
  "aws.b.classic_elb.desync_mode": {
    "description_base_sha256": "7148d70677da203ae40103bf0c4d869b853c6539facdb4c21572657d41a5685d",
    "description_fields": {
      "description": "Checks that the Classic load balancer uses defensive or strictest HTTP desync mitigation."
    },
    "remediation_base_sha256": "62d7706396255523a7a5c7d0d65247274859242fd1da1e523300f2a9ebea5ed7",
    "remediation_fields": {
      "caveats": [
        "Header dropping alone does not satisfy this exact mitigation-mode profile."
      ],
      "steps": [
        "Use defensive or strictest desync mitigation after checking application compatibility."
      ],
      "summary": "Use defensive or strictest desync mitigation after checking application compatibility."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.classic_desync": "9647f42954f581aaaa75a87c4cd06bda145c50ec33512df1ea639f71811ab84f"
      },
      "source_qualname": "classic_desync"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Classic load balancer uses monitor-only HTTP desync mitigation."
  },
  "aws.b.classic_elb.encrypted_listeners": {
    "description_base_sha256": "2c5353f6dbe92b5a1df4582444c9d5d8168fec83576e833befeeba7f11ccc950",
    "description_fields": {
      "description": "Checks each declared Classic ELB listener protocol for HTTPS, SSL or TLS."
    },
    "remediation_base_sha256": "c02f0a4bd34a5f0e125428d0ca75dc32a93b19f29cbdd5524ca11ff040a3f251",
    "remediation_fields": {
      "caveats": [
        "A protocol label does not validate the certificate or enabled cipher suites."
      ],
      "steps": [
        "Use HTTPS or TLS for listeners carrying data that needs transport protection."
      ],
      "summary": "Use HTTPS or TLS for listeners carrying data that needs transport protection."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.classic_tls": "8b406e7109cc66623e9e1057e99dd658f6e7053dead57385ce573aef100f5ab8"
      },
      "source_qualname": "classic_tls"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Classic ELB listener declares a protocol other than HTTPS, SSL or TLS."
  },
  "aws.b.classic_elb.multiple_az": {
    "description_base_sha256": "dcd16f81454658ac3c0f3c6585a8eefbbdb612ab8aae8a605ddaf9edc30b5de8",
    "description_fields": {
      "description": "Counts declared availability-zone entries on the Classic load balancer; requires at least two."
    },
    "remediation_base_sha256": "e0f72cd1a78943fc834abdaf0c3ffa4a3939286ce4228fecd4e82f2e85cde8b1",
    "remediation_fields": {
      "caveats": [
        "This source counts entries, not distinct zones, and does not test failover."
      ],
      "steps": [
        "Use at least two suitable availability zones if this service requires redundancy."
      ],
      "summary": "Use at least two suitable availability zones if this service requires redundancy."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.classic_zones": "3087731ad6403191f677879ae2053b24a893200792ef3926792ff7fff7bb0846"
      },
      "source_qualname": "classic_zones"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Classic load balancer declares fewer than two availability-zone entries."
  },
  "aws.b.cloudfront.custom_acm_certificate": {
    "description_base_sha256": "344c0ca7bbe85d6391f8d4c02511499f685819da87ba13be1b3c3738f980d289",
    "description_fields": {
      "description": "Checks presence of both ACMCertificateArn and Certificate in the viewer-certificate configuration."
    },
    "remediation_base_sha256": "4191229b9daaafc164caf847707c05471d4ccaef28ecf9566076318a7d3d35dc",
    "remediation_fields": {
      "caveats": [
        "The default CloudFront certificate can be appropriate; presence does not validate certificate suitability."
      ],
      "steps": [
        "Use a custom certificate if a custom domain requires one."
      ],
      "summary": "Use a custom certificate if a custom domain requires one."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BASE": "Config.DistributionConfig."
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront.custom_certificate": "1560bb8bc56d052bf60627772c13cdbb3544d6532f935ffc3c0a521501274838"
      },
      "source_qualname": "custom_certificate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The distribution lacks one of this profile\u2019s two custom-certificate references."
  },
  "aws.b.cloudfront.custom_origin_encryption": {
    "description_base_sha256": "70d74ea15b54aef5b20f39e6db9443fa6d1cc64711429fbb15fb78e447ab4450",
    "description_fields": {
      "description": "Finds http-only custom origins and match-viewer origins when any viewer behavior permits HTTP."
    },
    "remediation_base_sha256": "7c536a4938cec954fcab18f19b952fa9f6d9706db010403965299b3fe04cde7b",
    "remediation_fields": {
      "caveats": [
        "This conservative distribution-wide configuration model does not test actual request routing."
      ],
      "steps": [
        "Use HTTPS-only origins or require HTTPS across the viewer behaviors that can reach them."
      ],
      "summary": "Use HTTPS-only origins or require HTTPS across the viewer behaviors that can reach them."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront.config": "4405776caef822550b0f8919b422a3c3ab717f9ae5eabd58ca46964147a117d5",
        "peaso.checks.aws_b_cloudfront.custom_origin_https": "15bd2bb24e043364532777012fc57f6562472ae4f6997b2bc4e2b2499b6152a8",
        "peaso.checks.aws_b_cloudfront.origins": "3a0032daab487dc6ba3c8d4824b0b1faa6e989e3a745b79c31fa4aa7d69b1651",
        "peaso.checks.aws_b_cloudfront.viewer_http": "343f8d9fef6be916892856166f1f6048bc94a32d06a2ddc3b687042bfa87b07e"
      },
      "source_qualname": "custom_origin_https"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A custom-origin configuration permits plaintext HTTP transport."
  },
  "aws.b.cloudfront.default_root_object": {
    "description_base_sha256": "a03847c4b99623c6a7d91977bc16c6f6d6b7ea5fa5f547be3f97dceb09996238",
    "description_fields": {
      "description": "Checks that the distribution declares a nonempty default root object."
    },
    "remediation_base_sha256": "040261d2fab7081a89e44f40fb9ff3b64f7db859a78f08e1b245837006f53c05",
    "remediation_fields": {
      "caveats": [
        "A default root object is an application-routing preference, not a general security requirement."
      ],
      "steps": [
        "Configure a default root object if bare-path requests should resolve to one."
      ],
      "summary": "Configure a default root object if bare-path requests should resolve to one."
    },
    "reviewed_binding": {
      "closure": {
        "field": "DefaultRootObject"
      },
      "constants": {
        "BASE": "Config.DistributionConfig.",
        "DOC": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront._nonempty.<locals>.evaluate": "a361e6fe49998c4db3fce99c19544495a63bcd87e841a2ac62ccd99afbffb517"
      },
      "source_qualname": "_nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The distribution declares no default root object."
  },
  "aws.b.cloudfront.field_level_encryption": {
    "description_base_sha256": "4c5a5684450d26301a5c36e4a44db1c6a28e3c0e271d8f47d8ac787311119c7b",
    "description_fields": {
      "description": "Checks that the default cache behavior declares a nonempty field-level encryption identifier."
    },
    "remediation_base_sha256": "6aeb1b556e5f71ea9df7a604d09c1cffb92fe7dea81f5ad6a1d678c7a877fc1b",
    "remediation_fields": {
      "caveats": [
        "This optional feature is separate from HTTPS transport encryption."
      ],
      "steps": [
        "Configure field-level encryption only for fields and applications that require it."
      ],
      "summary": "Configure field-level encryption only for fields and applications that require it."
    },
    "reviewed_binding": {
      "closure": {
        "field": "DefaultCacheBehavior.FieldLevelEncryptionId"
      },
      "constants": {
        "BASE": "Config.DistributionConfig.",
        "DOC": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront._nonempty.<locals>.evaluate": "a361e6fe49998c4db3fce99c19544495a63bcd87e841a2ac62ccd99afbffb517"
      },
      "source_qualname": "_nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default cache behavior declares no field-level encryption identifier."
  },
  "aws.b.cloudfront.geo_restrictions": {
    "description_base_sha256": "d70845e29e021db8b277e311d9c743ca8b42c356152934f8a37729ac5b9ef0cf",
    "description_fields": {
      "description": "Checks whether the distribution declares a geographic allowlist or blocklist."
    },
    "remediation_base_sha256": "d0b3ff7cb6b049e5746ed2e38080a27283e6a1c8e39119b5b68efe76a8ccd868",
    "remediation_fields": {
      "caveats": [
        "Geographic filtering is an optional policy choice and does not replace authentication."
      ],
      "steps": [
        "Add geographic restrictions only if they are needed for the distribution\u2019s audience."
      ],
      "summary": "Add geographic restrictions only if they are needed for the distribution\u2019s audience."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BASE": "Config.DistributionConfig."
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront.geo": "6658bfb7712f078c750a573f829eb729c4a5fd5d26f42bf053f90e091a63d720"
      },
      "source_qualname": "geo"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CloudFront distribution declares no geographic restriction."
  },
  "aws.b.cloudfront.no_sslv3_origin": {
    "description_base_sha256": "90b4db07076beb1dd021ca5175870d080809bbaeec93df5ea6bb9a02b7f321e7",
    "description_fields": {
      "description": "Checks custom-origin TLS protocol declarations for SSLv3."
    },
    "remediation_base_sha256": "b49c348e515e71c6aa5af562e4d8035b1fa214ab8a390f54322671e8f3483c61",
    "remediation_fields": {
      "caveats": [
        "Only configured custom-origin protocols are assessed; no connection is attempted."
      ],
      "steps": [
        "Remove obsolete TLS protocols after confirming origin compatibility."
      ],
      "summary": "Remove obsolete TLS protocols after confirming origin compatibility."
    },
    "reviewed_binding": {
      "closure": {
        "forbidden": [
          "SSLv3"
        ]
      },
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront._protocol_check.<locals>.evaluate": "2b1cc40fde8c195eabed28fa2813e678988dfdcf906e1f44d01e3f01d5f80a2e",
        "peaso.checks.aws_b_cloudfront.config": "4405776caef822550b0f8919b422a3c3ab717f9ae5eabd58ca46964147a117d5",
        "peaso.checks.aws_b_cloudfront.origins": "3a0032daab487dc6ba3c8d4824b0b1faa6e989e3a745b79c31fa4aa7d69b1651"
      },
      "source_qualname": "_protocol_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A CloudFront custom origin permits SSLv3."
  },
  "aws.b.cloudfront.origin_group_metadata": {
    "description_base_sha256": "595ff5404318c10a4067fa0c93d684674e5e9a4e598de80d5bd9aec89283f55c",
    "description_fields": {
      "description": "Checks whether OriginGroups includes an Items property."
    },
    "remediation_base_sha256": "e07450a2b35e2b8df764749a4a530d6def4f5fe95d84946989aec3c3991291cf",
    "remediation_fields": {
      "caveats": [
        "This literal metadata-presence check does not establish group membership or working failover."
      ],
      "steps": [
        "Configure an origin group if this application requires origin failover."
      ],
      "summary": "Configure an origin group if this application requires origin failover."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BASE": "Config.DistributionConfig."
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront.group_metadata": "c4f0381277272b270506122fca6d0f8ed420f81bf8244768a0dd9789f0e290c9"
      },
      "source_qualname": "group_metadata"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CloudFront origin-group Items property is absent."
  },
  "aws.b.cloudfront.origin_secure_protocols": {
    "description_base_sha256": "a8567cea14e8475e1d9d7a5333df541293aa419218406d7469cb24a17f6fff21",
    "description_fields": {
      "description": "Checks custom-origin TLS protocol declarations for SSLv3 or TLSv1."
    },
    "remediation_base_sha256": "020126544b368056a11829844b411f4da21d721f0a375d38b6daa906d4c3ce4c",
    "remediation_fields": {
      "caveats": [
        "Only configured custom-origin protocols are assessed; no connection is attempted."
      ],
      "steps": [
        "Remove obsolete TLS protocols after confirming origin compatibility."
      ],
      "summary": "Remove obsolete TLS protocols after confirming origin compatibility."
    },
    "reviewed_binding": {
      "closure": {
        "forbidden": [
          "SSLv3",
          "TLSv1"
        ]
      },
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront._protocol_check.<locals>.evaluate": "2b1cc40fde8c195eabed28fa2813e678988dfdcf906e1f44d01e3f01d5f80a2e",
        "peaso.checks.aws_b_cloudfront.config": "4405776caef822550b0f8919b422a3c3ab717f9ae5eabd58ca46964147a117d5",
        "peaso.checks.aws_b_cloudfront.origins": "3a0032daab487dc6ba3c8d4824b0b1faa6e989e3a745b79c31fa4aa7d69b1651"
      },
      "source_qualname": "_protocol_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A CloudFront custom origin permits SSLv3 or TLSv1."
  },
  "aws.b.cloudfront.viewer_encryption": {
    "description_base_sha256": "b24998111600625b0ef839361628f5a492f751f02f5a219659679c0ed85ad599",
    "description_fields": {
      "description": "Checks the default and every additional cache behavior for allow-all viewer protocol policies."
    },
    "remediation_base_sha256": "6e8a01832dff5bf5b77da0a42ff95cd8ad8601d28a8a014a05c45da5cf966e3d",
    "remediation_fields": {
      "caveats": [
        "Behavior settings do not test live endpoints or origin transport."
      ],
      "steps": [
        "Require HTTPS or redirect HTTP to HTTPS on behaviors that need transport protection."
      ],
      "summary": "Require HTTPS or redirect HTTP to HTTPS on behaviors that need transport protection."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "DOC": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront.config": "4405776caef822550b0f8919b422a3c3ab717f9ae5eabd58ca46964147a117d5",
        "peaso.checks.aws_b_cloudfront.viewer_http": "343f8d9fef6be916892856166f1f6048bc94a32d06a2ddc3b687042bfa87b07e",
        "peaso.checks.aws_b_cloudfront.viewers": "2b5cfbc3f6e34bcfbd3ae566ebc7e7ed5d3b3ab36bef56e6cd810effbcfcfc13"
      },
      "source_qualname": "viewers"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A CloudFront cache behavior permits HTTP viewer traffic."
  },
  "aws.b.cloudfront.waf_reference": {
    "description_base_sha256": "ffe4e968088220c2b8509fbaade06b997cf52dea85d1d634e10f083645d67dc1",
    "description_fields": {
      "description": "Checks that the distribution has a nonempty WAF ACL reference."
    },
    "remediation_base_sha256": "f7996d460e3c365b121353c779aa0eaf5cdd08c92f1f746b8b3d2ad5e83e9226",
    "remediation_fields": {
      "caveats": [
        "An ACL reference does not prove enabled rules or blocked requests."
      ],
      "steps": [
        "Associate a suitable WAF ACL if application filtering is required."
      ],
      "summary": "Associate a suitable WAF ACL if application filtering is required."
    },
    "reviewed_binding": {
      "closure": {
        "field": "WebACLId"
      },
      "constants": {
        "BASE": "Config.DistributionConfig.",
        "DOC": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.aws_b_cloudfront",
      "predicate_sources": {
        "peaso.checks.aws_b_cloudfront._nonempty.<locals>.evaluate": "a361e6fe49998c4db3fce99c19544495a63bcd87e841a2ac62ccd99afbffb517"
      },
      "source_qualname": "_nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The distribution declares no WAF ACL reference."
  },
  "aws.b.codebuild.artifact_encryption": {
    "description_base_sha256": "285cc901fb19f25f11cdcfcca05937eaa08e7146a2f77afc0030ec42379d1317",
    "description_fields": {
      "description": "Checks explicit encryptionDisabled=false on the primary artifact and rejects true on secondary artifacts."
    },
    "remediation_base_sha256": "1c7a388b468115685df08738bdb7c4c26b78b892bbad4be4cc792ab38ad87559",
    "remediation_fields": {
      "caveats": [
        "This literal source profile also covers non-S3 types and treats an omitted primary flag differently from the S3-only variant."
      ],
      "steps": [
        "Keep encryption enabled on required artifacts; use the S3-specific check when evaluating native omission defaults."
      ],
      "summary": "Keep encryption enabled on required artifacts; use the S3-specific check when evaluating native omission defaults."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "codebuild_project",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute._artifact_setting": "4f502df9ffa65067f4af9adbefee63f98a6cfb23dd12bbd34677f3d97803b3d5",
        "peaso.checks.aws_b_compute._observed_project": "66f86f162a2c26bf94fb761cbdc9ca00dc897d312f726bbb8c4a31fa647273b8",
        "peaso.checks.aws_b_compute.artifacts": "ee055dfa3fe35158cf3e2e9dc7ae5b5ca9171a8bf01f4616c0ba5ae6196c4a78",
        "peaso.checks.aws_b_compute.project": "60cda4557e2350ead1c012361618e3da239db0b9e575a6799b9b47b6e7c73572"
      },
      "source_qualname": "artifacts"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The primary artifact does not explicitly retain encryption, or a secondary artifact disables it."
  },
  "aws.b.codebuild.logs_enabled": {
    "description_base_sha256": "bd772e90dc19c0063629e10e0ac749ccdbc07341a6bad7318cb7ee43c3c4f11a",
    "description_fields": {
      "description": "Checks that at least one CodeBuild CloudWatch or S3 log destination is enabled."
    },
    "remediation_base_sha256": "072f3284bc7d6ca324a7d115886574997c664db8be3442db0f72adb4d8284994",
    "remediation_fields": {
      "caveats": [
        "A destination setting does not prove successful delivery or retention."
      ],
      "steps": [
        "Enable a suitable build log destination where build auditing is required."
      ],
      "summary": "Enable a suitable build log destination where build auditing is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "codebuild_project",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute.build_logs": "199807fa535ef24b1907713652b36b94858ec9700987cc7a7b1678ba882e6f9d",
        "peaso.checks.aws_b_compute.project": "60cda4557e2350ead1c012361618e3da239db0b9e575a6799b9b47b6e7c73572"
      },
      "source_qualname": "build_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CodeBuild project enables neither CloudWatch nor S3 build logs."
  },
  "aws.b.codebuild.nonprivileged": {
    "description_base_sha256": "672d24e3a336a50c2cd797b3e40527d41473d5371f271b9ac2b3f0faf78fe89c",
    "description_fields": {
      "description": "Reads the CodeBuild project environment privileged-mode flag."
    },
    "remediation_base_sha256": "47755bca8f26b5017bb4039e5945f21b7b381203cf172ddcdbb75223eff3fb1c",
    "remediation_fields": {
      "caveats": [
        "This setting does not inspect build commands or prove a running container compromise."
      ],
      "steps": [
        "Disable privileged mode unless the build needs it; isolate builds that retain it."
      ],
      "summary": "Disable privileged mode unless the build needs it; isolate builds that retain it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "codebuild_project",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute.build_privileged": "534b509c1715f6e22fb586679ab2b1d36ab8fc83dc62a5a4c5767158560417fe",
        "peaso.checks.aws_b_compute.project": "60cda4557e2350ead1c012361618e3da239db0b9e575a6799b9b47b6e7c73572"
      },
      "source_qualname": "build_privileged"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CodeBuild project enables privileged environment mode."
  },
  "aws.b.codebuild.s3_artifact_encryption": {
    "description_base_sha256": "ba5ecf94d991be27c8dc6c5190d7630e617833fc43fd5d079317bd83d877a073",
    "description_fields": {
      "description": "Checks primary and secondary S3 artifacts for encryptionDisabled=true, respecting successful native detail-read defaults."
    },
    "remediation_base_sha256": "bcc41cd752000d8fc27acec649f0f02915103984f127afadaca856df057f86dc",
    "remediation_fields": {
      "caveats": [
        "Projects without S3 artifacts are outside scope; CodePipeline owns encryption for its artifacts."
      ],
      "steps": [
        "Enable encryption for the affected S3 artifacts."
      ],
      "summary": "Enable encryption for the affected S3 artifacts."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "codebuild_project",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute._artifact_setting": "4f502df9ffa65067f4af9adbefee63f98a6cfb23dd12bbd34677f3d97803b3d5",
        "peaso.checks.aws_b_compute._observed_project": "66f86f162a2c26bf94fb761cbdc9ca00dc897d312f726bbb8c4a31fa647273b8",
        "peaso.checks.aws_b_compute.project": "60cda4557e2350ead1c012361618e3da239db0b9e575a6799b9b47b6e7c73572",
        "peaso.checks.aws_b_compute.s3_artifacts": "1224f0523a8b78e14363dfdf1420d4a75504081725698107758389dce47ce114"
      },
      "source_qualname": "s3_artifacts"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "At least one CodeBuild S3 artifact disables encryption."
  },
  "aws.b.codebuild.s3_log_encryption": {
    "description_base_sha256": "9528a2b88a612f329cf0fd8827618804253a7224513e23872b20d1fb68779b7f",
    "description_fields": {
      "description": "Reads the CodeBuild S3 log encryptionDisabled flag."
    },
    "remediation_base_sha256": "ca10f69f601d2d042f311c6034ee048e2f5a2d582c6111c425defff53c4f4516",
    "remediation_fields": {
      "caveats": [
        "The flag does not prove delivery or inspect stored log objects."
      ],
      "steps": [
        "Keep S3 log encryption enabled if S3 log delivery is used."
      ],
      "summary": "Keep S3 log encryption enabled if S3 log delivery is used."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "codebuild_project",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute.build_s3": "0b8a22048d65a236443ec1f911e674f17c806f4d3ec7865f721bf72b0a054fc3",
        "peaso.checks.aws_b_compute.project": "60cda4557e2350ead1c012361618e3da239db0b9e575a6799b9b47b6e7c73572"
      },
      "source_qualname": "build_s3"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CodeBuild S3 log configuration disables encryption."
  },
  "aws.b.cognito.block_all_takeover_risks": {
    "description_base_sha256": "c2800e6cedbe03a87dae2aa352646b636f6ef4545320b3f29f474f79c22a8f89",
    "description_fields": {
      "description": "Checks enforced threat protection and BLOCK responses for low, medium and high account-takeover risks."
    },
    "remediation_base_sha256": "64a76ae42434d1135675a6b015156d0ea5317ff8a969c5ccfa750c8ec1ad06b6",
    "remediation_fields": {
      "caveats": [
        "MFA responses also fail this strict BLOCK-only preference and are not absence of protection."
      ],
      "steps": [
        "Choose appropriate takeover-risk responses; require BLOCK at every level only if this strict profile is intended."
      ],
      "summary": "Choose appropriate takeover-risk responses; require BLOCK at every level only if this strict profile is intended."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cognito_user_pool",
      "module": "peaso.checks.aws_b_cognito",
      "predicate_sources": {
        "peaso.checks.aws_b_cognito.takeover": "eaec6e1a357c4975c6464cd75316afc68457f3e25ba1eb226ada73d74638ac73",
        "peaso.checks.aws_b_cognito.threat_mode": "42fd76f5507b6ee9d387a807036d2404e75a885fa70355157a2ad2e6a8d5f5e7"
      },
      "source_qualname": "takeover"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cognito does not enforce BLOCK at every account-takeover risk level."
  },
  "aws.b.cognito.block_compromised_signin": {
    "description_base_sha256": "3dc8f83a3f5eff6f29fad3cf8fec05f9456326782f4fca20d7a49bdbcd8af4f2",
    "description_fields": {
      "description": "Checks enforced threat protection plus SIGN_IN in the compromised-credential filter and response BLOCK."
    },
    "remediation_base_sha256": "2c28d1f4eb4ced680aaea79912236d4b34a294fca9590a3c5e435d88207e26f1",
    "remediation_fields": {
      "caveats": [
        "This configuration does not demonstrate successful detection of an actual compromised credential."
      ],
      "steps": [
        "Enable enforced compromised-sign-in blocking if this risk-response profile is required."
      ],
      "summary": "Enable enforced compromised-sign-in blocking if this risk-response profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cognito_user_pool",
      "module": "peaso.checks.aws_b_cognito",
      "predicate_sources": {
        "peaso.checks.aws_b_cognito.compromised": "77ff09bad8ebd1a8db53aac92129bd5c2ac54e93972757ee6a01ce595dbed035",
        "peaso.checks.aws_b_cognito.threat_mode": "42fd76f5507b6ee9d387a807036d2404e75a885fa70355157a2ad2e6a8d5f5e7"
      },
      "source_qualname": "compromised"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cognito does not enforce this profile\u2019s compromised-sign-in blocking response."
  },
  "aws.b.cognito.password_minimum_fourteen": {
    "description_base_sha256": "18c5e2064962486b5cc8a2fa790c564f8d66bf1cb6d2e1e3f2a9fe5b600b358d",
    "description_fields": {
      "description": "Checks Cognito password-policy minimum length is at least 14 characters."
    },
    "remediation_base_sha256": "e9f9b7bee68342abfb62d9d24b77c04ea155672ca63d8f2617663b648adf396c",
    "remediation_fields": {
      "caveats": [
        "The policy does not assess existing passwords, passkeys or federated authentication."
      ],
      "steps": [
        "Require at least 14 characters if the user pool uses this password profile."
      ],
      "summary": "Require at least 14 characters if the user pool uses this password profile."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cognito_user_pool",
      "module": "peaso.checks.aws_b_cognito",
      "predicate_sources": {
        "peaso.checks.aws_b_cognito.minimum": "316bfc343b9928b1af7bc96bca9e91da8d7cde3178a0b004e43d26ab25c1fde1",
        "peaso.checks.aws_b_cognito.setting": "e12641491a228e9db3ade981cf00f2a9704c7c179ad1f2dea5de8bd67c43cd66"
      },
      "source_qualname": "minimum"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cognito password policy allows fewer than 14 characters."
  },
  "aws.b.cognito.password_policy": {
    "description_base_sha256": "9a4d354204f61d910823af93381a31ddb8a618f6d2b66fc6272ba181ee1e58ee",
    "description_fields": {
      "description": "Checks minimum length 8, uppercase/lowercase/numeric/symbol requirements and temporary-password validity no longer than 7 days."
    },
    "remediation_base_sha256": "c5a6e873047927071babca23809fa8af3f6be980666bd9d9459f6a226edf8ba1",
    "remediation_fields": {
      "caveats": [
        "This legacy password profile does not assess passkeys, passwordless access or actual user passwords."
      ],
      "steps": [
        "Set the user-pool password requirements and temporary-password validity to this profile\u2019s bounds."
      ],
      "summary": "Set the user-pool password requirements and temporary-password validity to this profile\u2019s bounds."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cognito_user_pool",
      "module": "peaso.checks.aws_b_compute",
      "predicate_sources": {
        "peaso.checks.aws_b_compute.passwords": "e77d4cddd8c07d540f533cbc1a1929941b5c5826f3b5bce7ff61e1dc7c672e7a"
      },
      "source_qualname": "passwords"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cognito password policy does not meet the configured length, character or temporary-password bounds."
  },
  "aws.b.cognito.temporary_password_seven_days": {
    "description_base_sha256": "6323ac7df5fdfce60114d48305391880c3746d63ae86cd54f34b3dc2258e667e",
    "description_fields": {
      "description": "Checks declared temporary-password validity is no longer than seven days; zero or omission uses the service\u2019s seven-day default."
    },
    "remediation_base_sha256": "7516cb0a635fc4a03e6315c4a9870dfc83b4e2290e6741d340e71ca9eb8ccd4e",
    "remediation_fields": {
      "caveats": [
        "The setting does not prove how long any issued temporary password remains usable."
      ],
      "steps": [
        "Reduce temporary-password validity to the required window if it exceeds seven days."
      ],
      "summary": "Reduce temporary-password validity to the required window if it exceeds seven days."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cognito_user_pool",
      "module": "peaso.checks.aws_b_cognito",
      "predicate_sources": {
        "peaso.checks.aws_b_cognito.setting": "e12641491a228e9db3ade981cf00f2a9704c7c179ad1f2dea5de8bd67c43cd66",
        "peaso.checks.aws_b_cognito.temporary": "83ff7e2e5204334374c2e229f6302a2ce5600a8f5875f4afb208f3ef06c4b6fd"
      },
      "source_qualname": "temporary"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cognito temporary-password validity exceeds seven days."
  },
  "aws.b.elbv2.listener_presence": {
    "description_base_sha256": "024b22b44c2062207cfc939ee7219bbf837d3c99b5100f79ca43087d11f05bac",
    "description_fields": {
      "description": "Checks that a completely collected application or network load balancer has at least one listener."
    },
    "remediation_base_sha256": "4fea9c4c60894b9d909194028b6bad94ecc223df2ee0467b025d5ff9ba72fb11",
    "remediation_fields": {
      "caveats": [
        "Gateway load balancers are outside scope; listener presence does not prove healthy backends."
      ],
      "steps": [
        "Configure a listener if this load balancer should serve traffic; otherwise remove unused infrastructure."
      ],
      "summary": "Configure a listener if this load balancer should serve traffic; otherwise remove unused infrastructure."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.listeners": "c2b95e51cdfcd740c733bc1563dc46d3f0a4719f7539d73e047e9bff2b4b636d"
      },
      "source_qualname": "listeners"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application or network load balancer has no listeners."
  },
  "aws.b.elbv2.multiple_az": {
    "description_base_sha256": "696d73ae60c837a5d7d26983c95f60df04857ec2cc516280191b62ec46fe1d07",
    "description_fields": {
      "description": "Counts declared availability-zone entries on the application, network or gateway load balancer; requires at least two."
    },
    "remediation_base_sha256": "124b4e3fd8a9e093ed7aa088f1f38bbe7f527325c91333404520834feb517724",
    "remediation_fields": {
      "caveats": [
        "This source counts entries, not distinct zones, and does not test failover."
      ],
      "steps": [
        "Use at least two suitable availability zones if this service requires redundancy."
      ],
      "summary": "Use at least two suitable availability zones if this service requires redundancy."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_b_loadbalancing",
      "predicate_sources": {
        "peaso.checks.aws_b_loadbalancing.v2_zones": "2caacb56ce588d86aff39d5ffd993878075a4bff43cf79544c2773b5e9634e76"
      },
      "source_qualname": "v2_zones"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application, network or gateway load balancer declares fewer than two availability-zone entries."
  },
  "aws.b.neptune.audit_logging": {
    "description_base_sha256": "e2d3dfc9d67b7acd94eaa8998f097aebfb48f34c73e0aeceabc54a4827de5afb",
    "description_fields": {
      "description": "Checks that the Neptune cluster declares an audit CloudWatch log export."
    },
    "remediation_base_sha256": "88ec9715959e516a86ccd7e8615f7dd265ae1d08abf7e2807a465f5f46d50c3b",
    "remediation_fields": {
      "caveats": [
        "The declaration does not prove audit events are generated or delivered."
      ],
      "steps": [
        "Enable audit log export if database audit records are required."
      ],
      "summary": "Enable audit log export if database audit records are required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "neptune_cluster",
      "module": "peaso.checks.aws_b_databases",
      "predicate_sources": {
        "peaso.checks.aws_b_databases.neptune_logging": "29ed0ed912e94a30922e3ed6dc06a261a9bb41b5aae40f456fddac2e6f1aadd0"
      },
      "source_qualname": "neptune_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Neptune cluster declares no audit log export."
  },
  "aws.b.rds_cluster.nondefault_port_policy": {
    "description_base_sha256": "ad53af2760b12c5f83e731423141fa044e7321c95b2e9342f81c59f7a67b9146",
    "description_fields": {
      "description": "Compares the database engine and configured endpoint port with this profile\u2019s engine-default ports."
    },
    "remediation_base_sha256": "9097fc70b31b4a15bb2bbb119066fe8be3e46e7fb96fed9e26d8f4dc175ef1f9",
    "remediation_fields": {
      "caveats": [
        "Changing the port is obscurity and does not improve authentication or isolate the database."
      ],
      "steps": [
        "Consider a nondefault port only if this operational profile is required; preserve client connectivity."
      ],
      "summary": "Consider a nondefault port only if this operational profile is required; preserve client connectivity."
    },
    "reviewed_binding": {
      "closure": {
        "path": "Port"
      },
      "constants": {},
      "kind": "rds_cluster",
      "module": "peaso.checks.aws_b_storage",
      "predicate_sources": {
        "peaso.checks.aws_b_storage._ports.<locals>.evaluate": "36a42fc82788147751fbdd1f251e6d7994f8a610b6a3f5e541b003b9e622e957"
      },
      "source_qualname": "_ports.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The database endpoint uses its engine\u2019s default port under this profile."
  },
  "aws.b.rds_instance.multiple_az": {
    "description_base_sha256": "30eea990d93848f4d575838c26d162fb4baf6ce197ba5bf25930d5e691e02255",
    "description_fields": {
      "description": "Checks the RDS instance MultiAZ flag, excluding this source\u2019s Aurora MySQL/PostgreSQL instance families."
    },
    "remediation_base_sha256": "d11a68fadab540115d9a7617473da5b67e1f5e2e0f67320c9770302f340a3dc2",
    "remediation_fields": {
      "caveats": [
        "The setting does not prove failover readiness or recovery time."
      ],
      "steps": [
        "Enable a suitable Multi-AZ deployment if the database needs that availability level."
      ],
      "summary": "Enable a suitable Multi-AZ deployment if the database needs that availability level."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_b_databases",
      "predicate_sources": {
        "peaso.checks.aws_b_databases.rds_instance_multiaz": "aba397842e72b81e567c52a5e7c49d9ce07e677fd0bb4bbeaeef9e5ca8a46fcc"
      },
      "source_qualname": "rds_instance_multiaz"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The applicable RDS instance has Multi-AZ disabled."
  },
  "aws.b.rds_instance.nondefault_port_policy": {
    "description_base_sha256": "dcc9a2d87776265b537cc74e5946fae1139d37f542a1b02b173918c217c413e4",
    "description_fields": {
      "description": "Compares the database engine and configured endpoint port with this profile\u2019s engine-default ports."
    },
    "remediation_base_sha256": "8eb0be48c9967da102064b880bb30bb31a1c2ac847cb27b80ff2614495365bfb",
    "remediation_fields": {
      "caveats": [
        "Changing the port is obscurity and does not improve authentication or isolate the database."
      ],
      "steps": [
        "Consider a nondefault port only if this operational profile is required; preserve client connectivity."
      ],
      "summary": "Consider a nondefault port only if this operational profile is required; preserve client connectivity."
    },
    "reviewed_binding": {
      "closure": {
        "path": "Endpoint.Port"
      },
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_b_storage",
      "predicate_sources": {
        "peaso.checks.aws_b_storage._ports.<locals>.evaluate": "36a42fc82788147751fbdd1f251e6d7994f8a610b6a3f5e541b003b9e622e957"
      },
      "source_qualname": "_ports.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The database endpoint uses its engine\u2019s default port under this profile."
  },
  "aws.b.redshift.kms_key_declared": {
    "description_base_sha256": "32bacfbbfd3873688916c5296bc1949b31d383e5c4bdf43199d8ea358c3a37f0",
    "description_fields": {
      "description": "Checks Redshift Encrypted=true and a nonempty KMS key reference; native inventory must prove an omitted reference."
    },
    "remediation_base_sha256": "c893f72a6b4e1aae404d7141464c414b13c101f123a297e17adad19dacf28d3f",
    "remediation_fields": {
      "caveats": [
        "A key reference does not establish customer ownership or usability."
      ],
      "steps": [
        "Enable storage encryption and select a suitable key if required; plan migration for existing data."
      ],
      "summary": "Enable storage encryption and select a suitable key if required; plan migration for existing data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "redshift_cluster",
      "module": "peaso.checks.aws_b_redshift",
      "predicate_sources": {
        "peaso.checks.aws_b_redshift.kms": "21e2231d59537e2c10913c90c9dd41fb6ddefc0040539f054104c37cc20ba652"
      },
      "source_qualname": "kms"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster has encryption disabled or a proven missing KMS key reference."
  },
  "aws.b.redshift.nondefault_admin": {
    "description_base_sha256": "9a2f1f9d05879e5aa4de24a1b767ce57782d2bd6d736481abc46067c1ff56bb1",
    "description_fields": {
      "description": "Checks the Redshift administrator name differs case-sensitively from awsuser."
    },
    "remediation_base_sha256": "aa60706a865338e7068839bf09522a2a390ffa9f5de6f9dfb87e3eb6aa47dfb4",
    "remediation_fields": {
      "caveats": [
        "Renaming does not strengthen authentication or establish restricted access."
      ],
      "steps": [
        "Use a different administrator name only if this naming profile is required."
      ],
      "summary": "Use a different administrator name only if this naming profile is required."
    },
    "reviewed_binding": {
      "closure": {
        "blocked": "awsuser",
        "field": "MasterUsername"
      },
      "constants": {},
      "kind": "redshift_cluster",
      "module": "peaso.checks.aws_b_redshift",
      "predicate_sources": {
        "peaso.checks.aws_b_redshift._name.<locals>.evaluate": "c793997f2d861973e1c416334864ca17a0df2b52a3e11eb6e3b23e20f7ae86bc"
      },
      "source_qualname": "_name.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Redshift administrator name equals the profile default awsuser."
  },
  "aws.b.redshift.nondefault_database": {
    "description_base_sha256": "08f8ad2c4949f1082c17966c19d683ead21d6b64be3f761c49c160721d9c459d",
    "description_fields": {
      "description": "Checks the Redshift database name differs case-sensitively from dev."
    },
    "remediation_base_sha256": "346f424f0235b2a981a5945ca0a04e0036339be5a256024a23a43392b3974b94",
    "remediation_fields": {
      "caveats": [
        "Renaming does not strengthen authentication or establish restricted access."
      ],
      "steps": [
        "Use a different database name only if this naming profile is required."
      ],
      "summary": "Use a different database name only if this naming profile is required."
    },
    "reviewed_binding": {
      "closure": {
        "blocked": "dev",
        "field": "DBName"
      },
      "constants": {},
      "kind": "redshift_cluster",
      "module": "peaso.checks.aws_b_redshift",
      "predicate_sources": {
        "peaso.checks.aws_b_redshift._name.<locals>.evaluate": "c793997f2d861973e1c416334864ca17a0df2b52a3e11eb6e3b23e20f7ae86bc"
      },
      "source_qualname": "_name.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Redshift database name equals the profile default dev."
  },
  "aws.c2b.apigateway.domain_pqc_tls": {
    "description_base_sha256": "9cc973b88c59229dc5c63a037065e7b9280f6cd50f2a7f3c8f37cd225667173c",
    "description_fields": {
      "description": "Compares the custom domain TLS security policy with the pinned post-quantum policy allowlist."
    },
    "remediation_base_sha256": "a0d5aeac64221d7adf4539aaede429e37aad400bf856c6268a96778594c6f5cf",
    "remediation_fields": {
      "caveats": [
        "A conventional TLS policy is not automatically unsafe because it lacks this optional profile."
      ],
      "steps": [
        "Select a supported post-quantum TLS policy if required and compatible with clients."
      ],
      "summary": "Select a supported post-quantum TLS policy if required and compatible with clients."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "APIGW_PQC": [
          "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09",
          "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
          "SecurityPolicy_TLS13_1_2_PQ_2025_09"
        ]
      },
      "kind": "apigateway_domain_name",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.apigw_domain_pqc": "c8d5b804df8d6858029dd7545c809e4eb39d7385334df1b525e316aca6337473"
      },
      "source_qualname": "apigw_domain_pqc"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The API Gateway custom domain does not use the pinned post-quantum TLS profile."
  },
  "aws.c2b.apigatewayv2.api_has_authorizer": {
    "description_base_sha256": "9b7ce722bf77371f8124e8e889bac43b913f1d71bf9cb7388a546c74f98d1d35",
    "description_fields": {
      "description": "Counts APIv2 authorizer definitions in the completely collected API inventory."
    },
    "remediation_base_sha256": "c0e72003d1a071884dc673d0a4368d889329719d1b84f9947ff30000209587d1",
    "remediation_fields": {
      "caveats": [
        "IAM-authorized APIs may not need an authorizer definition; presence does not prove route attachment."
      ],
      "steps": [
        "Configure a suitable authorizer if the API requires JWT or Lambda authorization."
      ],
      "summary": "Configure a suitable authorizer if the API requires JWT or Lambda authorization."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "http_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_common.detail_list": "486886f256c94e3dbbb5f0178babba295830d031bf8634d75afc4624dfd86813",
        "peaso.checks.claude2_aws_b_edge.apigw2_has_auth": "8e4f4fc173907b9ff3efe3d957f4aca1e13a5d7b8f99bfd886650eff37d07c4d"
      },
      "source_qualname": "apigw2_has_auth"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The APIv2 API defines no authorizers."
  },
  "aws.c2b.apigatewayv2.routes_authorization_type": {
    "description_base_sha256": "5110c02b4dff307be189f8299b7ddeeb02c625b13bbf6147af45db68e4df7aed",
    "description_fields": {
      "description": "Finds APIv2 routes whose authorization type is NONE or omitted."
    },
    "remediation_base_sha256": "c89255a2878b83b1ebcf0be42e424f03071e8cebceff36167720aa62b6c27b9d",
    "remediation_fields": {
      "caveats": [
        "Route configuration does not test requests or prove application-level access controls are absent."
      ],
      "steps": [
        "Require suitable authorization on routes that are not intentionally public."
      ],
      "summary": "Require suitable authorization on routes that are not intentionally public."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "http_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._routes": "85c4d1b9a2b6335004f928668b1a8c626cc18da50e5303b3c05344df160c9cb7",
        "peaso.checks.claude2_aws_b_edge.apigw2_route_type": "385c8b606b420355834097a7c4e7555514e26f84fd9bec19b009e87c808e3bab"
      },
      "source_qualname": "apigw2_route_type"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An APIv2 route declares no route-level authorization."
  },
  "aws.c2b.apigatewayv2.routes_authorizer": {
    "description_base_sha256": "e8a5afd2a7b26d0b6de11ef325472c4c8287f90d158b1e5255a56025f898c2f7",
    "description_fields": {
      "description": "Finds APIv2 routes without a nonempty AuthorizerId."
    },
    "remediation_base_sha256": "520bf5fd0410281a57f2baf5413dae6febb535da63153159ed1ebfd3c9346a0c",
    "remediation_fields": {
      "caveats": [
        "AWS_IAM routes also fail this literal authorizer-reference profile despite having authorization."
      ],
      "steps": [
        "Attach a JWT or Lambda authorizer where required; retain legitimate IAM-authorized routes."
      ],
      "summary": "Attach a JWT or Lambda authorizer where required; retain legitimate IAM-authorized routes."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "http_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._routes": "85c4d1b9a2b6335004f928668b1a8c626cc18da50e5303b3c05344df160c9cb7",
        "peaso.checks.claude2_aws_b_edge.apigw2_route_authorizer": "6a4be040fb212134c1b4029fbe35140e7f1cda169a486016fb4e7cd4fa7870b7"
      },
      "source_qualname": "apigw2_route_authorizer"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An APIv2 route has no authorizer reference."
  },
  "aws.c2b.appstream.disconnect_timeout_5m": {
    "description_base_sha256": "a66304a1190bec94039bce2471e702399fd16026bc12f5a5bc9c1823dc4023bc",
    "description_fields": {
      "description": "Checks AppStream disconnect timeout is at most 300 seconds."
    },
    "remediation_base_sha256": "d54b2fc51a7cf2bbeb213ff9e2a973ff034ae0146f34425c876e1ed38926dcef",
    "remediation_fields": {
      "caveats": [
        "These are configured timeout bounds, not observed session termination."
      ],
      "steps": [
        "Set a disconnect timeout suitable for the required session-risk profile."
      ],
      "summary": "Set a disconnect timeout suitable for the required session-risk profile."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appstream_fleet",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute.fleet_disconnect": "f8b91ee28447eee322de35107fa9e7c9812e378f09735fd59fcff022ef76c738"
      },
      "source_qualname": "fleet_disconnect"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "AppStream disconnect timeout exceeds five minutes."
  },
  "aws.c2b.appstream.idle_disconnect_10m": {
    "description_base_sha256": "6a0b722a2b5815ec63de782f4664890c2af653823b9af591ce4baf86d8940769",
    "description_fields": {
      "description": "Checks AppStream idle timeout is positive and at most 600 seconds; omission defaults to disabled."
    },
    "remediation_base_sha256": "c4c5f8e5327fe9106a269574768aff3f0fbfe7605edb90cc48ebe24145c5c73e",
    "remediation_fields": {
      "caveats": [
        "These are configured timeout bounds, not observed session termination."
      ],
      "steps": [
        "Enable idle disconnection within ten minutes if this session profile is required."
      ],
      "summary": "Enable idle disconnection within ten minutes if this session profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appstream_fleet",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute.fleet_idle": "04899d2304cec3bcf17bff90104af63845abe912af9b197de4933f65eb7676d7",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "fleet_idle"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "AppStream idle disconnection is disabled or exceeds ten minutes."
  },
  "aws.c2b.appstream.max_user_duration_under_10h": {
    "description_base_sha256": "5a324a59a96cf699197dfe051b18ff69b0dc90220dc91e4e9f6f4b722ca06813",
    "description_fields": {
      "description": "Checks AppStream maximum user duration is strictly less than 36,000 seconds."
    },
    "remediation_base_sha256": "8d7778431cb8de987e55fda0af8ecc9baa496e6e7f47e6318ae44e16ac5c6d6f",
    "remediation_fields": {
      "caveats": [
        "These are configured timeout bounds, not observed session termination."
      ],
      "steps": [
        "Shorten session duration if the strict under-ten-hour profile is required."
      ],
      "summary": "Shorten session duration if the strict under-ten-hour profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appstream_fleet",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute.fleet_duration": "7c76997890760031debb43a2493870b6ed8a972a66a1504a18d5c9bec54e0c1b"
      },
      "source_qualname": "fleet_duration"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "AppStream maximum user duration is at least ten hours."
  },
  "aws.c2b.appsync.field_level_logging": {
    "description_base_sha256": "3c03046b85c60cf3cb94f6bc549dc6b24f3684477881c0e1e7a24a1dd4fab153",
    "description_fields": {
      "description": "Checks the AppSync field logging level for ERROR or ALL."
    },
    "remediation_base_sha256": "f5a596c49f691e63579587399931240012e186df0faffcbac5ba9b755851331a",
    "remediation_fields": {
      "caveats": [
        "This profile does not accept other levels and does not prove log delivery."
      ],
      "steps": [
        "Enable suitable resolver field logging if needed for investigation."
      ],
      "summary": "Enable suitable resolver field logging if needed for investigation."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appsync_graphql_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.appsync_logging": "0431355021d10a154695c0968c3e75901802350f3495434806a1f4597e0e314c",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "appsync_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "AppSync field logging is not set to ERROR or ALL."
  },
  "aws.c2b.appsync.graphql_no_api_key": {
    "description_base_sha256": "5eeed608adee890a9f48eb03304f446e63ee63e770730c3b0c3c83fa9f6ed125",
    "description_fields": {
      "description": "Checks whether the AppSync GraphQL-type API uses API_KEY as its default authentication type."
    },
    "remediation_base_sha256": "53a73923d1ca2a328d1d23ec9dec87672aa222dc1d90e482a02ab33de6840f5d",
    "remediation_fields": {
      "caveats": [
        "API-key access may be intentional for public data; additional authentication modes are not assessed."
      ],
      "steps": [
        "Use per-principal authorization when shared API-key access is unsuitable for the data."
      ],
      "summary": "Use per-principal authorization when shared API-key access is unsuitable for the data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appsync_graphql_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.appsync_api_key": "9b4379746735f559de954165af37c2a0773c6003e836f733e5d3ac72541eb396",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "appsync_api_key"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The AppSync GraphQL-type API uses default API-key authentication."
  },
  "aws.c2b.appsync.no_api_key_auth": {
    "description_base_sha256": "20d70138edc4defbab9e75df57abe371dbb41ef1683d1a7d3ad72ef25eadaebd",
    "description_fields": {
      "description": "Checks whether the AppSync API of any type uses API_KEY as its default authentication type."
    },
    "remediation_base_sha256": "5bc0b03e6de641777dd2b2dcb9b11cc9ac327988c426f3514b52f3d33cd7d71f",
    "remediation_fields": {
      "caveats": [
        "API-key access may be intentional for public data; additional authentication modes are not assessed."
      ],
      "steps": [
        "Use per-principal authorization when shared API-key access is unsuitable for the data."
      ],
      "summary": "Use per-principal authorization when shared API-key access is unsuitable for the data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "appsync_graphql_api",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.appsync_api_key_any": "b61f45d3b054137305bbd9d1ccab2d1a5c0da2319496496c82ac142763bd06db"
      },
      "source_qualname": "appsync_api_key_any"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AppSync API of any type uses default API-key authentication."
  },
  "aws.c2b.athena.cloudwatch_metrics": {
    "description_base_sha256": "b42b241d74eb423fe1ab496fd6b81e6fc2756234309dd7655ed49ab573afb06b",
    "description_fields": {
      "description": "Checks Athena PublishCloudWatchMetricsEnabled=true."
    },
    "remediation_base_sha256": "38a8b47f73efc453a99ecb2294664fd7d2158ca1a9fd038983ed476a5b5eb7ed",
    "remediation_fields": {
      "caveats": [
        "The flag does not validate configuration quality or prove metrics delivery."
      ],
      "steps": [
        "Enable CloudWatch metrics publishing if required for this workgroup."
      ],
      "summary": "Enable CloudWatch metrics publishing if required for this workgroup."
    },
    "reviewed_binding": {
      "closure": {
        "path": "PublishCloudWatchMetricsEnabled",
        "prowler": false
      },
      "constants": {},
      "kind": "athena_workgroup",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._athena_bool.<locals>.evaluate": "ee8fac034b62fcefb759eedfe4b9a380505c380cae44656bcee8fc8b98e95767",
        "peaso.checks.claude2_aws_b_data._wg_conf": "caba23dbf6f631ea4c0c0f6a5f0568f0b13b6f0845136f92c3687394743d66e1",
        "peaso.checks.claude2_aws_b_data._wg_enabled": "fbcd50d39fea2bec4ce638037e35b3f4c6a30a2e6bbc113574555415ad057cee",
        "peaso.checks.claude2_aws_b_data._workgroup": "b6f719a9bac673bef205ace5f4d08005acc6dd43b3669b9b9937e041772f690c"
      },
      "source_qualname": "_athena_bool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Athena workgroup disables CloudWatch metrics publishing."
  },
  "aws.c2b.athena.cloudwatch_metrics_prowler": {
    "description_base_sha256": "283024291c328d58249fd439d8c48df094a8ae204c7b6ad837c017714a9194bd",
    "description_fields": {
      "description": "Checks Athena PublishCloudWatchMetricsEnabled=true for enabled workgroups only."
    },
    "remediation_base_sha256": "ec3ebfb328904505a41cee5c2aad93cc5dac6364e27e8bccbde7a039d768e525",
    "remediation_fields": {
      "caveats": [
        "The flag does not validate configuration quality or prove metrics delivery."
      ],
      "steps": [
        "Enable CloudWatch metrics publishing if required for this workgroup."
      ],
      "summary": "Enable CloudWatch metrics publishing if required for this workgroup."
    },
    "reviewed_binding": {
      "closure": {
        "path": "PublishCloudWatchMetricsEnabled",
        "prowler": true
      },
      "constants": {},
      "kind": "athena_workgroup",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._athena_bool.<locals>.evaluate": "ee8fac034b62fcefb759eedfe4b9a380505c380cae44656bcee8fc8b98e95767",
        "peaso.checks.claude2_aws_b_data._wg_conf": "caba23dbf6f631ea4c0c0f6a5f0568f0b13b6f0845136f92c3687394743d66e1",
        "peaso.checks.claude2_aws_b_data._wg_enabled": "fbcd50d39fea2bec4ce638037e35b3f4c6a30a2e6bbc113574555415ad057cee",
        "peaso.checks.claude2_aws_b_data._workgroup": "b6f719a9bac673bef205ace5f4d08005acc6dd43b3669b9b9937e041772f690c"
      },
      "source_qualname": "_athena_bool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Athena workgroup disables CloudWatch metrics publishing."
  },
  "aws.c2b.athena.enforce_configuration": {
    "description_base_sha256": "326ca2fb9439ab94f1baf93a0d31b4ca048463d724bb6de6ff2434e5a5256b6f",
    "description_fields": {
      "description": "Checks Athena EnforceWorkGroupConfiguration=true."
    },
    "remediation_base_sha256": "8ea78a6f33ca2655bc3a875219406033b3b976ba6f115ed4b339117b739947e1",
    "remediation_fields": {
      "caveats": [
        "The flag does not validate configuration quality or prove metrics delivery."
      ],
      "steps": [
        "Enable workgroup configuration enforcement if required for this workgroup."
      ],
      "summary": "Enable workgroup configuration enforcement if required for this workgroup."
    },
    "reviewed_binding": {
      "closure": {
        "path": "EnforceWorkGroupConfiguration",
        "prowler": false
      },
      "constants": {},
      "kind": "athena_workgroup",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._athena_bool.<locals>.evaluate": "ee8fac034b62fcefb759eedfe4b9a380505c380cae44656bcee8fc8b98e95767",
        "peaso.checks.claude2_aws_b_data._wg_conf": "caba23dbf6f631ea4c0c0f6a5f0568f0b13b6f0845136f92c3687394743d66e1",
        "peaso.checks.claude2_aws_b_data._wg_enabled": "fbcd50d39fea2bec4ce638037e35b3f4c6a30a2e6bbc113574555415ad057cee",
        "peaso.checks.claude2_aws_b_data._workgroup": "b6f719a9bac673bef205ace5f4d08005acc6dd43b3669b9b9937e041772f690c"
      },
      "source_qualname": "_athena_bool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Athena workgroup disables workgroup configuration enforcement."
  },
  "aws.c2b.athena.enforce_configuration_prowler": {
    "description_base_sha256": "f92cd6c3a73092c7bb8b4d052b025ce2c503026a3f6eb2df6400b3d92062267e",
    "description_fields": {
      "description": "Checks Athena EnforceWorkGroupConfiguration=true for enabled workgroups only."
    },
    "remediation_base_sha256": "4400dfaaf708fb8452571e816e631c5b54f6a0bd5adb21820d31fa853f52f2f2",
    "remediation_fields": {
      "caveats": [
        "The flag does not validate configuration quality or prove metrics delivery."
      ],
      "steps": [
        "Enable workgroup configuration enforcement if required for this workgroup."
      ],
      "summary": "Enable workgroup configuration enforcement if required for this workgroup."
    },
    "reviewed_binding": {
      "closure": {
        "path": "EnforceWorkGroupConfiguration",
        "prowler": true
      },
      "constants": {},
      "kind": "athena_workgroup",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._athena_bool.<locals>.evaluate": "ee8fac034b62fcefb759eedfe4b9a380505c380cae44656bcee8fc8b98e95767",
        "peaso.checks.claude2_aws_b_data._wg_conf": "caba23dbf6f631ea4c0c0f6a5f0568f0b13b6f0845136f92c3687394743d66e1",
        "peaso.checks.claude2_aws_b_data._wg_enabled": "fbcd50d39fea2bec4ce638037e35b3f4c6a30a2e6bbc113574555415ad057cee",
        "peaso.checks.claude2_aws_b_data._workgroup": "b6f719a9bac673bef205ace5f4d08005acc6dd43b3669b9b9937e041772f690c"
      },
      "source_qualname": "_athena_bool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Athena workgroup disables workgroup configuration enforcement."
  },
  "aws.c2b.backup.plan_rules_retention_35": {
    "description_base_sha256": "cd9ceffeb9aa955de92b566e58117a834a1d8df297aa53dd8b268c58779a9a39",
    "description_fields": {
      "description": "Finds backup-plan rules whose explicit DeleteAfterDays is below 35."
    },
    "remediation_base_sha256": "e0f1d8b58ab0eb941273fc31ddccb9607076bb94beebf6b4f9d1a3f95730f1d4",
    "remediation_fields": {
      "caveats": [
        "Omitted deletion passes this profile; this does not test backup jobs or restores."
      ],
      "steps": [
        "Increase affected rule retention if the required recovery window is at least 35 days."
      ],
      "summary": "Increase affected rule retention if the required recovery window is at least 35 days."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "backup_plan",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_common.detail": "24ef79499457c6519547eeb2b5dff453ac3347e57347cde5b7f4ac8e54452ab4",
        "peaso.checks.claude2_aws_b_data.plan_rules_retention": "8acdf6a0c51e3b9b7f6ca5003ac392a82e973b83f61ee77b0e9b4b0f013ffc9d"
      },
      "source_qualname": "plan_rules_retention"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A backup-plan rule declares deletion before 35 days."
  },
  "aws.c2b.backup.plans_exist_when_vaults": {
    "description_base_sha256": "a78639d34cf27e7fadeb3ee3d31811307731dfcff4cda07d8921d55f3e746937",
    "description_fields": {
      "description": "Checks that the scoped inventory has at least one backup plan when backup vaults exist."
    },
    "remediation_base_sha256": "7fa100b15f9bc862b793d425dc1a882fb4570f44b362860c4302baa4c1e61809",
    "remediation_fields": {
      "caveats": [
        "A region-wide plan witness does not establish resource assignment or successful backups."
      ],
      "steps": [
        "Create suitable backup plans if these vaults should support scheduled protection."
      ],
      "summary": "Create suitable backup plans if these vaults should support scheduled protection."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "backup_plan",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.backup_plans_exist": "4456359a7b15d63587c141d6d59cb07db880733065c26d83a86c39ec8b29d5db",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "backup_plans_exist"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Backup vaults exist but the scope contains no backup plans."
  },
  "aws.c2b.backup.recovery_point_retention_35": {
    "description_base_sha256": "12300c8a7932f6c73383153cc5141dc01f1d74cc9ab222d87bbc103dba84046d",
    "description_fields": {
      "description": "Checks an explicit recovery-point DeleteAfterDays value for at least 35 days; omission passes as no declared deletion."
    },
    "remediation_base_sha256": "cde0646d151f9a11367742fc6d499133d3d10b59f6a3626416a845168fc50793",
    "remediation_fields": {
      "caveats": [
        "Lifecycle settings do not prove recoverability; omitted deletion is not short retention."
      ],
      "steps": [
        "Increase retention if this recovery point needs the profile\u2019s 35-day window."
      ],
      "summary": "Increase retention if this recovery point needs the profile\u2019s 35-day window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "backup_recovery_point",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.recovery_point_retention": "4b3d1621551f4562bc764def0fddd0ad3b371a4b9da08915aee8130a3bcfb1d7",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "recovery_point_retention"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The recovery point declares deletion before 35 days."
  },
  "aws.c2b.backup.report_plans_when_plans": {
    "description_base_sha256": "d2cece22367f6e37a7df98a5479b06569774b5d72b7ba2313140b2e1d00837e1",
    "description_fields": {
      "description": "Checks that at least one backup report plan exists when backup plans exist."
    },
    "remediation_base_sha256": "e86665dc454dabe70b790c7bb71e55bc4deabc390d0ff5782e50e202e24a9266",
    "remediation_fields": {
      "caveats": [
        "Report-plan presence does not prove reports are delivered or every backup plan is covered."
      ],
      "steps": [
        "Configure reports if the backup process requires them."
      ],
      "summary": "Configure reports if the backup process requires them."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "backup_report_plan",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.backup_report_plans": "f69728257f3675241e29278fa0612ef1b2391ba11d76aafcba8f30905cd73c1c",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "backup_report_plans"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Backup plans exist but the scope has no backup report plans."
  },
  "aws.c2b.backup.vault_policy_denies_recovery_point_deletion": {
    "description_base_sha256": "f2f3e58dc40ae18c7363068009fb1fa1c7174ecc163501102d955ba544749baf",
    "description_fields": {
      "description": "Looks for one Deny statement on Resource:* covering deletion, lifecycle updates and vault-policy updates."
    },
    "remediation_base_sha256": "a297af4d0d1ab706ab3087631cf525d987ebd0d0087ae27baa09e9ca440b6034",
    "remediation_fields": {
      "caveats": [
        "This syntax witness does not evaluate Principal, Condition or every effective permission and is not proof of immutable backups."
      ],
      "steps": [
        "Review appropriate safeguards against unauthorized recovery-point deletion without blocking required administration."
      ],
      "summary": "Review appropriate safeguards against unauthorized recovery-point deletion without blocking required administration."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_LOCK_ACTIONS": [
          "backup:DeleteRecoveryPoint",
          "backup:UpdateRecoveryPointLifecycle",
          "backup:PutBackupVaultAccessPolicy"
        ]
      },
      "kind": "backup_vault",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._actions": "cabbc0b3174124f48d0bd6c6cd371454908628840b0b393c12eb8c9185f95ef6",
        "peaso.checks.claude2_aws_b_data._vault_policy": "b42bbdad89024c0957f3628f2459568fb6f2d5610a59cd39271a206ab1be0462",
        "peaso.checks.claude2_aws_b_data.vault_policy_denies_deletion": "aea4fcfdccc0cbad82b57cf50c7d7e45d533896e69cb3f9d911a1e6e60b50653"
      },
      "source_qualname": "vault_policy_denies_deletion"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The vault lacks the exact broad-resource Deny statement required by this profile."
  },
  "aws.c2b.backup.vault_policy_not_public": {
    "description_base_sha256": "51a83cb1c0fe300c820cb900d7dd51b418ebe05d11aea7b8707edc5ee030f882",
    "description_fields": {
      "description": "Checks the backup-vault policy with the source\u2019s wildcard-principal and restricting-condition model."
    },
    "remediation_base_sha256": "40fb1e2414ad22592a6e5b2c85ee01a747f4b8ee22f2fbfca86e3296d6436420",
    "remediation_fields": {
      "caveats": [
        "Policy-model results do not compute effective access across every external control."
      ],
      "steps": [
        "Restrict unnecessary public grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary public grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "kind": "backup_vault",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "vault_policy_not_public",
      "closure": {},
      "constants": {},
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_common.resource_policy_public": "e675cc9534fc3ddedf4600f65f65d7a21b63d1a02fc3f818132d34cfb969cae5",
        "peaso.checks.claude2_aws_b_data._vault_policy": "b42bbdad89024c0957f3628f2459568fb6f2d5610a59cd39271a206ab1be0462",
        "peaso.checks.claude2_aws_b_data.vault_policy_not_public": "61e1e4b05c8f788c3139a35fa0eeb0f4d9caa95064c6973b72abb830633c830a"
      }
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The backup-vault policy matches the public-grant model."
  },
  "aws.c2b.classic_elb.has_registered_instances": {
    "description_base_sha256": "c67155e667aee6158814a266077903499939b1f97a21b5489d5891110ef6b0d4",
    "description_fields": {
      "description": "Counts registered instances on the Classic load balancer."
    },
    "remediation_base_sha256": "6b175c7028738d5296a65a0e4182ab1bde2141a3ab2051c27e87520644e2fff7",
    "remediation_fields": {
      "caveats": [
        "Registered instances are not necessarily healthy."
      ],
      "steps": [
        "Register intended backends or remove the unused load balancer after checking dependencies."
      ],
      "summary": "Register intended backends or remove the unused load balancer after checking dependencies."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.clb_instances": "356505b7422ccd49192eb8d5481bad95640943bfced532b81db6dfb3cf241c47"
      },
      "source_qualname": "clb_instances"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Classic load balancer has no registered instances."
  },
  "aws.c2b.classic_elb.insecure_ssl_ciphers": {
    "description_base_sha256": "15a1327118510b3ca30ba817f762f42b1fbce76a7a01bdd3efe0b2596ab2fc0c",
    "description_fields": {
      "description": "Checks HTTPS listener policy names for the exact ELBSecurityPolicy-TLS-1-2-2017-01 profile."
    },
    "remediation_base_sha256": "3ecc6d6834d71ec8978633c8e4f065143f7848ab5d5081037a12192299adea86",
    "remediation_fields": {
      "caveats": [
        "This name comparison does not enumerate actual cipher strength or reject every newer secure policy fairly."
      ],
      "steps": [
        "Use a suitable TLS policy for clients; adopt this exact policy only if the profile is required."
      ],
      "summary": "Use a suitable TLS policy for clients; adopt this exact policy only if the profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._clb_listeners": "4e0d70c22cc18ad38e4d8a954d89587616ad1f6a29c6976c5b5d10fb6cf8af86",
        "peaso.checks.claude2_aws_b_edge.clb_ciphers": "50d1e636be73edc8eaa32810af10e9bb39e3bcb9e8f68c3aa1a6131449805956",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      },
      "source_qualname": "clb_ciphers"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An HTTPS listener does not reference the pinned TLS-1-2-2017-01 policy."
  },
  "aws.c2b.classic_elb.not_internet_facing": {
    "description_base_sha256": "5b36b3bdf080b42a43526aa9dee76e09b46c3f2d34a25071479983094dc5a02a",
    "description_fields": {
      "description": "Reads whether the Classic load balancer scheme is internet-facing."
    },
    "remediation_base_sha256": "324502fea21b959c1dfc3705a39bbace62cef0c23a4ea05627a443c9ada94bae",
    "remediation_fields": {
      "caveats": [
        "Internet-facing load balancers can be intentional; this does not prove an exposed listener.",
        "Scheme cannot be changed in place: migrate clients to a replacement internal load balancer if needed. The old internet-facing resource continues to fail this declaration check until retired."
      ],
      "steps": [
        "Use an internal load balancer if the service does not need Internet clients."
      ],
      "summary": "Use an internal load balancer if the service does not need Internet clients."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.clb_public": "ed5760c8b42594948aa2fc47601690f5dc34ed02e9888dbb5de7f95b6c8d2f19"
      },
      "source_qualname": "clb_public"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Classic load balancer declares an internet-facing scheme."
  },
  "aws.c2b.classic_elb.sg_inbound_rule": {
    "description_base_sha256": "23eb1dcdfbd2fe6172d2f1352048370b88f3ec34f4c71988e5bc33b73bf85872",
    "description_fields": {
      "description": "Checks that security groups are attached and every resolved group has at least one inbound rule."
    },
    "remediation_base_sha256": "831c62dd0b7f9f786ef766279e40f6f0551b529d5a1643b1b809540fbaa4b853",
    "remediation_fields": {
      "caveats": [
        "This is rule presence, not a test of port coverage or reachability; one group\u2019s rules can complement another\u2019s."
      ],
      "steps": [
        "Configure only the inbound rules the listeners, targets or health checks need."
      ],
      "summary": "Configure only the inbound rules the listeners, targets or health checks need."
    },
    "reviewed_binding": {
      "closure": {
        "field": "IpPermissions"
      },
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._classic_sg.<locals>.evaluate": "8a0e017639ecf7fcacc94abd5303a3dfccdb0b73cd743c9eae084b03d161f5d0",
        "peaso.checks.claude2_aws_b_edge._sg_rule_gap": "cb8168c68ea8f331d65c02c031a07edbb24e223428b5f8d0126eee125c8404f4"
      },
      "source_qualname": "_classic_sg.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Classic load balancer lacks attached security groups or a group has no inbound rules."
  },
  "aws.c2b.classic_elb.sg_outbound_rule": {
    "description_base_sha256": "cf4eb29e9eaf93a816a53ca52922d69ad204c26ca73ded362f5f106af5c33dd6",
    "description_fields": {
      "description": "Checks that security groups are attached and every resolved group has at least one outbound rule."
    },
    "remediation_base_sha256": "4f3cb364d1d1f94c8f2364fedee9bd44b98145257f2b1d5b17a1f7dbff5fb7c1",
    "remediation_fields": {
      "caveats": [
        "This is rule presence, not a test of port coverage or reachability; one group\u2019s rules can complement another\u2019s."
      ],
      "steps": [
        "Configure only the outbound rules the listeners, targets or health checks need."
      ],
      "summary": "Configure only the outbound rules the listeners, targets or health checks need."
    },
    "reviewed_binding": {
      "closure": {
        "field": "IpPermissionsEgress"
      },
      "constants": {},
      "kind": "classic_load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._classic_sg.<locals>.evaluate": "8a0e017639ecf7fcacc94abd5303a3dfccdb0b73cd743c9eae084b03d161f5d0",
        "peaso.checks.claude2_aws_b_edge._sg_rule_gap": "cb8168c68ea8f331d65c02c031a07edbb24e223428b5f8d0126eee125c8404f4"
      },
      "source_qualname": "_classic_sg.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Classic load balancer lacks attached security groups or a group has no outbound rules."
  },
  "aws.c2b.cloudfront.default_behavior_https": {
    "description_base_sha256": "3adff8b379639fdd666b9a44a94c0d929501d3c59637682aedb5425a6f5bc2d1",
    "description_fields": {
      "description": "Reads only the default cache behavior\u2019s viewer protocol policy and rejects allow-all."
    },
    "remediation_base_sha256": "9ac226463b830f7b767808cda95f5e3f7df065ea560834358cfe20f8c68d7581",
    "remediation_fields": {
      "caveats": [
        "Additional behaviors and origin transport are assessed separately."
      ],
      "steps": [
        "Require HTTPS or redirect HTTP to HTTPS on the default behavior."
      ],
      "summary": "Require HTTPS or redirect HTTP to HTTPS on the default behavior."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "VIEWER": [
          "allow-all",
          "https-only",
          "redirect-to-https"
        ]
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._cfg": "4989f77ecaa8160501ee533074c26bb63e75fc11384700de9ebe7c0834182fd3",
        "peaso.checks.claude2_aws_b_edge._viewer_policy": "fe6ca9f4b8c10d6e50187a1372c324ba39082103598fa78dec9b242f34442b99",
        "peaso.checks.claude2_aws_b_edge.cf_default_https": "c471a098879b3c3d8d84c1b9278ae65dd1137e28ae51252824cb5f85955cff07"
      },
      "source_qualname": "cf_default_https"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default CloudFront behavior permits HTTP viewers."
  },
  "aws.c2b.cloudfront.https_sni": {
    "description_base_sha256": "6b925f3bdad9fd5d3747f4f2cb1c9abb7f93087c632b31cec6573bf755f4632a",
    "description_fields": {
      "description": "Checks custom viewer certificates for sni-only SSL support, treating omitted support as static-IP mode."
    },
    "remediation_base_sha256": "ce16d24550b5a631693bd29ecf51375b953d370c5182b23bc29da828258b0510",
    "remediation_fields": {
      "caveats": [
        "Dedicated-IP support is a compatibility and cost choice, not evidence of plaintext traffic."
      ],
      "steps": [
        "Use SNI-only support unless legacy clients need dedicated-IP HTTPS."
      ],
      "summary": "Use SNI-only support unless legacy clients need dedicated-IP HTTPS."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._cfg": "4989f77ecaa8160501ee533074c26bb63e75fc11384700de9ebe7c0834182fd3",
        "peaso.checks.claude2_aws_b_edge.cf_sni": "33e48520d7065291afe52bf57252532f736291c40aa25ea2b6c91861e55d3a0c"
      },
      "source_qualname": "cf_sni"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The custom viewer certificate does not use SNI-only HTTPS support."
  },
  "aws.c2b.cloudfront.pqc_tls": {
    "description_base_sha256": "adda8e52babb6f29be8422258afadfc9f5effa42a2e89251a60f6c8c4810996d",
    "description_fields": {
      "description": "Compares the custom viewer certificate\u2019s minimum TLS policy with the pinned TLSv1.3_2025 preference."
    },
    "remediation_base_sha256": "83f53a201c74cf98a887f01cc0eda7814f71bb07df0d47ec583f83353d26d8b0",
    "remediation_fields": {
      "caveats": [
        "A different policy does not by itself prove weak conventional TLS."
      ],
      "steps": [
        "Adopt the supported post-quantum TLS profile if required and compatible with intended clients."
      ],
      "summary": "Adopt the supported post-quantum TLS profile if required and compatible with intended clients."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "CF_PQC": [
          "TLSv1.3_2025"
        ]
      },
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._cfg": "4989f77ecaa8160501ee533074c26bb63e75fc11384700de9ebe7c0834182fd3",
        "peaso.checks.claude2_aws_b_edge.cf_pqc": "827dcc53f966342fadc026b638d80ab6b194bc01f06eb0fe6d6ee1199e89787a"
      },
      "source_qualname": "cf_pqc"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The distribution does not use this profile\u2019s TLSv1.3_2025 custom-certificate policy."
  },
  "aws.c2b.cloudfront.s3_origin_access_control": {
    "description_base_sha256": "5604e3c8d64aa7f3c7e4690cdf238f4b4433544d1cbc37e35611f4bfdc88cf37",
    "description_fields": {
      "description": "Checks that every configured S3 origin references an Origin Access Control."
    },
    "remediation_base_sha256": "e558295a2a07152cdfc5066bdcdba0bcb85365fadd1787e22a16f9a7c0fe5be9",
    "remediation_fields": {
      "caveats": [
        "An OAC reference alone does not prove signing settings or a restrictive bucket policy."
      ],
      "steps": [
        "Use OAC for S3 origins that should be restricted to CloudFront and align bucket permissions."
      ],
      "summary": "Use OAC for S3 origins that should be restricted to CloudFront and align bucket permissions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._cfg": "4989f77ecaa8160501ee533074c26bb63e75fc11384700de9ebe7c0834182fd3",
        "peaso.checks.claude2_aws_b_edge._origins": "fbe849672d0bde5d6724e7f277503da82ada6842fcd8c1decc461d34b5ea1bef",
        "peaso.checks.claude2_aws_b_edge._s3_config": "4887d3cbfdeb0b04b21f62c7cc0459143723927b01cc9ee87c45f23931a9a91b",
        "peaso.checks.claude2_aws_b_edge.cf_oac": "472c72300afaf43994aca84e0045c378893bb4e2b5e62c354ee855327563c158"
      },
      "source_qualname": "cf_oac"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A configured S3 origin has no Origin Access Control reference."
  },
  "aws.c2b.cloudfront.s3_origin_access_identity": {
    "description_base_sha256": "d2bfee464f2356f1bfe45b8798ef80460199f7f0ab3ca214365020110dc57ed1",
    "description_fields": {
      "description": "Checks the legacy OAI field on origins whose domain ends with s3.amazonaws.com."
    },
    "remediation_base_sha256": "f1521d28d37eeca7a1a6916f257b278750b2368f306c1ec192e8bf7114417450",
    "remediation_fields": {
      "caveats": [
        "An OAC-only origin can fail this legacy OAI profile despite using the recommended mechanism."
      ],
      "steps": [
        "Prefer OAC for new deployments; review legacy OAI only if this compatibility profile is required."
      ],
      "summary": "Prefer OAC for new deployments; review legacy OAI only if this compatibility profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudfront_distribution",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._cfg": "4989f77ecaa8160501ee533074c26bb63e75fc11384700de9ebe7c0834182fd3",
        "peaso.checks.claude2_aws_b_edge._origins": "fbe849672d0bde5d6724e7f277503da82ada6842fcd8c1decc461d34b5ea1bef",
        "peaso.checks.claude2_aws_b_edge._s3_config": "4887d3cbfdeb0b04b21f62c7cc0459143723927b01cc9ee87c45f23931a9a91b",
        "peaso.checks.claude2_aws_b_edge.cf_oai": "c6c6fd63b0f8747729b516c4f76703fc9f9e112b233d3e1a329a9ee08b0d39f0"
      },
      "source_qualname": "cf_oai"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An applicable S3 origin declares an empty legacy Origin Access Identity."
  },
  "aws.c2b.datasync.task_log_group": {
    "description_base_sha256": "af1c201f5da992be06b660ec5f8a1c510ebd3a0f338f4892d8ef753b29b5fb1a",
    "description_fields": {
      "description": "Reads the DataSync task\u2019s CloudWatch log-group ARN."
    },
    "remediation_base_sha256": "c0254501a7a383993c2de661f565e57034b7ab61d9c8f7be1bd0db758c8d5343",
    "remediation_fields": {
      "caveats": [
        "A reference does not prove log permissions, delivery or retention."
      ],
      "steps": [
        "Configure a suitable log group if task activity must be recorded."
      ],
      "summary": "Configure a suitable log group if task activity must be recorded."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "datasync_task",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._task_detail": "38b842c46727faae3dddbaa01cabb9c843508adcb00455d37205cfbf7378e403",
        "peaso.checks.claude2_aws_b_data.datasync_log_group": "48c5f52f23a56f8c8ed9ef03aa3a751bf0ee70bf5a2282146684613d7ec83d73",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "datasync_log_group"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The DataSync task declares no CloudWatch log group."
  },
  "aws.c2b.datasync.task_logging_level": {
    "description_base_sha256": "030281fd565fbef6cdf9420515edc725ec25330faa510092f621ee70d2c58e7e",
    "description_fields": {
      "description": "Checks the DataSync task has a log group and log level BASIC or TRANSFER."
    },
    "remediation_base_sha256": "ca235b00e89d5e26035474b382e8ce6c813570065a2a3d288649e9bb7092afd2",
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove delivery or coverage outside this task."
      ],
      "steps": [
        "Configure the required log group and a suitable task log level."
      ],
      "summary": "Configure the required log group and a suitable task log level."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "datasync_task",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._task_detail": "38b842c46727faae3dddbaa01cabb9c843508adcb00455d37205cfbf7378e403",
        "peaso.checks.claude2_aws_b_data.datasync_log_level": "484971c8e207e7c49a01db83aa38894ba3946eaf69758ee1a6b515d245668ee2",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "datasync_log_level"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DataSync task lacks a log group or a BASIC/TRANSFER logging level."
  },
  "aws.c2b.dax.multi_az": {
    "description_base_sha256": "95da2431160df5c1f8dc9766af1954508352765e4668a2f176bc10124ebbe90c",
    "description_fields": {
      "description": "Counts distinct availability-zone names among declared DAX nodes; requires at least two."
    },
    "remediation_base_sha256": "b4f3a91a42aacfb25b1b734ba70a262cb94a2bbd0eb1ad0594dff2fda616a67f",
    "remediation_fields": {
      "caveats": [
        "Declared node placement does not prove node health or successful failover."
      ],
      "steps": [
        "Use nodes in multiple zones if the DAX workload requires redundancy."
      ],
      "summary": "Use nodes in multiple zones if the DAX workload requires redundancy."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dax_cluster",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.dax_multi_az": "86f7e7fd020276e60f2def9c8436064bcf9a277966b3db70e0b8fa0a5a7c3441",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "dax_multi_az"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DAX cluster declares nodes in fewer than two availability zones."
  },
  "aws.c2b.directconnect.connection_redundancy": {
    "description_base_sha256": "d55c91e686e57429ca87d56590fe5da3c65db3d2477a8a26cbaca690daf47e33",
    "description_fields": {
      "description": "Counts scoped Direct Connect connections and distinct declared locations; requires at least two of each."
    },
    "remediation_base_sha256": "3c6b3fea228ef27481b6f70c80007bb5e47ab9c731d53e0068362cf42b578ed0",
    "remediation_fields": {
      "caveats": [
        "Inventory redundancy does not prove link health, independent failure domains or tested failover.",
        "The criterion requires two connections at two distinct locations; no connections is NOT_APPLICABLE. Verify a failover test before relying on declared redundancy."
      ],
      "steps": [
        "Add a connection at a different location if Direct Connect redundancy is required."
      ],
      "summary": "Add a connection at a different location if Direct Connect redundancy is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "directconnect_connection",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.dx_connections": "b072ee56ba6b269d52fbe4dcce6b2d159ff826932aa7a187ad1b64fbef87fedd",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "dx_connections"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Direct Connect lacks two connections at distinct locations."
  },
  "aws.c2b.directconnect.virtual_interface_redundancy": {
    "description_base_sha256": "b72689f1d48384390b99252019ec2125df2a410db0c69a8c5f5389365f06f0fb",
    "description_fields": {
      "description": "Groups virtual interfaces by gateway and requires two distinct interfaces on distinct connections per gateway."
    },
    "remediation_base_sha256": "1207aa1ae1a28b1327c78993b22316fd5cbc52c01e44ec6e5e6652f85770e6f9",
    "remediation_fields": {
      "caveats": [
        "The declarations do not prove route convergence, link health or successful failover.",
        "The criterion requires two distinct VIF IDs on two connection IDs per gateway; no interfaces is NOT_APPLICABLE. Verify a failover test before relying on the declarations."
      ],
      "steps": [
        "Add a second interface on another connection for gateways that need redundancy."
      ],
      "summary": "Add a second interface on another connection for gateways that need redundancy."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "directconnect_virtual_interface",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge.dx_vifs": "ba292ed2bb672735d0c7e004babb1871604be24af12073946f6e240489cb8d99",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "dx_vifs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A gateway lacks two virtual interfaces on distinct connections."
  },
  "aws.c2b.dlm.ebs_snapshot_policy_with_snapshots": {
    "description_base_sha256": "14e2d58de283c468f1a205645180a0400ef367b9c1a41f7cd6ddd63a887892b5",
    "description_fields": {
      "description": "Checks for an EBS_SNAPSHOT-prefixed lifecycle policy when the scope contains EBS snapshots."
    },
    "remediation_base_sha256": "3c1f9a8114ec40befaefc9db776b97f23b869138a4e338c331775ff7d4f194ef",
    "remediation_fields": {
      "caveats": [
        "Policy presence does not prove it is enabled, selects these snapshots or produces backups."
      ],
      "steps": [
        "Configure appropriate snapshot lifecycle management if automated retention is needed."
      ],
      "summary": "Configure appropriate snapshot lifecycle management if automated retention is needed."
    },
    "reviewed_binding": {
      "closure": {
        "typed": true
      },
      "constants": {},
      "kind": "dlm_lifecycle_policy",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._dlm.<locals>.evaluate": "d11b2d7636549d0346e0eca39844231610fd218b74b77ad931dcb3ce5a5c43c8",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "_dlm.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The scope has EBS snapshots but lacks an EBS_SNAPSHOT-prefixed lifecycle policy."
  },
  "aws.c2b.dlm.policy_exists_with_snapshots": {
    "description_base_sha256": "354f4173cfc2627926b15602442ddcd47af5ac4f65800e6b4a47dd89b24a69cc",
    "description_fields": {
      "description": "Checks for any lifecycle policy when the scope contains EBS snapshots."
    },
    "remediation_base_sha256": "14d0f1457fa8641afdfd98c286aa698fd106103dee9c4b290a598ca07bb90275",
    "remediation_fields": {
      "caveats": [
        "Policy presence does not prove it is enabled, selects these snapshots or produces backups."
      ],
      "steps": [
        "Configure appropriate snapshot lifecycle management if automated retention is needed."
      ],
      "summary": "Configure appropriate snapshot lifecycle management if automated retention is needed."
    },
    "reviewed_binding": {
      "closure": {
        "typed": false
      },
      "constants": {},
      "kind": "dlm_lifecycle_policy",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._dlm.<locals>.evaluate": "d11b2d7636549d0346e0eca39844231610fd218b74b77ad931dcb3ce5a5c43c8",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "_dlm.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The scope has EBS snapshots but lacks any lifecycle policy."
  },
  "aws.c2b.dms.certificate_not_expired": {
    "description_base_sha256": "ebd7d38c474355a05c08f5d668011fa9215427c14d519e21badc2f6fb01e36e9",
    "description_fields": {
      "description": "Compares the DMS certificate expiry with one second before the snapshot day starts."
    },
    "remediation_base_sha256": "893372b26ed191f853b70188d3c7c5d3cd5c3d2ded950d5d64fc65ae9fdcecf2",
    "remediation_fields": {
      "caveats": [
        "This calendar-boundary profile does not fail expiry during the current snapshot day.",
        "Certificate deletion is irreversible. Migrate endpoint associations and verify connectivity before retiring the old certificate; importing a new certificate alone cannot clear the old expired-certificate finding."
      ],
      "steps": [
        "Renew or replace the certificate if it is still used."
      ],
      "summary": "Renew or replace the certificate if it is still used."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dms_certificate",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.dms_certificate": "468503c4bd9712c9b107bdf0a2a88ed058f0bc691ba4621e3acd7f062fbae70a",
        "peaso.checks.claude_aws_b_common.clock": "ab5a2682bc5a3cea8b9401c0db21419e8e73541184499f65f169c4bdce2acf2e",
        "peaso.checks.claude_aws_b_common.parse_time": "54cc7721378b8eb220b5730d3e5a0e5a2a832c7daf598e85da3ff58d48bb023f"
      },
      "source_qualname": "dms_certificate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DMS certificate expired before this profile\u2019s snapshot-day cutoff."
  },
  "aws.c2b.dms.endpoint_ssl": {
    "description_base_sha256": "14f9f5f989b64cf191bf8d2da6b772967d2deb5270ecad77cf2d9f334edca916",
    "description_fields": {
      "description": "Flags DMS endpoint SslMode only when it is exactly none."
    },
    "remediation_base_sha256": "2431716f061c5cbf312dd3404c406c5d9606123df2334a21440e9d5c4254d844",
    "remediation_fields": {
      "caveats": [
        "Omitted or other mode values pass this literal profile and do not establish certificate verification."
      ],
      "steps": [
        "Use an engine-supported encrypted transport mode where required."
      ],
      "summary": "Use an engine-supported encrypted transport mode where required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dms_endpoint",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.dms_endpoint_ssl": "8f87f62bb2238d4e8d0bbcc4b5e480f692295119958d3c5ecd434672c3eca6aa",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "dms_endpoint_ssl"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The DMS endpoint explicitly sets SSL mode to none."
  },
  "aws.c2b.dms.mongodb_auth": {
    "description_base_sha256": "4d6d2471ef16a9841ffd7bef6580844a249e73bdfa1d7acb328bed1e09197585",
    "description_fields": {
      "description": "Checks MongoDB DMS endpoint AuthType and rejects no, including its omission default."
    },
    "remediation_base_sha256": "634065bb6d77a5b4588401808897e705dee9d26d7251ef85b228c0039dc332ac",
    "remediation_fields": {
      "caveats": [
        "The type declaration does not test credentials or effective database permissions."
      ],
      "steps": [
        "Configure appropriate MongoDB endpoint authentication."
      ],
      "summary": "Configure appropriate MongoDB endpoint authentication."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dms_endpoint",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._engine": "e74fd5626c005dc4f871f9e0dd5f54f4d3bf9030a312a3f7a653fbe92a143e5c",
        "peaso.checks.claude2_aws_b_data.dms_mongodb_auth": "52aaf0f616b2a6d8fc03a6bad0086299d5341f16371800ab36aca5e73a7a188f",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "dms_mongodb_auth"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The MongoDB DMS endpoint declares no authentication."
  },
  "aws.c2b.dms.neptune_iam_auth": {
    "description_base_sha256": "5067da97946c5949e6a2a84441778612ae1bb7a5d94e26971ccbbfe59731b9f6",
    "description_fields": {
      "description": "Reads IamAuthEnabled on Neptune DMS endpoints."
    },
    "remediation_base_sha256": "b5187a343f31e7c292ba1e22e67b6562250aba052d899c1e73d4af1576ebe974",
    "remediation_fields": {
      "caveats": [
        "The flag does not prove usable role permissions or replace network controls."
      ],
      "steps": [
        "Enable IAM authentication if the Neptune integration requires it."
      ],
      "summary": "Enable IAM authentication if the Neptune integration requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dms_endpoint",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._engine": "e74fd5626c005dc4f871f9e0dd5f54f4d3bf9030a312a3f7a653fbe92a143e5c",
        "peaso.checks.claude2_aws_b_data.dms_neptune_iam": "8256030cd4879e288b45b460e08cfa1d799e96f7b270c1482bac8f3d87c4ebad"
      },
      "source_qualname": "dms_neptune_iam"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Neptune DMS endpoint disables IAM authentication."
  },
  "aws.c2b.dms.redis_tls": {
    "description_base_sha256": "5374bff1c8818431351fc6f75c90fab2bd5067c213f8f61838769dabfa1d98fe",
    "description_fields": {
      "description": "Checks Redis DMS endpoint SslSecurityProtocol equals ssl-encryption, including its source omission default."
    },
    "remediation_base_sha256": "433c06c5a192bf98d59edb3d0a3193aa0c4a6ad884114a185ea6bc7c59d5a1fd",
    "remediation_fields": {
      "caveats": [
        "The value does not prove certificate validation or a successful connection."
      ],
      "steps": [
        "Use ssl-encryption for Redis endpoints that require TLS."
      ],
      "summary": "Use ssl-encryption for Redis endpoints that require TLS."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dms_endpoint",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._engine": "e74fd5626c005dc4f871f9e0dd5f54f4d3bf9030a312a3f7a653fbe92a143e5c",
        "peaso.checks.claude2_aws_b_data.dms_redis_tls": "57dca0e7c5c2ee0478bab7797487571b62d0caec4afdaa9fb1d13830d5eaab98",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "dms_redis_tls"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Redis DMS endpoint does not declare ssl-encryption."
  },
  "aws.c2b.dms.task_source_logging": {
    "description_base_sha256": "fb1cd521508260943910f3e791cbc823b6263832015085c473b3af19a388d560",
    "description_fields": {
      "description": "Checks DMS task logging is enabled and SOURCE_CAPTURE and SOURCE_UNLOAD have a default, debug or detailed-debug severity."
    },
    "remediation_base_sha256": "010470c7047fce96f201358514d45412d511d12a4ba4e96589a9385ebdd4687a",
    "remediation_fields": {
      "caveats": [
        "Other log levels fail this exact profile; no logs are inspected or delivery verified."
      ],
      "steps": [
        "Enable the required task component logging at an appropriate diagnostic level."
      ],
      "summary": "Enable the required task component logging at an appropriate diagnostic level."
    },
    "reviewed_binding": {
      "closure": {
        "components": [
          "SOURCE_CAPTURE",
          "SOURCE_UNLOAD"
        ]
      },
      "constants": {},
      "kind": "dms_replication_task",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._dms_logging.<locals>.evaluate": "28cd2afbe91f67b27d720286822b6f6762101094780104b4531e6f051104d1ef",
        "peaso.checks.claude2_aws_b_data.task_logging": "92e6fa603c329e035c2206e652e44c1f2a38802dcff0b12c0429d325052429bc"
      },
      "source_qualname": "_dms_logging.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "DMS task logging is disabled or lacks the required SOURCE_CAPTURE and SOURCE_UNLOAD settings."
  },
  "aws.c2b.dms.task_target_logging": {
    "description_base_sha256": "b355f561dd7d2e292600991ee5c68c54a0bafca080d9ce0eccca1f1081ace76c",
    "description_fields": {
      "description": "Checks DMS task logging is enabled and TARGET_APPLY and TARGET_LOAD have a default, debug or detailed-debug severity."
    },
    "remediation_base_sha256": "17dba560fc4d5d484b162b5481974f61401d6d511cccd5cbb22eace6aaaaf41d",
    "remediation_fields": {
      "caveats": [
        "Other log levels fail this exact profile; no logs are inspected or delivery verified."
      ],
      "steps": [
        "Enable the required task component logging at an appropriate diagnostic level."
      ],
      "summary": "Enable the required task component logging at an appropriate diagnostic level."
    },
    "reviewed_binding": {
      "closure": {
        "components": [
          "TARGET_APPLY",
          "TARGET_LOAD"
        ]
      },
      "constants": {},
      "kind": "dms_replication_task",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._dms_logging.<locals>.evaluate": "28cd2afbe91f67b27d720286822b6f6762101094780104b4531e6f051104d1ef",
        "peaso.checks.claude2_aws_b_data.task_logging": "92e6fa603c329e035c2206e652e44c1f2a38802dcff0b12c0429d325052429bc"
      },
      "source_qualname": "_dms_logging.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "DMS task logging is disabled or lacks the required TARGET_APPLY and TARGET_LOAD settings."
  },
  "aws.c2b.docdb.snapshot_not_public_prowler": {
    "description_base_sha256": "49790d8048b35a4f507c3edcaf8a1974c2390ddc8a0ec45d97c55fb28a38bfb4",
    "description_fields": {
      "description": "Checks all returned DocumentDB snapshot attribute-value lists for the all marker."
    },
    "remediation_base_sha256": "7f4f5584d6e2a3e99c4f1ce3f62c9eade672a08300ee8f62a8efd6f3e72e4743",
    "remediation_fields": {
      "caveats": [
        "This source examines every attribute list, not only restore; the raw attribute identifies the actual declaration."
      ],
      "steps": [
        "Review the matching attribute and remove unnecessary public restore sharing."
      ],
      "summary": "Review the matching attribute and remove unnecessary public restore sharing."
    },
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "docdb_snap_public",
      "closure": {},
      "constants": {
        "_CSNAP": "Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes"
      },
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._docdb": "cfe5341d32b49a184c33908500790570bbca9d88ea07cbad31f81bc77d32c2b8",
        "peaso.checks.claude2_aws_b_data._snap_values": "a98dfa571c0376038d5cc0b7272349d60489c910961e0d7b31e22a4acb0507b6",
        "peaso.checks.claude2_aws_b_data.docdb_snap_public": "61014358e4e6e34e0fd9cdaf98b1082de1e5d54e300b923e2a35bd4c17565cda"
      }
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "A DocumentDB snapshot attribute contains the public all marker."
  },
  "aws.c2b.docdb.snapshot_restore_not_all_exact": {
    "description_base_sha256": "1e8ba1310ab3cfaf9ca46a44ed8cf2018f6054720425efbab41ef9c6c5143928",
    "description_fields": {
      "description": "Checks DocumentDB snapshot restore attributes for the public all value."
    },
    "remediation_base_sha256": "d160cdd82f975324f89480ecf8650913d7de3452228ef691f7b608b61871b7b1",
    "remediation_fields": {
      "caveats": [
        "This is a declared snapshot share, not network exposure or evidence the snapshot was copied."
      ],
      "steps": [
        "Remove the public restore share if it is unnecessary; preserve explicitly approved account shares."
      ],
      "summary": "Remove the public restore share if it is unnecessary; preserve explicitly approved account shares."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_CSNAP": "Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes"
      },
      "kind": "rds_cluster_snapshot",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._docdb": "cfe5341d32b49a184c33908500790570bbca9d88ea07cbad31f81bc77d32c2b8",
        "peaso.checks.claude2_aws_b_data.docdb_snap_exact": "e5fe86f86cebd4e23234655c9a9979ca2999152f37a8676ad9dd5be6ee6a4751",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      },
      "source_qualname": "docdb_snap_exact"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The DocumentDB snapshot grants restore access to all accounts."
  },
  "aws.c2b.documentdb.backup_retention_7": {
    "description_base_sha256": "610dc1c68ef1683c9a80c812faa1367e35f5ea0606fd9a565648e9e280ea17d8",
    "description_fields": {
      "description": "Checks DocumentDB automatic-backup retention is at least seven days."
    },
    "remediation_base_sha256": "8c47fb794730df03483b4e12472cd67ccef68966bbd394262a1b6ec2112386f7",
    "remediation_fields": {
      "caveats": [
        "Retention settings do not prove successful backups or restores."
      ],
      "steps": [
        "Increase backup retention if seven days is the required recovery window."
      ],
      "summary": "Increase backup retention if seven days is the required recovery window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "docdb_cluster",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._docdb": "cfe5341d32b49a184c33908500790570bbca9d88ea07cbad31f81bc77d32c2b8",
        "peaso.checks.claude2_aws_b_data.docdb_backup": "d28f214f650b20c2fea653a71c4c0c44c18b6c063f9564fcec7eb9f9ea1476a5"
      },
      "source_qualname": "docdb_backup"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "DocumentDB backup retention is below seven days."
  },
  "aws.c2b.documentdb.cluster_log_exports": {
    "description_base_sha256": "ba5822ee5217647899af0d3ccb41dc21622b8a15028af3359224a1f8c61f5c71",
    "description_fields": {
      "description": "Checks DocumentDB exported log types include both audit and profiler."
    },
    "remediation_base_sha256": "3ec7a10ee1d415455694fd73f4b0c9e3e24b5e549c7d4332e6a3d21c3ef74cdd",
    "remediation_fields": {
      "caveats": [
        "Declared exports do not prove log generation or delivery."
      ],
      "steps": [
        "Enable the log exports needed for auditing and performance investigation."
      ],
      "summary": "Enable the log exports needed for auditing and performance investigation."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "docdb_cluster",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._docdb": "cfe5341d32b49a184c33908500790570bbca9d88ea07cbad31f81bc77d32c2b8",
        "peaso.checks.claude2_aws_b_data.docdb_log_exports": "f6fe170cf3fd6bb562ccb8e4c35c23371d3e1aaf16995b0489768a0f7752e137",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      },
      "source_qualname": "docdb_log_exports"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DocumentDB cluster lacks an audit or profiler log export."
  },
  "aws.c2b.drs.region_has_job": {
    "description_base_sha256": "e1e2de4cf1ccb07265e7a592bfe05fc9dad07d7478e86faaa1a24886ae035c3e",
    "description_fields": {
      "description": "Checks configured DRS source-server replication states for STOPPED, STALLED or DISCONNECTED; incomplete states remain UNKNOWN."
    },
    "remediation_base_sha256": "ff0808d41ce038a03f9fa74f13f4da319575332137a4ed134d0dfbc88794f1d2",
    "remediation_fields": {
      "caveats": [
        "Despite the legacy identifier, this checks replication state, not job presence, recovery drills or workload RTO.",
        "This native scope check now uses a complete DescribeSourceServers inventory and dataReplicationInfo.dataReplicationState. It does not use DescribeJobs history; historical recovery jobs cannot establish current replication.",
        "No configured source servers is NOT_APPLICABLE, not proof that all required workloads are protected. The protection scope must be established by the recovery owner.",
        "StartReplication is documented for STOPPED sources and restarts billing. STALLED/DISCONNECTED require cause-specific repair; intermediate or unread states are UNKNOWN. No drill or recovery launch is suggested by this template.",
        "CONTINUOUS alone does not prove recovery readiness, acceptable lag, launch configuration or workload RTO. Those require separate owner review and authorized drills."
      ],
      "steps": [
        "Resolve impaired replication for the affected configured source servers."
      ],
      "summary": "Resolve impaired replication for the affected configured source servers."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "drs_source_server",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.drs_jobs": "4a07adfa66bbf587045d114251b6dbdfc7482c3e5b1ba1e893ec4ba359d412f4",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998"
      },
      "source_qualname": "drs_jobs"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "At least one configured DRS source server has stopped, stalled or disconnected replication."
  },
  "aws.c2b.dynamodb.capacity_autoscaling": {
    "description_base_sha256": "15a2f242820e4ed59b0504af2b31d1b0c6efbdabf0f296594f52a71d28c012fa",
    "description_fields": {
      "description": "Checks provisioned tables for read and write scalable-target dimensions; on-demand billing passes."
    },
    "remediation_base_sha256": "36873196539535b235e8d48708088da69b06c77b4cadd98181758e8258bdf27d",
    "remediation_fields": {
      "caveats": [
        "Scalable-target presence does not prove scaling policies or successful scaling."
      ],
      "steps": [
        "Configure appropriate read and write capacity scaling if provisioned capacity should scale automatically."
      ],
      "summary": "Configure appropriate read and write capacity scaling if provisioned capacity should scale automatically."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_RW": [
          "dynamodb:table:ReadCapacityUnits",
          "dynamodb:table:WriteCapacityUnits"
        ]
      },
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data.table_autoscaling": "955266e119c2ca31c6832ade48ae2b58f0f1ef33a9dc78ed808e7bbd91a734ce",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "table_autoscaling"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The provisioned DynamoDB table lacks a read or write scalable-target dimension."
  },
  "aws.c2b.dynamodb.policy_not_cross_account": {
    "description_base_sha256": "9630e7ff7712e86ddb60b28a4e6aec178bb543457f33195fea549ecee0288ec9",
    "description_fields": {
      "description": "Checks the table resource policy with the account-aware public and cross-account grant model."
    },
    "remediation_base_sha256": "c12388e662c1e33a72c8c78843a9888e3594d89ef96062c63ffad1a3392628f1",
    "remediation_fields": {
      "caveats": [
        "Cross-account grants can be legitimate; this model does not establish business approval or all effective permissions."
      ],
      "steps": [
        "Restrict only grants that exceed intended access; retain required partner-account access."
      ],
      "summary": "Restrict only grants that exceed intended access; retain required partner-account access."
    },
    "reviewed_binding": {
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "table_cross_account",
      "closure": {},
      "constants": {},
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_common.detail": "24ef79499457c6519547eeb2b5dff453ac3347e57347cde5b7f4ac8e54452ab4",
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data.table_cross_account": "86d888d170f2ee779b8f42ea9d2de4fca3bd374ce20dd8665e5157308465089a",
        "peaso.checks.claude_aws_b_common.account": "e81980f4cab1bc0e206f42709aa2bc53c5ac0c54268c8cc9c11f58853bbc7bb0",
        "peaso.checks.claude_aws_b_common.is_policy_public": "80a33609944bd0a1df87c7b89bdc31093d82fc9a5544183e6926e7f4ef38032f",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13"
      }
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DynamoDB policy matches this profile\u2019s public or cross-account grant criteria."
  },
  "aws.c2b.dynamodb.sse_kms": {
    "description_base_sha256": "593fa8178c88fc2a6e93539193268f49b02332797ddef355c76d3d0c7447b4b3",
    "description_fields": {
      "description": "Checks DynamoDB SSEType is KMS."
    },
    "remediation_base_sha256": "99d7de3f9909d4bb8ad0535724d50494ce21cf19080bf3f01b46a99eaf17a11b",
    "remediation_fields": {
      "caveats": [
        "Default DynamoDB encryption also encrypts data; this is not a plaintext-data test."
      ],
      "steps": [
        "Use the required KMS key-control option if this profile is necessary."
      ],
      "summary": "Use the required KMS key-control option if this profile is necessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data.table_sse_kms": "6d9934a59c22202a74e2c9857129db2cfa14d282c45914663b10a186db38eba2",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "table_sse_kms"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The DynamoDB table does not declare SSEType KMS."
  },
  "aws.c2b.dynamodb.table_in_backup_selection_or_tag": {
    "description_base_sha256": "13e46ed802143def1e9b3fa70ffeb647d21ab1c8196a336171005215432297fe",
    "description_fields": {
      "description": "Matches supported backup resource strings or an overlapping selection tag key against the table."
    },
    "remediation_base_sha256": "ab2d3efe74f55bc879ed825aff59ba38acdf17147636fd951d8821399146948b",
    "remediation_fields": {
      "caveats": [
        "A tag-key match ignores values and operators, so PASS does not prove effective backup selection."
      ],
      "steps": [
        "Configure a backup selection that actually includes the table, checking both tag keys and values."
      ],
      "summary": "Configure a backup selection that actually includes the table, checking both tag keys and values."
    },
    "reviewed_binding": {
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "table_selected_or_tag",
      "closure": {},
      "constants": {},
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._selections": "ade400deaecb37a025fb65b90887ade0b1ef1820c75a00e1ccbf27fea5131b70",
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data._table_tags": "ccf186e3170e38237a5c9e23cbc093028a25eb634e5c0e548175d301d2bb5658",
        "peaso.checks.claude2_aws_b_data._table_wildcards": "9d9cd72386829ef59b4e80edd47373ddb38aba753cd7cab94d4dfaee87cdc9df",
        "peaso.checks.claude2_aws_b_data.table_selected_or_tag": "beab6861a0a605e5344dba21cede6ed55ef24ebcb90adfcb5aa984158c2fa1c8",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      }
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The table lacks a supported backup resource match or overlapping selection tag key."
  },
  "aws.c2b.dynamodb.table_in_backup_selection_prowler": {
    "description_base_sha256": "8933da19db58cf7013793564f03de5a9fdeeec93f4400be72ee69b247752effb",
    "description_fields": {
      "description": "Matches the table ARN against the source\u2019s limited exact and wildcard backup resource strings."
    },
    "remediation_base_sha256": "d8129d0b4e0b815cbf45113c2a17907c1085d034b6e800cdc69b0634bf423699",
    "remediation_fields": {
      "caveats": [
        "This profile does not evaluate all wildcard patterns, tag selections or exclusion semantics."
      ],
      "steps": [
        "Include the table in a suitable backup selection if scheduled protection is required."
      ],
      "summary": "Include the table in a suitable backup selection if scheduled protection is required."
    },
    "reviewed_binding": {
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "table_selected",
      "closure": {},
      "constants": {},
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data._table_wildcards": "9d9cd72386829ef59b4e80edd47373ddb38aba753cd7cab94d4dfaee87cdc9df",
        "peaso.checks.claude2_aws_b_data.table_selected": "876639b285ef5528cb1e120985e36b481659982ea512cfdc0e9553f9914df58b",
        "peaso.checks.claude_aws_b_common.selection_resources": "1b3f6f283ebba3632ce1b69c735699e6bed8b19e30a0ef64ec89dec3a64c0443"
      }
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The table is not matched by the supported backup-selection resource strings."
  },
  "aws.c2b.dynamodb.table_protected_resource": {
    "description_base_sha256": "1c0496120e0c14d3438333b752d5f9a3de03f4baa0d1dd4886cb46b9830a6239",
    "description_fields": {
      "description": "Joins the table ARN to AWS Backup protected resources of type DynamoDB."
    },
    "remediation_base_sha256": "7302bfed9e8a310a876e21746465325a875b47b2826ff295548a88674654d0be",
    "remediation_fields": {
      "caveats": [
        "A protected-resource record is not proof of the required recovery window or a successful restore."
      ],
      "steps": [
        "Configure suitable backup protection if this table requires it."
      ],
      "summary": "Configure suitable backup protection if this table requires it."
    },
    "reviewed_binding": {
      "kind": "dynamodb_table",
      "module": "peaso.checks.claude2_aws_b_data",
      "source_qualname": "table_protected",
      "closure": {},
      "constants": {},
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data._table_body": "bb844f120eb692ac7894392c400fdbdd0be3e74244c8cb8a0a9cc12421d2cf99",
        "peaso.checks.claude2_aws_b_data.table_protected": "8005f404eb0902296ab22c36d24f2488c3cee45dcc2b78a0f1d7b000726b0d86",
        "peaso.checks.claude_aws_b_common.protected_resources": "e0e174f9b196b5ecb5bea300e5462b559f383bac0dbdf1d15759ad76513ceca8"
      }
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The table has no matching AWS Backup protected-resource record."
  },
  "aws.c2b.ecs.container_instance_in_vpc": {
    "description_base_sha256": "e644179171a3f5913402c86d35189616dda41985768799eac29113dc60d33ac0",
    "description_fields": {
      "description": "Joins ECS container-instance host IDs to EC2 and requires a readable VPC identifier; ECS Anywhere hosts are outside scope."
    },
    "remediation_base_sha256": "05fb02508e7d6446ea209ef1277fe721e5272f6934b784ebd6bf1512a56633b4",
    "remediation_fields": {
      "caveats": [
        "This predicate has no FAIL path; unreadable VPC associations remain UNKNOWN and do not prove public exposure."
      ],
      "steps": [
        "Resolve the EC2 VPC association before relying on this inventory result."
      ],
      "summary": "Resolve the EC2 VPC association before relying on this inventory result."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ecs_container_instance",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute._instance": "ab755971deba2e6cc255421361618b4ffbc26251f866fac871452d314a0098e2",
        "peaso.checks.claude2_aws_b_compute.ecs_ci_vpc": "c8db9a67298864db3332a79b65335bc23804f64b07d19b738df8806987ffeeac"
      },
      "source_qualname": "ecs_ci_vpc"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ECS host VPC association could not be established."
  },
  "aws.c2b.ecs.fargate_latest_platform": {
    "description_base_sha256": "59b0ad805b267006c7bc44ce57eba442f63d2e967f1032f96e6b07f2a1a7f8e6",
    "description_fields": {
      "description": "Checks explicit FARGATE services for LATEST or the pinned Linux 1.4.0 / Windows 1.0.0 platform version."
    },
    "remediation_base_sha256": "13b5176fa4c959b66aa5ac4d15c3460f7ab4a16edc4c6fc555fb4a60991f397e",
    "remediation_fields": {
      "caveats": [
        "The pinned version preference does not discover new releases or prove running tasks have been replaced."
      ],
      "steps": [
        "Plan a compatible platform update if the service is below your required Fargate baseline."
      ],
      "summary": "Plan a compatible platform update if the service is below your required Fargate baseline."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "LATEST_LINUX": "1.4.0",
        "LATEST_WINDOWS": "1.0.0"
      },
      "kind": "ecs_service",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute.ecs_fargate": "0bf0d85f829cdbd99ea3e014b739103cca99a540772587a2c10a5c2c51f517b9",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "ecs_fargate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Fargate service differs from the pinned platform-version preference."
  },
  "aws.c2b.ecs.service_load_balancer_attached": {
    "description_base_sha256": "a8779e34d02d5f34af9e29cb3c2ac2684de190f54afcdbe0edca6e1838fe3cb7",
    "description_fields": {
      "description": "Checks whether the ECS service loadBalancers list is nonempty."
    },
    "remediation_base_sha256": "bdd2c24cdb01409ca708d53ec278eaa2e7deba139ce25fbc13f5fe6ccd26ff30",
    "remediation_fields": {
      "caveats": [
        "Workers, service-discovery and other private services may legitimately need no load balancer."
      ],
      "steps": [
        "Attach a load balancer only if this service needs load-balanced incoming traffic."
      ],
      "summary": "Attach a load balancer only if this service needs load-balanced incoming traffic."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ecs_service",
      "module": "peaso.checks.claude2_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_compute.ecs_svc_lb": "cf6f1820a5459d5844618e8e45e2584e2869fa366602ec236047210e0902ba1f"
      },
      "source_qualname": "ecs_svc_lb"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The ECS service declares no load balancer."
  },
  "aws.c2b.efs.access_point_root_directory": {
    "description_base_sha256": "2fe867c7dfadac20e5a851cb44b6dcc856320a3c83b27c0a37c698906f2852f3",
    "description_fields": {
      "description": "Checks whether the EFS access point\u2019s declared root directory is exactly /."
    },
    "remediation_base_sha256": "88e7f5e31d6550cabe77e4ef590728c2992cca591cb486f8247ddf46943a7a59",
    "remediation_fields": {
      "caveats": [
        "A root path alone does not establish client permissions or expose the filesystem to the Internet."
      ],
      "steps": [
        "Use a narrower access-point root if clients should be confined to a subdirectory."
      ],
      "summary": "Use a narrower access-point root if clients should be confined to a subdirectory."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "efs_access_point",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.efs_ap_root": "3c271222057985c1dae6b59b6547a051f87af8d770ca5c998fccca6cf3c708f0"
      },
      "source_qualname": "efs_ap_root"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The EFS access point uses the filesystem root directory."
  },
  "aws.c2b.efs.access_point_user_identity": {
    "description_base_sha256": "9ac1fac77611364b09727c0f3115a9a0ced6b9ece4815f0736939b9dd97f5fce",
    "description_fields": {
      "description": "Checks whether the EFS access point has a nonempty PosixUser object."
    },
    "remediation_base_sha256": "07def855bb4aaa2470b4d718c89bc0ec8f247cd949aae51e00d7916cbe8b14ff",
    "remediation_fields": {
      "caveats": [
        "Object presence does not prove least privilege or override all filesystem permissions."
      ],
      "steps": [
        "Configure an enforced POSIX identity if the application requires access-point identity mapping."
      ],
      "summary": "Configure an enforced POSIX identity if the application requires access-point identity mapping."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "efs_access_point",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.efs_ap_user": "a599783c9304ead0e63a5f92f4f55d77b0e00450c01ae649952d7bfbc92b048a",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "efs_ap_user"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The EFS access point declares no POSIX user mapping."
  },
  "aws.c2b.elasticache.cluster_no_default_subnet_group": {
    "description_base_sha256": "133609e981215a963608b9cd4e1a7fd33b446e46d3d853d4324c85b3498cf449",
    "description_fields": {
      "description": "Checks whether the cache subnet-group name is exactly default."
    },
    "remediation_base_sha256": "b6ae05faa309dc86de1c21c8926f23575cae48c540d66132e15117cb265c24ac",
    "remediation_fields": {
      "caveats": [
        "The name default alone does not prove poor isolation or public reachability."
      ],
      "steps": [
        "Use a dedicated subnet group if this placement profile is required."
      ],
      "summary": "Use a dedicated subnet group if this placement profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "elasticache_cluster",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.ec_default_subnet_group": "1a14dbb2fc1c32bf03c2cf8132dd14a2bf9c8f1b1b5e73ad2a5e47d0aa36caa0",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "ec_default_subnet_group"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cache cluster uses the subnet group named default."
  },
  "aws.c2b.elasticache.rg_backup_retention_15": {
    "description_base_sha256": "0a0806a347ed7eca5c5899820b81f57ba39e6e97c10c665be6b2dab6779a35c0",
    "description_fields": {
      "description": "Checks replication-group snapshot retention is at least 15 days."
    },
    "remediation_base_sha256": "84bca7ac1580b64844e39c736b95fdfb8ea8656dce586c0bfdbd6cacd688c81e",
    "remediation_fields": {
      "caveats": [
        "Retention configuration does not prove successful snapshots or restores."
      ],
      "steps": [
        "Increase snapshot retention if this cache requires a 15-day recovery window."
      ],
      "summary": "Increase snapshot retention if this cache requires a 15-day recovery window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "elasticache_replication_group",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.rg_backup_15": "df91afe07342ca0c143ed951d18daf4a6430239b645cdb8e46034c1d0ebf784e"
      },
      "source_qualname": "rg_backup_15"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "ElastiCache snapshot retention is below 15 days."
  },
  "aws.c2b.elasticache.rg_backup_retention_7": {
    "description_base_sha256": "d5c69e39a7ab1b8758bcbd8f6fa8a4dfeda52d681b39048c02e77cade8cf51cd",
    "description_fields": {
      "description": "Checks replication-group snapshot retention is at least 7 days."
    },
    "remediation_base_sha256": "afe4101da35a0df2f24bb603a273db95f8ed432ed80cf7b947b06614c490f319",
    "remediation_fields": {
      "caveats": [
        "Retention configuration does not prove successful snapshots or restores."
      ],
      "steps": [
        "Increase snapshot retention if this cache requires a 7-day recovery window."
      ],
      "summary": "Increase snapshot retention if this cache requires a 7-day recovery window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "elasticache_replication_group",
      "module": "peaso.checks.claude2_aws_b_data",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_data.rg_backup_7": "88dd4632df1d45aa0d28c50883f3512cb822cd484a0a536649d75b962a3243c4",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "rg_backup_7"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "ElastiCache snapshot retention is below 7 days."
  },
  "aws.c2b.elbv2.cross_zone_enabled": {
    "description_base_sha256": "56c1885cc601104e67d9cd511a5849c94383a0f5246864f4dfee853f074d5ba4",
    "description_fields": {
      "description": "Reads the cross-zone attribute on network and gateway load balancers; application load balancers are outside scope."
    },
    "remediation_base_sha256": "368842f2eb7b68116d1ccc236f5b43a4ea6aa5257c25fdf020c78af784f7c3d9",
    "remediation_fields": {
      "caveats": [
        "The attribute does not establish healthy targets or actual availability."
      ],
      "steps": [
        "Enable cross-zone balancing if it matches the service\u2019s availability and traffic requirements."
      ],
      "summary": "Enable cross-zone balancing if it matches the service\u2019s availability and traffic requirements."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.claude2_aws_b_edge",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_edge._attrs": "b0a78dbd133ec386e460ff8eff683f346401baaf18297d7d68c0b0d962d5f497",
        "peaso.checks.claude2_aws_b_edge._type": "8cd0ef56271b10bb449d959cd9e0e540b3f1fc511dae6f5cc6fe11623ba801bd",
        "peaso.checks.claude2_aws_b_edge.v2_cross_zone": "2fbbd699b058e156f42d53653ee4519119e0bb2208eb09f5a798a59fd7b6d679"
      },
      "source_qualname": "v2_cross_zone"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cross-zone balancing is disabled on the network or gateway load balancer."
  },
  "aws.c2b.emr.block_public_access_enabled": {
    "description_base_sha256": "26b68e20f97ddb4dddfb197c66b0794cebdf9123b5cd0852bbacfa467e2bdab4",
    "description_fields": {
      "description": "Reads the EMR regional BlockPublicSecurityGroupRules flag."
    },
    "remediation_base_sha256": "675275f35991e46b738431e7bbf38e2f0d9fd9d869ac4051bb323f77fb41dc74",
    "remediation_fields": {
      "caveats": [
        "This flag does not prove existing clusters are private or inspect exception ports."
      ],
      "steps": [
        "Enable the public security-group guardrail where unnecessary public cluster access should be blocked."
      ],
      "summary": "Enable the public security-group guardrail where unnecessary public cluster access should be blocked."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "emr_block_public_access_configuration",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.emr_bpa": "037d86c263220c240a1f14e95879d681908516dec6ce363920a7961c14a03da3"
      },
      "source_qualname": "emr_bpa"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The EMR regional public security-group guardrail is disabled."
  },
  "aws.c2b.es.all_logs_to_cloudwatch": {
    "description_base_sha256": "056428f963ff1dfb5419ac5a25f74b0ceca2632eb96fd7f924c501258f676eb7",
    "description_fields": {
      "description": "Checks OpenSearch domain publishing settings for enabled application, search-slow and index-slow logs with a CloudWatch log-group ARN."
    },
    "remediation_base_sha256": "e00cfa645e2510996c9c6424866fc131a8b506377a054464f17fee9ebd46033c",
    "remediation_fields": {
      "caveats": [
        "The declarations do not prove log generation, destination permissions or delivery."
      ],
      "steps": [
        "Configure the required application, search-slow and index-slow logs publishing destinations."
      ],
      "summary": "Configure the required application, search-slow and index-slow logs publishing destinations."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics._log_to_cloudwatch": "699442ccfe607d68dcc23a6eb2fd44a009f22611d4e8c4c61a1b790c4e8ad06b",
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_all_logs": "35efdc423e7094b3580065e8751ac697937368eb8adbba336716ab566dcb8ed0"
      },
      "source_qualname": "es_all_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The domain lacks an enabled CloudWatch destination for required application, search-slow and index-slow logs."
  },
  "aws.c2b.es.audit_logs_to_cloudwatch": {
    "description_base_sha256": "a82a550ba3ebe16b96550b317204df1779ce679e61d2b3b496f4173fbe4e528e",
    "description_fields": {
      "description": "Checks OpenSearch domain publishing settings for enabled audit logs with a CloudWatch log-group ARN."
    },
    "remediation_base_sha256": "b00228646d9c5ee0a14f2479f78dbc527a53a2d54492e9cd79fc31f4c8f3d9c7",
    "remediation_fields": {
      "caveats": [
        "The declarations do not prove log generation, destination permissions or delivery."
      ],
      "steps": [
        "Configure the required audit logs publishing destinations."
      ],
      "summary": "Configure the required audit logs publishing destinations."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics._log_to_cloudwatch": "699442ccfe607d68dcc23a6eb2fd44a009f22611d4e8c4c61a1b790c4e8ad06b",
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_audit": "902b23f61681422a3a4d102abe547483ff2cdc48ab91a4be9ba2d4175d9d16b1"
      },
      "source_qualname": "es_audit"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The domain lacks an enabled CloudWatch destination for required audit logs."
  },
  "aws.c2b.es.error_logs_to_cloudwatch": {
    "description_base_sha256": "497cfbea01d33c519694529cadc5b5ccd65f395ce55914c7d179434aaaf1e585",
    "description_fields": {
      "description": "Checks OpenSearch domain publishing settings for enabled application error logs with a CloudWatch log-group ARN."
    },
    "remediation_base_sha256": "4e888456061c392292dccdcc77f0bef312c2dc03c7747104592f8cfdbb5a7c83",
    "remediation_fields": {
      "caveats": [
        "The declarations do not prove log generation, destination permissions or delivery."
      ],
      "steps": [
        "Configure the required application error logs publishing destinations."
      ],
      "summary": "Configure the required application error logs publishing destinations."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics._log_to_cloudwatch": "699442ccfe607d68dcc23a6eb2fd44a009f22611d4e8c4c61a1b790c4e8ad06b",
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_error_logs": "d519ff58cfa9af40299a754f96f9069a274111758bd0fa2ee958801141aee070"
      },
      "source_qualname": "es_error_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The domain lacks an enabled CloudWatch destination for required application error logs."
  },
  "aws.c2b.es.in_vpc": {
    "description_base_sha256": "67036c21551fe3288e3f144afb20dd83ea17ea4b3958b1d1538e5c0ab7e8fbde",
    "description_fields": {
      "description": "Checks the OpenSearch domain configuration for a nonempty VPC identifier."
    },
    "remediation_base_sha256": "4504d38c941ac8c698eddc8fae7ad4da3d32b470d51c5f6182e73036d19be24c",
    "remediation_fields": {
      "caveats": [
        "Public service endpoints may be intentional; the VPC field does not assess authorization or routes."
      ],
      "steps": [
        "Use VPC placement if the domain should be privately accessed."
      ],
      "summary": "Use VPC placement if the domain should be privately accessed."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_vpc": "cebcae9adf913ef45d0256de86c73298ce21e6f1d62edf8b0e94999fcdc2846c",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "es_vpc"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The OpenSearch domain declares no VPC identifier."
  },
  "aws.c2b.es.policy_prohibit_public_access": {
    "description_base_sha256": "b85f95708d90768b146c5056e6ab254b63123fc6086035efcf78e9e0af57b4ee",
    "description_fields": {
      "description": "Checks the domain access policy for wildcard-principal grants lacking recognized restricting conditions."
    },
    "remediation_base_sha256": "de814f6b2a92150f4005f0dc1e19e7903f48485a5bcb8651cc8edfe86171485b",
    "remediation_fields": {
      "caveats": [
        "The policy model does not establish effective data access across domain authentication and other controls."
      ],
      "steps": [
        "Restrict unnecessary public policy grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary public policy grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_public_x": "bf46272d483cb9047c236d040a820105cc26d8744a3bf42a95fcf3c80c1775f8",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131"
      },
      "source_qualname": "es_public_x"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The OpenSearch domain policy matches the public-grant model."
  },
  "aws.c2b.es.tls_1_2_policy": {
    "description_base_sha256": "2e3c2864334b5efbfe4c08951a928679a458ce8d180aac54f0d9de306e6b42b1",
    "description_fields": {
      "description": "Compares the domain TLS policy name with the two pinned TLS1.2 policy names."
    },
    "remediation_base_sha256": "799dc8e3eddab4aa20f7b85c198deee483a9b43fd26298a0e86322214b4926cb",
    "remediation_fields": {
      "caveats": [
        "A name outside the pinned allowlist is not automatically weak or a live TLS negotiation result."
      ],
      "steps": [
        "Use an appropriate TLS policy compatible with clients; adopt this exact profile only if required."
      ],
      "summary": "Use an appropriate TLS policy compatible with clients; adopt this exact profile only if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_TLS12": [
          "Policy-Min-TLS-1-2-2019-07",
          "Policy-Min-TLS-1-2-PFS-2023-10"
        ]
      },
      "kind": "opensearch_domain",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.domain_status": "7e8eee9176f57c7ab2499d0baed9baab0fb378b899e13f668711dacb5fcb861e",
        "peaso.checks.claude2_aws_b_analytics.es_tls": "3284f1858a94426d9b17307f7c963370be10ab460015787bc0e9c99220fe1e67"
      },
      "source_qualname": "es_tls"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The OpenSearch domain TLS policy differs from the pinned TLS1.2 profile."
  },
  "aws.c2b.firehose.encrypted_at_rest_or_msk_source": {
    "description_base_sha256": "261381cac21b3989e495db30a0844f169493e31fa8d08fa3151040f0e8d63dfc",
    "description_fields": {
      "description": "Accepts Firehose stream encryption ENABLED or the source\u2019s MSKAsSource encryption alternative."
    },
    "remediation_base_sha256": "d972dd6488d89a90f3f98417927c0e771400793734762cbf9a1f16ef683c8a20",
    "remediation_fields": {
      "caveats": [
        "MSK-source streams use a different encryption boundary; destination encryption is separate."
      ],
      "steps": [
        "Enable supported stream encryption when this stream type requires it."
      ],
      "summary": "Enable supported stream encryption when this stream type requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "firehose_delivery_stream",
      "module": "peaso.checks.claude2_aws_b_analytics",
      "predicate_sources": {
        "peaso.checks.claude2_aws_b_analytics.firehose_rest": "4718c3f80cdc12ff1215cfe8db7a0c2e88b43078850fad5506c9cdb1a997724b",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "firehose_rest"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The non-MSK-source Firehose stream does not declare encryption ENABLED."
  },
  "aws.cb.apigatewayv2.stage_access_logging": {
    "description_base_sha256": "d267ab57fb9f640ba99b7d176bd6440642f81b5775c1c376a21fa55d5c2d0081",
    "description_fields": {
      "description": "Checks that APIv2 stage AccessLogSettings is nonempty."
    },
    "remediation_base_sha256": "ca0b497766bff5e74cba7a0956449174c56447e7099489337e5f3fe078ff01bd",
    "remediation_fields": {
      "caveats": [
        "Object presence does not validate the format, destination permissions or delivery."
      ],
      "steps": [
        "Configure a suitable access-log destination and format if request auditing is needed."
      ],
      "summary": "Configure a suitable access-log destination and format if request auditing is needed."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "http_api_stage",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.empty": "70a375e9fe2c4171e3a260b1ab46bd1808aac1d00b957c7f2a798c1840790151",
        "peaso.checks.claude_aws_b_storage.v2_access_logs": "fef755694b78663e1bf8121902409f65b5e50c74ca7c5c6cff13ca53ec59bee6"
      },
      "source_qualname": "v2_access_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The APIv2 stage has no nonempty access-log settings."
  },
  "aws.cb.firehose.server_side_encryption": {
    "description_base_sha256": "30df768fa9c12772cc6e598de90bc8e16daaf6ba130deaf34c37aba8656741c0",
    "description_fields": {
      "description": "Checks Firehose delivery-stream encryption status for ENABLED."
    },
    "remediation_base_sha256": "44b5c91d4539c53df5ce1d0bfe666ab0b8d61c0659d50dd8d96f77e44b66a6c4",
    "remediation_fields": {
      "caveats": [
        "This status does not assess destination encryption or the special MSK-source alternative."
      ],
      "steps": [
        "Enable suitable stream encryption where supported and required."
      ],
      "summary": "Enable suitable stream encryption where supported and required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "firehose_delivery_stream",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.firehose_sse": "1ce2d0bbdd050392728e2ec92fc70a8aaea9ddf1acdc7bf5a4fc151b6398ac8d"
      },
      "source_qualname": "firehose_sse"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Firehose stream encryption is not in ENABLED status."
  },
  "aws.cb.glacier.vault_policy_no_public_principal": {
    "description_base_sha256": "1fbe2ce2f28c7a419a7f4708dd65d0ef27ac69ed9b8d5870143a3f4ed6e9bddf",
    "description_fields": {
      "description": "Finds Glacier vault-policy wildcard-principal Allow statements without interpreting conditions."
    },
    "remediation_base_sha256": "82a73d0a395951728d89542e8d22feef19db79b09da514ddb88178623079443c",
    "remediation_fields": {
      "caveats": [
        "Conditioned wildcard grants also fail this literal profile; effective access is not computed."
      ],
      "steps": [
        "Review wildcard grants and restrict those exceeding intended access."
      ],
      "summary": "Review wildcard grants and restrict those exceeding intended access."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glacier_vault",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.wildcard_allow_statements": "8a5586bb9a835246ae37b3fe8f2d2afd149fa3013f765c7829df23433f5f49da",
        "peaso.checks.claude_aws_b_storage.glacier_compliance": "38ae954ee4667a8457dd7cf6c16987773d8f64e4d2b82e2554aeccc392a1955e",
        "peaso.checks.claude_aws_b_storage.vault_policy": "df7a8158c73c47ece763947ba7575dc0b8ff8309f07a4273e84509d3f3fbb86b"
      },
      "source_qualname": "glacier_compliance"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Glacier vault policy declares a wildcard-principal Allow."
  },
  "aws.cb.glacier.vault_policy_prohibit_public_access": {
    "description_base_sha256": "886e42751e38bf7ca7eb965783733c8447386b1b2e1ff97c135dea224fb41e43",
    "description_fields": {
      "description": "Finds Glacier wildcard-principal grants lacking this policy model\u2019s recognized restricting conditions."
    },
    "remediation_base_sha256": "d33e6495c03becd6d60a2aab7feae2bffbef75434a82ce61403f039d28315e53",
    "remediation_fields": {
      "caveats": [
        "The declaration model does not prove effective access across explicit denies or external controls."
      ],
      "steps": [
        "Restrict unnecessary public grants to intended principals or scoped conditions."
      ],
      "summary": "Restrict unnecessary public grants to intended principals or scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glacier_vault",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131",
        "peaso.checks.claude_aws_b_storage.glacier_perimeter": "559b6c381b59ee35c7091fd26e5c99763f1f57efa0351f688540eb212b867676",
        "peaso.checks.claude_aws_b_storage.vault_policy": "df7a8158c73c47ece763947ba7575dc0b8ff8309f07a4273e84509d3f3fbb86b"
      },
      "source_qualname": "glacier_perimeter"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Glacier vault policy matches the public-grant model."
  },
  "aws.cb.glacier.vault_policy_star_principal": {
    "description_base_sha256": "afa7ca1ca17577a5e654f7ca76fe44e2a70254b20f0a1eb94465b3878b3c4139",
    "description_fields": {
      "description": "Finds Allow principals containing * in the principal, AWS or CanonicalUser value."
    },
    "remediation_base_sha256": "c4a8bd0bf0834226b2788309fef96b73a693344b7942a3131a86afeda42e47b2",
    "remediation_fields": {
      "caveats": [
        "This source uses substring matching and ignores conditions; a match is not proof of effective public access."
      ],
      "steps": [
        "Review the matching grants and narrow any access beyond intended principals."
      ],
      "summary": "Review the matching grants and narrow any access beyond intended principals."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glacier_vault",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.glacier_prowler": "56001f5e41c7d31f1ca451a8d8e89b8cd00bd43ac8ae933faee7857098e3e692",
        "peaso.checks.claude_aws_b_storage.prowler_star_principal": "36db8645abd38082902848922ecd70eb0345e9cf0bb74374719b7fe88d7b0825",
        "peaso.checks.claude_aws_b_storage.vault_policy": "df7a8158c73c47ece763947ba7575dc0b8ff8309f07a4273e84509d3f3fbb86b"
      },
      "source_qualname": "glacier_prowler"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "A Glacier vault Allow principal contains a wildcard marker."
  },
  "aws.cb.glue.catalog_metadata_encryption": {
    "description_base_sha256": "bc34773f1efbf82a8566464a3ff5f4ca8027af91bc9ae97b2c9e544257ab9db8",
    "description_fields": {
      "description": "Checks whether Glue CatalogEncryptionMode equals DISABLED."
    },
    "remediation_base_sha256": "539e14b11249c418653b4798308e1b915fcb68255914d6f8432eb5f7b899192b",
    "remediation_fields": {
      "caveats": [
        "This literal predicate only rejects DISABLED and does not prove key usability."
      ],
      "steps": [
        "Enable suitable catalog metadata encryption if required."
      ],
      "summary": "Enable suitable catalog metadata encryption if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_data_catalog",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.glue_meta": "e4594b2a06f844236ac6fa84f35c4ec182a471e08410de7a7224b8dbfd3f74dd"
      },
      "source_qualname": "glue_meta"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Glue Data Catalog metadata encryption is set to DISABLED."
  },
  "aws.cb.glue.catalog_metadata_sse_kms_with_tables": {
    "description_base_sha256": "749071acba91a20a4c95a41dc376d01e2fe8b5e00577f65f6fd272290cbbb129",
    "description_fields": {
      "description": "Checks regions containing Glue tables for CatalogEncryptionMode exactly SSE-KMS."
    },
    "remediation_base_sha256": "7765e7344693c3404c43bb4cc5be432046f2edd513b4b23cd28ebdc9b7ec23d8",
    "remediation_fields": {
      "caveats": [
        "SSE-KMS-WITH-SERVICE-ROLE also fails this literal preference and must not be described as plaintext."
      ],
      "steps": [
        "Use the required metadata-encryption mode if this exact profile is necessary."
      ],
      "summary": "Use the required metadata-encryption mode if this exact profile is necessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_data_catalog",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._has_tables": "90142cbf10f51a1e150744c37e8f57ddf68cc83a957a9738d6e99e454bc45d67",
        "peaso.checks.claude_aws_b_storage.glue_meta_tables": "b984ad94ff6cecac3e2961704850f43ac046fcbc0a4a0eaa519b9ca0c1797037"
      },
      "source_qualname": "glue_meta_tables"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The catalog metadata mode is not exactly SSE-KMS in this profile."
  },
  "aws.cb.glue.catalog_password_encryption": {
    "description_base_sha256": "b27f83e78c718a06efb8440998b0f7f79bfc1f54fd646bcf53aaddaab18525a1",
    "description_fields": {
      "description": "Checks ReturnConnectionPasswordEncrypted."
    },
    "remediation_base_sha256": "b6c287dab212a1f5c0d1d20c167c6b0100e6c5bc8cabc59e006dbb8937aa7f6b",
    "remediation_fields": {
      "caveats": [
        "This setting does not read passwords or prove every stored connection uses the key."
      ],
      "steps": [
        "Enable encrypted connection-password retrieval with an appropriate KMS configuration."
      ],
      "summary": "Enable encrypted connection-password retrieval with an appropriate KMS configuration."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_data_catalog",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.glue_password": "f55c2d14853df1c25e0fe4d59543dd33032254d70b4a832210767147741822c6"
      },
      "source_qualname": "glue_password"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Glue Data Catalog does not return connection passwords encrypted under this profile."
  },
  "aws.cb.glue.catalog_password_encryption_with_tables": {
    "description_base_sha256": "b2f05393d1f7e95321f9d38554ad61c57378df12ccc5630ef3317b552fd0d017",
    "description_fields": {
      "description": "Checks ReturnConnectionPasswordEncrypted when the region contains tables."
    },
    "remediation_base_sha256": "a787051ce8000f1623a0a4472ca59e624c378ae3560a17fce8ba8df0ee7ea37e",
    "remediation_fields": {
      "caveats": [
        "This setting does not read passwords or prove every stored connection uses the key."
      ],
      "steps": [
        "Enable encrypted connection-password retrieval with an appropriate KMS configuration."
      ],
      "summary": "Enable encrypted connection-password retrieval with an appropriate KMS configuration."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_data_catalog",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._has_tables": "90142cbf10f51a1e150744c37e8f57ddf68cc83a957a9738d6e99e454bc45d67",
        "peaso.checks.claude_aws_b_storage.glue_password_tables": "335ee98d5d16350118300254b8cbf435072f879108f18106120d49797b32c029"
      },
      "source_qualname": "glue_password_tables"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Glue Data Catalog does not return connection passwords encrypted under this profile."
  },
  "aws.cb.glue.catalog_policy_not_public": {
    "description_base_sha256": "b03da5881625d9dabfd00e4a46a5c5f77ab9c79c20ed86b08e8ce9a7a9533818",
    "description_fields": {
      "description": "Checks the Glue resource policy with the account-aware public-grant model."
    },
    "remediation_base_sha256": "299dcb726cd1b3335948b45c7f4348162c0e19e532737ec5452d28aaf621f3c9",
    "remediation_fields": {
      "caveats": [
        "No policy is outside scope; the model does not prove effective access across all controls."
      ],
      "steps": [
        "Restrict unnecessary wildcard grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary wildcard grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_data_catalog",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.account": "e81980f4cab1bc0e206f42709aa2bc53c5ac0c54268c8cc9c11f58853bbc7bb0",
        "peaso.checks.claude_aws_b_common.is_policy_public": "80a33609944bd0a1df87c7b89bdc31093d82fc9a5544183e6926e7f4ef38032f",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_storage.glue_catalog_policy": "4319e97052c50e54c6eadca2388a93c7ef7df9a76139b044c3f0ca42b10fb416"
      },
      "source_qualname": "glue_catalog_policy"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Glue Catalog policy matches the public-grant model."
  },
  "aws.cb.glue.connection_jdbc_enforce_ssl": {
    "description_base_sha256": "eeeded4b11ca74296d8fcb9f4145ceefceab2f2ae9ce61cd42aca225ad6fb162",
    "description_fields": {
      "description": "Checks JDBC Glue connections for JDBC_ENFORCE_SSL exactly true; non-JDBC connections are outside scope."
    },
    "remediation_base_sha256": "e68f072a0044398c69cc951d4b675c8e6a061ae3d3a0febd28c890bf47e9ac3e",
    "remediation_fields": {
      "caveats": [
        "The setting does not validate server certificates or test a live connection."
      ],
      "steps": [
        "Require SSL on JDBC connections that carry sensitive data."
      ],
      "summary": "Require SSL on JDBC connections that carry sensitive data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_connection",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.glue_ssl": "108e78633ed05f1aa8fd720b81c252e402a47aa008fd557776df35305c8705df"
      },
      "source_qualname": "glue_ssl"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Glue JDBC connection does not explicitly enforce SSL."
  },
  "aws.cb.glue.dev_endpoint_bookmarks_encryption": {
    "description_base_sha256": "6f5076f855d2bb8cd0e9110b1fb2ee610a04fd4dfa8e6509197fc7318bca72d0",
    "description_fields": {
      "description": "Joins the Glue dev endpoint security configuration and rejects missing configuration or job bookmarks mode DISABLED."
    },
    "remediation_base_sha256": "ca029acb0391ed81d0d2f9334e15cc7704f00cc92edf5409eee963d12d82acae",
    "remediation_fields": {
      "caveats": [
        "Only the referenced setting is checked; key usability and existing data encryption are not verified."
      ],
      "steps": [
        "Attach a suitable security configuration that enables encryption for job bookmarks."
      ],
      "summary": "Attach a suitable security configuration that enables encryption for job bookmarks."
    },
    "reviewed_binding": {
      "closure": {
        "block": "JobBookmarksEncryption",
        "field": "JobBookmarksEncryptionMode",
        "sentinel": "EndpointName"
      },
      "constants": {},
      "kind": "glue_dev_endpoint",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._glue_mode.<locals>.evaluate": "15c22fe0465b3597dc4248f28836f72f375c74d7b66ea9403c25ab854bc74dba",
        "peaso.checks.claude_aws_b_storage._security_configuration": "477a9b0741f6bbf2ab2aebf1c3f87a8faa812c545f41fc63b30d33ce2beac4e7"
      },
      "source_qualname": "_glue_mode.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue dev endpoint lacks a resolved encryption configuration or disables job bookmarks encryption."
  },
  "aws.cb.glue.dev_endpoint_cloudwatch_encryption": {
    "description_base_sha256": "31b9e946ffda7ee15c8f22ee48ce3a583b69a9770693e22af7c91f9589e489fc",
    "description_fields": {
      "description": "Joins the Glue dev endpoint security configuration and rejects missing configuration or CloudWatch logs mode DISABLED."
    },
    "remediation_base_sha256": "09eca25b9fa252f7a1355c88e89f26b508f2d8f5a1bea1f4805216ae0000223a",
    "remediation_fields": {
      "caveats": [
        "Only the referenced setting is checked; key usability and existing data encryption are not verified."
      ],
      "steps": [
        "Attach a suitable security configuration that enables encryption for CloudWatch logs."
      ],
      "summary": "Attach a suitable security configuration that enables encryption for CloudWatch logs."
    },
    "reviewed_binding": {
      "closure": {
        "block": "CloudWatchEncryption",
        "field": "CloudWatchEncryptionMode",
        "sentinel": "EndpointName"
      },
      "constants": {},
      "kind": "glue_dev_endpoint",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._glue_mode.<locals>.evaluate": "15c22fe0465b3597dc4248f28836f72f375c74d7b66ea9403c25ab854bc74dba",
        "peaso.checks.claude_aws_b_storage._security_configuration": "477a9b0741f6bbf2ab2aebf1c3f87a8faa812c545f41fc63b30d33ce2beac4e7"
      },
      "source_qualname": "_glue_mode.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue dev endpoint lacks a resolved encryption configuration or disables CloudWatch logs encryption."
  },
  "aws.cb.glue.dev_endpoint_s3_encryption_first_mode": {
    "description_base_sha256": "c50cf0991923a5c3a57dc4b93d1a340d5e46a305a7241085714b22307b526dad",
    "description_fields": {
      "description": "Joins the development endpoint security configuration and checks only the first S3 encryption mode for DISABLED."
    },
    "remediation_base_sha256": "8fe6dee56da72a394f02353d42579fb7e719652e41472e9e050938e182446dc0",
    "remediation_fields": {
      "caveats": [
        "Only the first S3 mode is assessed; this does not inspect all destinations or existing objects."
      ],
      "steps": [
        "Attach a suitable S3-encryption security configuration if required."
      ],
      "summary": "Attach a suitable S3-encryption security configuration if required."
    },
    "reviewed_binding": {
      "closure": {
        "kind": "glue_dev_endpoint",
        "sentinel": "EndpointName"
      },
      "constants": {},
      "kind": "glue_dev_endpoint",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._glue_s3.<locals>.evaluate_first": "ac2ba9bce6e3fdc5ad7ae492306f94471ab0c7a7e379936e190722bafbb40fa2",
        "peaso.checks.claude_aws_b_storage._security_configuration": "477a9b0741f6bbf2ab2aebf1c3f87a8faa812c545f41fc63b30d33ce2beac4e7"
      },
      "source_qualname": "_glue_s3.<locals>.evaluate_first"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue endpoint lacks its security configuration or its first S3 encryption mode is DISABLED."
  },
  "aws.cb.glue.job_bookmarks_encryption": {
    "description_base_sha256": "c8d6bb90e3e92d0e83ca46f5074f3acf398ad41897ec11bdc592f8ecf6ac7c24",
    "description_fields": {
      "description": "Joins the Glue job security configuration and rejects missing configuration or job bookmarks mode DISABLED."
    },
    "remediation_base_sha256": "a1b156a4deff1852b1f0ee6e4caa0fcac9c021840f0112cbfea5cf0ae712ad8e",
    "remediation_fields": {
      "caveats": [
        "Only the referenced setting is checked; key usability and existing data encryption are not verified."
      ],
      "steps": [
        "Attach a suitable security configuration that enables encryption for job bookmarks."
      ],
      "summary": "Attach a suitable security configuration that enables encryption for job bookmarks."
    },
    "reviewed_binding": {
      "closure": {
        "block": "JobBookmarksEncryption",
        "field": "JobBookmarksEncryptionMode",
        "sentinel": "Role"
      },
      "constants": {},
      "kind": "glue_job",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._glue_mode.<locals>.evaluate": "15c22fe0465b3597dc4248f28836f72f375c74d7b66ea9403c25ab854bc74dba",
        "peaso.checks.claude_aws_b_storage._security_configuration": "477a9b0741f6bbf2ab2aebf1c3f87a8faa812c545f41fc63b30d33ce2beac4e7"
      },
      "source_qualname": "_glue_mode.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue job lacks a resolved encryption configuration or disables job bookmarks encryption."
  },
  "aws.cb.glue.job_cloudwatch_encryption": {
    "description_base_sha256": "248122b712f8e67d9e60e58b9e28de059e9e9875fc0f03d40dee1e041ffac9bc",
    "description_fields": {
      "description": "Joins the Glue job security configuration and rejects missing configuration or CloudWatch logs mode DISABLED."
    },
    "remediation_base_sha256": "73d30970357988ecb8eaa4de63dd1d5370d53c1a2c18b87191bb2bad90839512",
    "remediation_fields": {
      "caveats": [
        "Only the referenced setting is checked; key usability and existing data encryption are not verified."
      ],
      "steps": [
        "Attach a suitable security configuration that enables encryption for CloudWatch logs."
      ],
      "summary": "Attach a suitable security configuration that enables encryption for CloudWatch logs."
    },
    "reviewed_binding": {
      "closure": {
        "block": "CloudWatchEncryption",
        "field": "CloudWatchEncryptionMode",
        "sentinel": "Role"
      },
      "constants": {},
      "kind": "glue_job",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._glue_mode.<locals>.evaluate": "15c22fe0465b3597dc4248f28836f72f375c74d7b66ea9403c25ab854bc74dba",
        "peaso.checks.claude_aws_b_storage._security_configuration": "477a9b0741f6bbf2ab2aebf1c3f87a8faa812c545f41fc63b30d33ce2beac4e7"
      },
      "source_qualname": "_glue_mode.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue job lacks a resolved encryption configuration or disables CloudWatch logs encryption."
  },
  "aws.cb.glue.job_continuous_cloudwatch_logging": {
    "description_base_sha256": "a5277e9918f0a956f70e51d42e4133de64446b57f24a5d3408846bf51e2be340",
    "description_fields": {
      "description": "Checks the allowlisted --enable-continuous-cloudwatch-log job flag for true."
    },
    "remediation_base_sha256": "a2a483b936fbba5f05a8c3a411838eada77e648121835c0aa875ec6bbf61dee4",
    "remediation_fields": {
      "caveats": [
        "The flag does not prove delivered logs or account for every version\u2019s logging defaults."
      ],
      "steps": [
        "Enable continuous logging if the job version and operational needs require this flag."
      ],
      "summary": "Enable continuous logging if the job version and operational needs require this flag."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_job",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.glue_job_logging": "ec550975e3820b5e0bc6e3fdfe7685e7eeed5c97f0eee19eaedeb6ca2aa07fe2"
      },
      "source_qualname": "glue_job_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue job does not set its continuous-logging flag to true."
  },
  "aws.cb.glue.ml_transform_encryption_configured": {
    "description_base_sha256": "fce852d082e03ba0ac79a52e296cbcae391174eb1fe58ebb1757f71469295811",
    "description_fields": {
      "description": "Checks whether the Glue ML transform includes TransformEncryption metadata."
    },
    "remediation_base_sha256": "22dca803a08419793230d4429db8da9fc790782810c8dc28f9207404d5428e8d",
    "remediation_fields": {
      "caveats": [
        "Object presence does not prove individual encryption modes are enabled."
      ],
      "steps": [
        "Configure suitable transform encryption where needed."
      ],
      "summary": "Configure suitable transform encryption where needed."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_ml_transform",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.glue_ml_presence": "2356392755e763c8987fb3cc808d19db7b38d334fd5943e77dbc4aee3e26c447"
      },
      "source_qualname": "glue_ml_presence"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue ML transform has no encryption-configuration object."
  },
  "aws.cb.glue.ml_transform_user_data_encryption": {
    "description_base_sha256": "4464aa86619294904c03fa03fff2cad01db379260eabc0811f7bccf672e62f39",
    "description_fields": {
      "description": "Checks the Glue ML user-data encryption mode for DISABLED, including its source omission default."
    },
    "remediation_base_sha256": "b98df0d913f4e160a6685477d97c6f2a681dd1c0b5e03c2fbe9e50bba721e018",
    "remediation_fields": {
      "caveats": [
        "A non-DISABLED mode alone does not validate the key or existing data."
      ],
      "steps": [
        "Enable suitable ML user-data encryption if required."
      ],
      "summary": "Enable suitable ML user-data encryption if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_ml_transform",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.glue_ml": "0e380b1aac16be6442e2aa85bc79b7d8c93e4cb89324c76f6dbc4404f83bba4a"
      },
      "source_qualname": "glue_ml"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Glue ML transform declares user-data encryption disabled."
  },
  "aws.cb.glue.spark_job_version_3": {
    "description_base_sha256": "7a405615c7475e483157b2abd78ba5dc39db61aa24fd9e2a9ce4237af245742e",
    "description_fields": {
      "description": "Checks GlueVersion numerically against 3.0 only when the Spark UI job flag is true."
    },
    "remediation_base_sha256": "0bc87a4789651437029132092725ccd49aec0c7a334f89e918859bcfe9933626",
    "remediation_fields": {
      "caveats": [
        "The pinned 3.0 threshold does not certify current support or the newest release."
      ],
      "steps": [
        "Plan an upgrade if this Spark-UI job requires a supported newer runtime; validate compatibility first."
      ],
      "summary": "Plan an upgrade if this Spark-UI job requires a supported newer runtime; validate compatibility first."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "glue_job",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.glue_spark": "20a88ba2986dc1fc5237ab21fcdd03c7408bf4a7c5dda031cd205ae87dc135aa"
      },
      "source_qualname": "glue_spark"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Spark-UI-enabled Glue job declares a version below 3.0."
  },
  "aws.cb.kafka.cmk_encryption_at_rest": {
    "description_base_sha256": "127a2a4a0e4b617527382182e12d912df5ccac819f8db74661d3da9794b9e6b4",
    "description_fields": {
      "description": "Joins the provisioned cluster data-volume key to KMS metadata and requires a customer-managed key."
    },
    "remediation_base_sha256": "e33227656e27fbd6fc63620a27209de67279f2ed1d382d2e3ac44ab9ae13f40b",
    "remediation_fields": {
      "caveats": [
        "AWS-managed encryption can still protect data; Serverless uses the source\u2019s managed-setting branch."
      ],
      "steps": [
        "Use a customer-managed volume key if required; plan any necessary cluster migration."
      ],
      "summary": "Use a customer-managed volume key if required; plan any necessary cluster migration."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_cmk"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.kms_manager": "8c6889a17131e413b37d1e6cee61cb9dd21463b690219228c6989e33d94c3f75",
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging._prov": "3c19e5f9368a3abb6210efccf057a7332e63a0981705aa227a7652e4636e43c0",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_cmk": "66a9e5bf4f91f5356f069748579c439a04dc45d1c3ffcc89c4e881938cc74b28"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The provisioned MSK volume key is absent or is not customer-managed."
  },
  "aws.cb.kafka.enhanced_monitoring": {
    "description_base_sha256": "cd0af78d38b59bb5a7852a4d62ddf4b9850d41390477c47301cb44609dea451e",
    "description_fields": {
      "description": "Checks that provisioned MSK monitoring is not DEFAULT."
    },
    "remediation_base_sha256": "b5cf7080a93e842b0e56c742eaad5b2d0a57b065cf92a0e3f9d726f3e6cd632b",
    "remediation_fields": {
      "caveats": [
        "A nondefault declaration does not prove metrics delivery or monitor coverage."
      ],
      "steps": [
        "Choose a suitable per-broker monitoring level if additional metrics are needed."
      ],
      "summary": "Choose a suitable per-broker monitoring level if additional metrics are needed."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_monitoring"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging._prov": "3c19e5f9368a3abb6210efccf057a7332e63a0981705aa227a7652e4636e43c0",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_monitoring": "85dbbed930804b08e74fe384197d04b0b8d5f92310a9408765a51a3cd1e7f434"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The provisioned MSK cluster uses DEFAULT monitoring."
  },
  "aws.cb.kafka.mutual_tls_authentication": {
    "description_base_sha256": "d4e1c9e470aec63c444a6f1db6ee07b39a94fc058a7429947dc4800807c09791",
    "description_fields": {
      "description": "Checks provisioned MSK TLS client-authentication Enabled=true."
    },
    "remediation_base_sha256": "1e0a7e9d9ecb528579c82e783bd5d4955703ea80cb12ae1d463973b07c457f56",
    "remediation_fields": {
      "caveats": [
        "Mutual TLS is one authentication option; its absence does not prove unauthenticated access."
      ],
      "steps": [
        "Enable mutual TLS if certificate authentication is required; preserve suitable IAM or SASL authentication."
      ],
      "summary": "Enable mutual TLS if certificate authentication is required; preserve suitable IAM or SASL authentication."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_mtls"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging._prov": "3c19e5f9368a3abb6210efccf057a7332e63a0981705aa227a7652e4636e43c0",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_mtls": "e67dedd13e61b01b442288e11a4e5779a5b48277567abf8a3b8b7294dd3c91e7"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The provisioned MSK cluster does not enable mutual TLS client authentication."
  },
  "aws.cb.kafka.public_access_disabled": {
    "description_base_sha256": "879137bf6d176b9335a6e5fc97c0ddf0f277f71d1f8133e5a446e8662b422849",
    "description_fields": {
      "description": "Reads provisioned MSK public-access type and requires DISABLED."
    },
    "remediation_base_sha256": "44abf0db5e945eaf0fdd93c054e2b2027068a7216da0ea8604fad11d7671ca78",
    "remediation_fields": {
      "caveats": [
        "Public-access configuration does not prove successful network access or bypass of authentication."
      ],
      "steps": [
        "Disable public access if broker clients do not need Internet connectivity."
      ],
      "summary": "Disable public access if broker clients do not need Internet connectivity."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_public"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_public": "d92f60f4c90843cf0ba9bd276a2f57e7afe000960f1c90fd8d2e1db15eb381a2"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The MSK cluster does not declare public access disabled."
  },
  "aws.cb.kafka.tls_client_and_in_cluster": {
    "description_base_sha256": "a67cf69558d9575f36615c1d1217c409e8c76f4e59ab022373c5d553c64c2fa2",
    "description_fields": {
      "description": "Checks provisioned MSK ClientBroker=TLS together with InCluster=true."
    },
    "remediation_base_sha256": "067703683bf5461f373dcfd9ab5b3ae6e1d55f561377263866e23848bb354615",
    "remediation_fields": {
      "caveats": [
        "The settings do not validate client certificates or test live traffic."
      ],
      "steps": [
        "Require TLS-only client-broker traffic and in-cluster encryption where supported."
      ],
      "summary": "Require TLS-only client-broker traffic and in-cluster encryption where supported."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_transit"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging._prov": "3c19e5f9368a3abb6210efccf057a7332e63a0981705aa227a7652e4636e43c0",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_transit": "33cdc7200b888fb35ae540c303fadf58e64e9576b16746fbd887394b31eba0c1"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The provisioned MSK cluster does not require both TLS-only clients and in-cluster encryption."
  },
  "aws.cb.kafka.unauthenticated_access_disabled": {
    "description_base_sha256": "23f8d3ebcfb25f73402364826d1c36e333130c46e4ffcbbcb7e56d9ce0298b97",
    "description_fields": {
      "description": "Reads the provisioned MSK unauthenticated-client flag."
    },
    "remediation_base_sha256": "2f470f6c183e2f41546892b17fface92a816e85e3c9af43a50f477d9d28fc0f0",
    "remediation_fields": {
      "caveats": [
        "The setting does not prove that a network path is reachable."
      ],
      "steps": [
        "Disable unauthenticated client access if it is not intentionally required."
      ],
      "summary": "Disable unauthenticated client access if it is not intentionally required."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_unauth"
        },
        "serverless": "PASS"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_unauth": "0115868e2cd0e586167238aad46627b1e5969a0aba69dead21fe75af37de4f42"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The MSK cluster enables unauthenticated client access."
  },
  "aws.cb.kinesis.customer_kms_key": {
    "description_base_sha256": "4858109535c273c19259ab177a10c672484861f542c9bd28bbe153cf53290380",
    "description_fields": {
      "description": "Checks Kinesis encryption type KMS and rejects the alias/aws/kinesis key identifier."
    },
    "remediation_base_sha256": "6a937ea063cc4995ebeaaf573a2a3ec7d2e1891f9af3dbed091fa9dc18abb021",
    "remediation_fields": {
      "caveats": [
        "The literal alias comparison does not verify key ownership; AWS-managed KMS encryption is still encryption."
      ],
      "steps": [
        "Use a customer-managed key if that key-control profile is required."
      ],
      "summary": "Use a customer-managed key if that key-control profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kinesis_stream",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.kinesis_cmk": "88099bd408e9852ef6c5da7f17f7d9ca91296bfd97739fca13f81b87e4b0073d"
      },
      "source_qualname": "kinesis_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Kinesis stream lacks KMS encryption or uses alias/aws/kinesis."
  },
  "aws.cb.kinesis.kms_encryption": {
    "description_base_sha256": "a9a909eb5949364d349a270e00a5905eb5e5d499d2451e6e11457c4d7faf22b3",
    "description_fields": {
      "description": "Checks Kinesis EncryptionType for KMS."
    },
    "remediation_base_sha256": "b450424b32c5126048e9c2e4cdd70657da0f31cf451e113c1215847347671f1e",
    "remediation_fields": {
      "caveats": [
        "This declaration does not validate the key or test data access."
      ],
      "steps": [
        "Enable KMS encryption if the stream data requires it."
      ],
      "summary": "Enable KMS encryption if the stream data requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kinesis_stream",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage.kinesis_kms": "16192f1be62d1946887ff98db55f01cb778a92d4a8933fe0d801d778cae68af9"
      },
      "source_qualname": "kinesis_kms"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Kinesis stream does not declare KMS encryption."
  },
  "aws.cb.kinesis.retention_at_least_168h": {
    "description_base_sha256": "38294b234a5ae774fd019ce8cd058d6b7ef0d03c5c889410d4ac9b3b5231a561",
    "description_fields": {
      "description": "Compares Kinesis stream retention with a minimum of 168 hours."
    },
    "remediation_base_sha256": "699c2cbd3aaf18f64fe48a4065502e0aa35c1779795e7d858bbc634f3eed10fe",
    "remediation_fields": {
      "caveats": [
        "Retention configuration does not prove consumers can successfully replay retained data."
      ],
      "steps": [
        "Increase retention to at least 168 hours if the workload needs that recovery window."
      ],
      "summary": "Increase retention to at least 168 hours if the workload needs that recovery window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kinesis_stream",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.kinesis_min": "4f21ac76e013e53eec70d5381270e7d6b3680ec2db75daf136d747aa1d87e928"
      },
      "source_qualname": "kinesis_min"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Kinesis stream retention is below 168 hours."
  },
  "aws.cb.kinesis.retention_exactly_168h": {
    "description_base_sha256": "eaced88cf9f05efb147c6a2a846b2541199990c074a1df7597276ca2c29a6ea7",
    "description_fields": {
      "description": "Compares Kinesis stream retention with exactly 168 hours."
    },
    "remediation_base_sha256": "983f7f3660b856efd3af4f6f02b0926ae9022f2b628212bb10f56bd30e1adc8e",
    "remediation_fields": {
      "caveats": [
        "Longer retention also fails this equality profile and is not a shorter recovery window."
      ],
      "steps": [
        "Choose retention for recovery and cost needs; use exactly 168 hours only if this profile is required."
      ],
      "summary": "Choose retention for recovery and cost needs; use exactly 168 hours only if this profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kinesis_stream",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.kinesis_eq": "0d0279a000152a871a2bc1dc38e6a20255680a416bf7dfedf99aca96be8a17a2"
      },
      "source_qualname": "kinesis_eq"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Kinesis retention differs from this profile\u2019s exact 168-hour preference."
  },
  "aws.cb.mediastore.container_policy_not_public": {
    "description_base_sha256": "53e9dcecf072990bf6b045f6ef43c0c564cfc6ba1fbb6795c48cc7830b64769c",
    "description_fields": {
      "description": "For historical pre-shutdown snapshots, checks MediaStore policy wildcard grants using recognized restrictive conditions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "MediaStore shutdown makes current observations not applicable; historical policy models are not live access tests."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "media_store_container.Policy.Policy",
          "snapshot observation clock",
          "MediaStore retirement date"
        ],
        "kind": "media_store_container",
        "target": "resource"
      },
      "references": [
        {
          "title": "Official AWS service documentation",
          "url": "https://docs.aws.amazon.com/mediastore/latest/ug/what-is.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "For historical findings, review unnecessary public grants; migrate any remaining service dependencies."
      ],
      "summary": "For historical findings, review unnecessary public grants; migrate any remaining service dependencies."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "RETIRED_SERVICES": {
          "mediastore": {
            "access_url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediastore-container.html",
            "applies_to_service_kinds": [
              "media_store_container"
            ],
            "end_of_support": {
              "datetime": "2025-11-12"
            },
            "name": "AWS Elemental MediaStore",
            "no_access_after": {
              "datetime": "2025-11-13"
            },
            "primary_url": "https://docs.aws.amazon.com/general/latest/gr/full_shutdown_services.html"
          }
        }
      },
      "kind": "media_store_container",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.clock": "ab5a2682bc5a3cea8b9401c0db21419e8e73541184499f65f169c4bdce2acf2e",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131",
        "peaso.checks.claude_aws_b_storage.mediastore": "ea130a8be7a620a0cd2c29a908d006c1a5cfcb6bf783a781f5f4c66f3e008a58"
      },
      "source_qualname": "mediastore"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The historical MediaStore policy matches the public-grant model."
  },
  "aws.cb.mq.activemq_active_standby": {
    "description_base_sha256": "2fd27a7fbf73bf0b4bf9ed9bae3140659a990a825cb71e53a542e9f78f31137f",
    "description_fields": {
      "description": "Checks the ActiveMQ broker deployment mode for ACTIVE_STANDBY_MULTI_AZ."
    },
    "remediation_base_sha256": "a5ec102f4322dc31afd1165e859e09cb87bbc2226a7904a1add8981442f6091b",
    "remediation_fields": {
      "caveats": [
        "Changing deployment type can require a replacement broker and client migration."
      ],
      "steps": [
        "Plan a ACTIVE_STANDBY_MULTI_AZ broker if Multi-AZ availability is required."
      ],
      "summary": "Plan a ACTIVE_STANDBY_MULTI_AZ broker if Multi-AZ availability is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "mq_broker",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._engine": "9220e5d2f4e4f9103eb5a959cf9149de1f19c44733439fb23a4bbddf1720528c",
        "peaso.checks.claude_aws_b_messaging.mq_active": "306cedefd9f5e8f02c1cb3c885cc5a0e8b276bb54a208ab3fcd664729ff24d1a"
      },
      "source_qualname": "mq_active"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The ActiveMQ broker does not declare ACTIVE_STANDBY_MULTI_AZ."
  },
  "aws.cb.mq.activemq_audit_logs": {
    "description_base_sha256": "7dcf4dac2dd9138abc5607de15a55ae8f651a5173737cc7232166d18fc0030e9",
    "description_fields": {
      "description": "Reads the ActiveMQ broker audit-log flag; RabbitMQ is outside scope."
    },
    "remediation_base_sha256": "6309e75ec4eab03ecff0cad3f5b509d92b3817f78c7f06acf538177ab8009af3",
    "remediation_fields": {
      "caveats": [
        "The flag does not prove log delivery; RabbitMQ does not support this audit-log setting."
      ],
      "steps": [
        "Enable audit-log publishing if administrative activity must be recorded."
      ],
      "summary": "Enable audit-log publishing if administrative activity must be recorded."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "mq_broker",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._engine": "9220e5d2f4e4f9103eb5a959cf9149de1f19c44733439fb23a4bbddf1720528c",
        "peaso.checks.claude_aws_b_messaging.mq_audit": "4debf178217cadc07ab9afadf63cb7575882103a9a64334a30dbe099680e9b42"
      },
      "source_qualname": "mq_audit"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ActiveMQ broker disables audit-log publishing."
  },
  "aws.cb.mq.engine_logging": {
    "description_base_sha256": "a3663993eec74cc9d74a851e001817c2e5923ae5166609f1bbdac29e40d8d12d",
    "description_fields": {
      "description": "Checks general and audit logs for ActiveMQ, or general logs for RabbitMQ."
    },
    "remediation_base_sha256": "02ebafcef5c812a518fb15d109d751a85b2fd112791e51b19c7ee44120b71ff7",
    "remediation_fields": {
      "caveats": [
        "Configured streams do not prove delivery; unrecognized engines fail this literal profile."
      ],
      "steps": [
        "Enable the engine-supported log streams needed for audit and investigation."
      ],
      "summary": "Enable the engine-supported log streams needed for audit and investigation."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "mq_broker",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging._engine": "9220e5d2f4e4f9103eb5a959cf9149de1f19c44733439fb23a4bbddf1720528c",
        "peaso.checks.claude_aws_b_messaging.mq_logging": "6ebbc5883f758669e236933a56ad17b0147c1533a061a9d2fef1b9e7d735750b"
      },
      "source_qualname": "mq_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The broker lacks one of the log settings required for its engine."
  },
  "aws.cb.mq.rabbitmq_cluster_deployment": {
    "description_base_sha256": "9c89726708246a44d0328071db9c1e65a73dfef14fee30019c380545bfe0bf63",
    "description_fields": {
      "description": "Checks the RabbitMQ broker deployment mode for CLUSTER_MULTI_AZ."
    },
    "remediation_base_sha256": "6681d6a88b68170fb68ed49f705ac229455709aba567550ee693f79c90651dac",
    "remediation_fields": {
      "caveats": [
        "Changing deployment type can require a replacement broker and client migration."
      ],
      "steps": [
        "Plan a CLUSTER_MULTI_AZ broker if Multi-AZ availability is required."
      ],
      "summary": "Plan a CLUSTER_MULTI_AZ broker if Multi-AZ availability is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "mq_broker",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._engine": "9220e5d2f4e4f9103eb5a959cf9149de1f19c44733439fb23a4bbddf1720528c",
        "peaso.checks.claude_aws_b_messaging.mq_cluster": "989df0b5ff7d078e74da99506ef2b7c96bc5b9a9a16c44a55e1bef1483b09e98"
      },
      "source_qualname": "mq_cluster"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The RabbitMQ broker does not declare CLUSTER_MULTI_AZ."
  },
  "aws.cb.msk.client_broker_tls": {
    "description_base_sha256": "d41c411545a7012822ea0c0a35c44e5b8a69875bcf40e2865c757ed47a6952cb",
    "description_fields": {
      "description": "Checks provisioned MSK ClientBroker encryption equals TLS; Serverless is outside scope."
    },
    "remediation_base_sha256": "dd2e51b0d37f85431c9ad4998642d29b3001f4cbaaa04231cde9dc90e95c23a2",
    "remediation_fields": {
      "caveats": [
        "This setting does not assess in-cluster traffic or authentication."
      ],
      "steps": [
        "Require TLS-only client connections if plaintext is unnecessary."
      ],
      "summary": "Require TLS-only client connections if plaintext is unnecessary."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "msk_tls"
        },
        "serverless": "NOT_APPLICABLE"
      },
      "constants": {},
      "kind": "msk_cluster",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._cluster_type": "70d75738fe124dec8f45cc5ad40c0ad82073900b203c4c7453ad3fc2c766c5c7",
        "peaso.checks.claude_aws_b_messaging.msk_check.<locals>.decorate.<locals>.evaluate": "4fef7da65eb22e93bf88b987c7a0c5535355479eb4756ce933467c00c9f3bae0",
        "peaso.checks.claude_aws_b_messaging.msk_tls": "17a1db7015dc0355693bc255adcdfb522892df2baeaed869d48f6b29ae9f0a16"
      },
      "source_qualname": "msk_check.<locals>.decorate.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The provisioned MSK client-broker setting is not TLS-only."
  },
  "aws.cb.mskconnect.log_delivery": {
    "description_base_sha256": "8a6f98bb6998f7b4a17cc8818c4e9766968f566557c8af051934dc27c4bfd9b4",
    "description_fields": {
      "description": "Checks whether the MSK Connect connector declares a logDelivery object."
    },
    "remediation_base_sha256": "1c8b938d4c6d9537f9ab964f7577a9bda9a6737a8adc998505b63bb7137b4f78",
    "remediation_fields": {
      "caveats": [
        "Object presence alone does not validate enabled destinations or delivery."
      ],
      "steps": [
        "Configure worker log delivery if connector operations need auditing."
      ],
      "summary": "Configure worker log delivery if connector operations need auditing."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "mskconnect_connector",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.mskc_logs": "2684fa7004f4697040174a73f13ab4adfff166ec0425c9accdce1bf4ee87b1a5"
      },
      "source_qualname": "mskc_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The MSK Connect connector has no log-delivery configuration."
  },
  "aws.cb.sagemaker.clarify_job_exists": {
    "description_base_sha256": "4a755fedd7bff0cbc9b9f21ba1863d8e9887aaf2495f6c06c866c7d64bf87cdf",
    "description_fields": {
      "description": "Looks for a processing-job image URI containing sagemaker-clarify-processing in regions containing models."
    },
    "remediation_base_sha256": "d2f733ed15a8995ff440feec3a2a9a48967bbbfb9347334b8a71a8d23f3ba7b7",
    "remediation_fields": {
      "caveats": [
        "This region-wide witness is not joined to each model and does not prove successful coverage or analysis quality."
      ],
      "steps": [
        "Run appropriate bias and explainability analysis if these models require it."
      ],
      "summary": "Run appropriate bias and explainability analysis if these models require it."
    },
    "reviewed_binding": {
      "closure": {
        "evaluate_rows": {
          "callable": "_clarify"
        },
        "kind": "sagemaker_processing_job"
      },
      "constants": {},
      "kind": "sagemaker_processing_job",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998",
        "peaso.checks.claude_aws_b_compute._clarify": "d756895f56cc85395b59a2ebb18bd4cd1cb2123f98e94243d4f1ad850df7f81f",
        "peaso.checks.claude_aws_b_compute._region_models": "9fda65e6c6cce87baa6563789de770f0a2eef63350fd56d704404701f6ee9b08",
        "peaso.checks.claude_aws_b_compute._regional.<locals>.evaluate": "0aa4038804f96665e054affc09c3dff104b9f80a4ea183d4923620321b161a50"
      },
      "source_qualname": "_regional.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The region has models but no processing job matching the Clarify image marker."
  },
  "aws.cb.sagemaker.domain_sso": {
    "description_base_sha256": "79c67e65518304e60072a14ff492c10ca656979d48aa4c0bd8e25a1bea85c8be",
    "description_fields": {
      "description": "Checks domain AuthMode=SSO together with a nonempty linked SSO application reference."
    },
    "remediation_base_sha256": "b5bff179f3eca71825081f5aa9d9d19b6ab8e69a2258868c8b6f12cf3bb7847d",
    "remediation_fields": {
      "caveats": [
        "IAM authentication can be legitimate; a link does not prove MFA or effective user access."
      ],
      "steps": [
        "Use IAM Identity Center if this domain\u2019s authentication profile requires it."
      ],
      "summary": "Use IAM Identity Center if this domain\u2019s authentication profile requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_domain",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.dom_sso": "cf8e6fc1b27db840b29c85dabaa27815d8477b86fda2daf3ba564a065c521f51"
      },
      "source_qualname": "dom_sso"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker domain lacks this profile\u2019s linked SSO configuration."
  },
  "aws.cb.sagemaker.endpoint_config_kms": {
    "description_base_sha256": "d2fe9c201d604c5937e2502940e70630c5ac00d30d132beaa0fc6d46957c08da",
    "description_fields": {
      "description": "Checks the endpoint configuration for a nonempty KmsKeyId."
    },
    "remediation_base_sha256": "a042e9f0508b10b1eaa35a1acd0df2d0190826b58b9aaefc4827a198de1d5d6a",
    "remediation_fields": {
      "caveats": [
        "A missing customer-selected key is not proof of plaintext; review instance-specific service encryption defaults."
      ],
      "steps": [
        "Configure a suitable key for endpoint storage if explicit KMS key control is required."
      ],
      "summary": "Configure a suitable key for endpoint storage if explicit KMS key control is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_endpoint_config",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.epc_kms": "22313287a94a8f84c37c08599a18bd9d3a22216b2ef4dc676a50bfac2932d4bf"
      },
      "source_qualname": "epc_kms"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The endpoint configuration declares no KMS key identifier."
  },
  "aws.cb.sagemaker.endpoint_variants_more_than_one": {
    "description_base_sha256": "2bb4ed65d760e5888538fe93cd2e41219d72b9c737fe34f52715d23776ae9d13",
    "description_fields": {
      "description": "Finds production variants with integer InitialInstanceCount at most one; missing counts are not counted."
    },
    "remediation_base_sha256": "8a9c785b26f657f8695d16358db7ed46be2425fce79ee2789087f8a97090afa5",
    "remediation_fields": {
      "caveats": [
        "Initial count does not prove current capacity or failover; Serverless variants can omit counts."
      ],
      "steps": [
        "Use redundant provisioned instances if availability requirements justify them."
      ],
      "summary": "Use redundant provisioned instances if availability requirements justify them."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_endpoint_config",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_compute.epc_variants_p": "0f04ee6f9ac5eb60f0cd2be87198501b6722592a8343b0b5d0b4ea28a02c9c8d"
      },
      "source_qualname": "epc_variants_p"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A production variant declares at most one initial instance."
  },
  "aws.cb.sagemaker.endpoint_variants_not_exactly_one": {
    "description_base_sha256": "48ac1dc41d2e514c00a1368daeb8c609183586b2af94fec59ac0ed0de541f035",
    "description_fields": {
      "description": "Finds production variants whose integer InitialInstanceCount is exactly one."
    },
    "remediation_base_sha256": "838c376d9da9dbfa9818d4b98b8a12bf5060240fc09a198444fcbdb387d6ce5f",
    "remediation_fields": {
      "caveats": [
        "This equality profile does not reject zero or missing counts and does not prove current capacity."
      ],
      "steps": [
        "Use redundant provisioned instances if availability requirements justify them."
      ],
      "summary": "Use redundant provisioned instances if availability requirements justify them."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_endpoint_config",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_compute.epc_variants_c": "3fd2a81f20a6cc41b774d45f1fcbe5a996adef252d0cd71a526ce4a4ee0b7ec9"
      },
      "source_qualname": "epc_variants_c"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A production variant declares exactly one initial instance."
  },
  "aws.cb.sagemaker.model_registry_approved_package": {
    "description_base_sha256": "c3565a8c07de60ba567ea8d95740db687e032c94163be7aafe67cbfa19a924af",
    "description_fields": {
      "description": "Looks for a model package group with ApprovedPackages greater than zero in regions containing models."
    },
    "remediation_base_sha256": "70c43e56966ba7a7993369f992f3b2eefdcbb291df0a9c23a05b81eba80e49d8",
    "remediation_fields": {
      "caveats": [
        "This region-wide witness is not joined to each model and does not prove successful coverage or analysis quality."
      ],
      "steps": [
        "Use an approved model registry workflow if required for these models."
      ],
      "summary": "Use an approved model registry workflow if required for these models."
    },
    "reviewed_binding": {
      "closure": {
        "evaluate_rows": {
          "callable": "_registry"
        },
        "kind": "sagemaker_model_package_group"
      },
      "constants": {},
      "kind": "sagemaker_model_package_group",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998",
        "peaso.checks.claude_aws_b_compute._region_models": "9fda65e6c6cce87baa6563789de770f0a2eef63350fd56d704404701f6ee9b08",
        "peaso.checks.claude_aws_b_compute._regional.<locals>.evaluate": "0aa4038804f96665e054affc09c3dff104b9f80a4ea183d4923620321b161a50",
        "peaso.checks.claude_aws_b_compute._registry": "0ba28ac908acb47cddc402baca8e47335c344e4a1c71e40ed61f6776fa337f9d"
      },
      "source_qualname": "_regional.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The region has models but no package group reporting approved packages."
  },
  "aws.cb.sagemaker.model_vpc_config": {
    "description_base_sha256": "df4e3ad2e3f83b72394083f260551e018aa173d51ee3f4d4d586a12a8dec07c3",
    "description_fields": {
      "description": "Checks the SageMaker model for a VPC configuration object."
    },
    "remediation_base_sha256": "c271b1fd5fe9a818e5fe988c72cce41d9870cf4763482746f4a8bff8d5cbf676",
    "remediation_fields": {
      "caveats": [
        "These metadata declarations do not establish isolation, private reachability or absence of other Internet paths."
      ],
      "steps": [
        "Configure suitable VPC networking for the model if required."
      ],
      "summary": "Configure suitable VPC networking for the model if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_model",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.model_vpc": "f1ce6e933fd7b897ae8e13a0c4858ab5135cac645877824c2b9682ce8f087aa4"
      },
      "source_qualname": "model_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker model does not declare a VPC configuration object."
  },
  "aws.cb.sagemaker.model_vpc_subnets": {
    "description_base_sha256": "8778c853d7c0cd66d42d15d6f886a56a7df2fecb5b07bbd7841ec53c4540c219",
    "description_fields": {
      "description": "Checks the SageMaker model for at least one VPC subnet."
    },
    "remediation_base_sha256": "9b8459eb8c3b4685d7404c24d7f3f99cc9f5b3edb0832f3f271c72b354d0d81c",
    "remediation_fields": {
      "caveats": [
        "These metadata declarations do not establish isolation, private reachability or absence of other Internet paths."
      ],
      "steps": [
        "Configure suitable VPC networking for the model if required."
      ],
      "summary": "Configure suitable VPC networking for the model if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_model",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2",
        "peaso.checks.claude_aws_b_compute.model_subnets": "60b048e79c62c50139c0942cbca9c4d283943aba4153b3c4909a3ed4ad24b6de"
      },
      "source_qualname": "model_subnets"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker model does not declare at least one VPC subnet."
  },
  "aws.cb.sagemaker.monitoring_schedule_active": {
    "description_base_sha256": "1c9a8595f56a2a8bf9d19ae4de75481c42ba7d80821f064c754173ee16019e1b",
    "description_fields": {
      "description": "Looks for any Scheduled monitoring schedule in regions containing SageMaker models."
    },
    "remediation_base_sha256": "43cb92a16524e67221d57de214c89aa2142adad72bc93679ceb22a4252274a73",
    "remediation_fields": {
      "caveats": [
        "This region-wide witness is not joined to each model and does not prove successful coverage or analysis quality."
      ],
      "steps": [
        "Configure suitable model monitoring if the deployed models need it."
      ],
      "summary": "Configure suitable model monitoring if the deployed models need it."
    },
    "reviewed_binding": {
      "closure": {
        "evaluate_rows": {
          "callable": "_monitor"
        },
        "kind": "sagemaker_monitoring_schedule"
      },
      "constants": {},
      "kind": "sagemaker_monitoring_schedule",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.scope_of": "1c77a1c03eada080bc374b04f68f98242c834af2a08ccf1ddb78e1f10a200998",
        "peaso.checks.claude_aws_b_compute._monitor": "c97e8bb19b23e06595ad21d97bfaf53ac89d5cea6434619f6eab8a09c0ad9321",
        "peaso.checks.claude_aws_b_compute._region_models": "9fda65e6c6cce87baa6563789de770f0a2eef63350fd56d704404701f6ee9b08",
        "peaso.checks.claude_aws_b_compute._regional.<locals>.evaluate": "0aa4038804f96665e054affc09c3dff104b9f80a4ea183d4923620321b161a50"
      },
      "source_qualname": "_regional.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The region has models but no monitoring schedule with status Scheduled."
  },
  "aws.cb.sagemaker.notebook_cmk": {
    "description_base_sha256": "67082cb0a63af9aca492760ccf75a565ad0fecb3d98bb64346dbb531f2ac6902",
    "description_fields": {
      "description": "Joins the notebook key reference to KMS metadata and requires KeyManager=CUSTOMER."
    },
    "remediation_base_sha256": "a6123bfd74d19432eb57c5dfca7e54bb7a6dbd22966d4aba3f51c3e61be5f46d",
    "remediation_fields": {
      "caveats": [
        "AWS-managed or service-owned encryption can still protect storage; key ownership does not prove usability."
      ],
      "steps": [
        "Use a customer-managed key if this key-control profile is required; plan migration where necessary."
      ],
      "summary": "Use a customer-managed key if this key-control profile is required; plan migration where necessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_notebook_instance",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.kms_manager": "8c6889a17131e413b37d1e6cee61cb9dd21463b690219228c6989e33d94c3f75",
        "peaso.checks.claude_aws_b_compute.nb_cmk": "085e7927692251c1e8c2b3c8ee21e328190f1d1641612718f1864002d00494af"
      },
      "source_qualname": "nb_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The notebook lacks a resolved customer-managed key."
  },
  "aws.cb.sagemaker.notebook_in_vpc": {
    "description_base_sha256": "3f548700cc7387a162ac1baefa10c35caa12b5b81fa0a67452bed17d1e6a3e4e",
    "description_fields": {
      "description": "Checks the SageMaker notebook for a subnet identifier."
    },
    "remediation_base_sha256": "6315c1d79c69f3b2fa74997b4c15a853bd2240467321c660e95aa7d2db150de2",
    "remediation_fields": {
      "caveats": [
        "These metadata declarations do not establish isolation, private reachability or absence of other Internet paths."
      ],
      "steps": [
        "Configure suitable VPC networking for the notebook if required."
      ],
      "summary": "Configure suitable VPC networking for the notebook if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_notebook_instance",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.nb_vpc": "25ad42dc58b3de71313443570e87bd3ad838c6ff5dabc5bfb8410bc0d383fe5f"
      },
      "source_qualname": "nb_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker notebook does not declare a subnet identifier."
  },
  "aws.cb.sagemaker.notebook_kms_key": {
    "description_base_sha256": "5ab286e7a461632edb3f56e669800ad26457ed8c7a416d5fefdbc8759531d0e0",
    "description_fields": {
      "description": "Checks the notebook instance for a nonempty KmsKeyId."
    },
    "remediation_base_sha256": "1637570cf3579b3688a6e50418f6faf6b64b18c42d301d80a57c5da4f7ba955b",
    "remediation_fields": {
      "caveats": [
        "A missing customer-selected key is not proof of plaintext; review instance-specific service encryption defaults."
      ],
      "steps": [
        "Configure a suitable key for notebook volume if explicit KMS key control is required."
      ],
      "summary": "Configure a suitable key for notebook volume if explicit KMS key control is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_notebook_instance",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.nb_kms": "7dcd7e40a08e5ffc3aa5670d853a0271ce3c1cf00d2398319eeba6ecd262f26b"
      },
      "source_qualname": "nb_kms"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The notebook declares no KMS key identifier."
  },
  "aws.cb.sagemaker.notebook_supported_platform": {
    "description_base_sha256": "ecda727eb4509627261cb5b7afd64557fb2a64101f3aab57c6341b4387d53cec",
    "description_fields": {
      "description": "Compares the notebook platform and snapshot date with reviewed AWS launch and retirement dates."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    "remediation_fields": {
      "caveats": [
        "Unlisted platforms or support claims beyond the reviewed lifecycle window remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "sagemaker_notebook_instance.PlatformIdentifier",
          "_provenance.collected_at",
          "context.created_at"
        ],
        "kind": "sagemaker_notebook_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Official AWS service documentation",
          "url": "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-al2023.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Migrate a retired notebook platform after validating instance types, lifecycle scripts, kernels and workload compatibility."
      ],
      "summary": "Migrate a retired notebook platform after validating instance types, lifecycle scripts, kernels and workload compatibility."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_notebook_instance",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.clock": "ab5a2682bc5a3cea8b9401c0db21419e8e73541184499f65f169c4bdce2acf2e",
        "peaso.checks.claude_aws_b_compute.nb_platform": "99d4755bf8cb0b877afd04f521d10c4444f51ec00d440dfff8bb6bc6614ba454"
      },
      "source_qualname": "nb_platform"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The notebook platform has passed its reviewed end-of-support date."
  },
  "aws.cb.sagemaker.training_output_kms": {
    "description_base_sha256": "4a0c9e45a924160497461e4d7fc8ed9bf8f52a2dc0fdf43069cd68ca06942a98",
    "description_fields": {
      "description": "Checks OutputDataConfig for a nonempty KmsKeyId."
    },
    "remediation_base_sha256": "45b64000f2e104a6594eefe1d915953dfec11af75a5b2485e993dada84670bc4",
    "remediation_fields": {
      "caveats": [
        "A missing customer-selected key is not proof of plaintext; review instance-specific service encryption defaults."
      ],
      "steps": [
        "Configure a suitable key for training output if explicit KMS key control is required."
      ],
      "summary": "Configure a suitable key for training output if explicit KMS key control is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_training_job",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.tj_output": "78378868c24e00de9900565314f2b7bb4415b190523bba747911893847f6d2fb"
      },
      "source_qualname": "tj_output"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Training output declares no KMS key identifier."
  },
  "aws.cb.sagemaker.training_volume_kms": {
    "description_base_sha256": "ab9db94f0ad4596e502447a76a00d851cede677fe2ec7669d41d1f8a86bfee9a",
    "description_fields": {
      "description": "Checks ResourceConfig for a nonempty VolumeKmsKeyId."
    },
    "remediation_base_sha256": "3f7e8fe28412879cc8fc6d6762c065e604503d64ec172e49b8a78b0a86d1afad",
    "remediation_fields": {
      "caveats": [
        "A missing customer-selected key is not proof of plaintext; review instance-specific service encryption defaults."
      ],
      "steps": [
        "Configure a suitable key for training volume if explicit KMS key control is required."
      ],
      "summary": "Configure a suitable key for training volume if explicit KMS key control is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_training_job",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.tj_volume": "4adf62abbb0d9fdd1aadfd9c0fd458a04add404cd4245a4bd9b24aa998f90570"
      },
      "source_qualname": "tj_volume"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The training volume declares no KMS key identifier."
  },
  "aws.cb.sagemaker.training_vpc_config": {
    "description_base_sha256": "a2f7f0936ec53e7d83aff27b2b495bf09b4479f0395b0b55d7f0e5116878b74e",
    "description_fields": {
      "description": "Checks the SageMaker training job for a VPC configuration object."
    },
    "remediation_base_sha256": "77dcf150aea7b80554df570a8e0c693c602001c10b2180f3ba178433c760a31b",
    "remediation_fields": {
      "caveats": [
        "These metadata declarations do not establish isolation, private reachability or absence of other Internet paths."
      ],
      "steps": [
        "Configure suitable VPC networking for the training job if required."
      ],
      "summary": "Configure suitable VPC networking for the training job if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_training_job",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_compute.tj_vpc": "ef0f95c44191501852064823b8297fe936dc357f745234032f68420a45864f37"
      },
      "source_qualname": "tj_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker training job does not declare a VPC configuration object."
  },
  "aws.cb.sagemaker.training_vpc_subnets": {
    "description_base_sha256": "91babf0d74aebee7628f920b09aa7ba1cb715e1accd6a76dbbe5c0afd73f2280",
    "description_fields": {
      "description": "Checks the SageMaker training job for at least one VPC subnet."
    },
    "remediation_base_sha256": "d5bc5af6688709444b0607e39e53045616a31d37ba31f0f41f54eeccd341ef2c",
    "remediation_fields": {
      "caveats": [
        "These metadata declarations do not establish isolation, private reachability or absence of other Internet paths."
      ],
      "steps": [
        "Configure suitable VPC networking for the training job if required."
      ],
      "summary": "Configure suitable VPC networking for the training job if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sagemaker_training_job",
      "module": "peaso.checks.claude_aws_b_compute",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2",
        "peaso.checks.claude_aws_b_compute.tj_subnets": "f7344460caad7b68fb073d978b28930a70d0383f3949b37ac25703ae220fbc52"
      },
      "source_qualname": "tj_subnets"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SageMaker training job does not declare at least one VPC subnet."
  },
  "aws.cb.ses.dkim_signing": {
    "description_base_sha256": "9c3c5c241f1c0c030bdc132e282518286ad5a07b6ba365331d755296c753e7b4",
    "description_fields": {
      "description": "Checks that SES DKIM status is SUCCESS and signing is enabled."
    },
    "remediation_base_sha256": "42f535bd4af37d1102ea831e4ea97bf49b61bb934a3dc3293a73069c74f5003b",
    "remediation_fields": {
      "caveats": [
        "These identity settings do not prove every outgoing message is signed or passes recipient checks."
      ],
      "steps": [
        "Complete DKIM verification and enable signing for identities that send mail."
      ],
      "summary": "Complete DKIM verification and enable signing for identities that send mail."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ses_email_identity",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging.ses_dkim": "eb7cfc25981db2a068a065d7ea3d490bac9b6e837322d52b134051253effec94"
      },
      "source_qualname": "ses_dkim"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "SES DKIM verification is not successful or signing is disabled."
  },
  "aws.cb.ses.identity_policies_not_public": {
    "description_base_sha256": "ef3beda2e6abab6de9aa94d60952a8c352347d2fe8425610af1df18f546f5392",
    "description_fields": {
      "description": "Checks SES sending-authorization policies for modeled public grants; public Allow with any explicit Deny requires review."
    },
    "remediation_base_sha256": "9a37264c2bc701efbd072b159f5d5e457915b7ae4babde92f5c0b6cb507bfb1c",
    "remediation_fields": {
      "caveats": [
        "This model does not prove effective authorization when explicit denies or external policies intervene."
      ],
      "steps": [
        "Restrict unnecessary sending grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary sending grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ses_email_identity",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_messaging.ses_public": "b3d82c77d43b3b7a28b93032efca1099faf55577a3aceaa71d56f6b8f10ec19c"
      },
      "source_qualname": "ses_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SES identity has a policy matching the public-grant model."
  },
  "aws.cb.sfn.logging_not_off": {
    "description_base_sha256": "66613d4fa06492e8ab9031986b17866c7816346d3f989b030bd4f5885264e0e7",
    "description_fields": {
      "description": "Flags Step Functions logging only when its declared level is exactly OFF."
    },
    "remediation_base_sha256": "cbbf5a8f23ff0db26be823bf452ea1a62895a7fbcb6977b682a5dc579e6e90f3",
    "remediation_fields": {
      "caveats": [
        "Missing configuration passes this literal profile; PASS is not proof that logging exists."
      ],
      "steps": [
        "Enable a suitable logging level if execution logs are required."
      ],
      "summary": "Enable a suitable logging level if execution logs are required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sfn_state_machine",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.sfn_logging_c": "70ea91b141cbeafd870df0e59dfca6e15697edbdc83b2336d27d863daab82212"
      },
      "source_qualname": "sfn_logging_c"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Step Functions logging level is OFF."
  },
  "aws.cb.sns.failure_feedback_role": {
    "description_base_sha256": "35b35c48249b24982950ab82bd8737d647fc5720db6083b4e6056deb3aa07d70",
    "description_fields": {
      "description": "Checks whether any supported SNS failure-feedback role attribute is nonempty."
    },
    "remediation_base_sha256": "b1bdd1dff787575838fdaa1d1d2be391c73f6bee0c4ef35e5dc6cd4ed345aa84",
    "remediation_fields": {
      "caveats": [
        "One role reference does not prove every protocol is covered or that logs arrive."
      ],
      "steps": [
        "Configure delivery-status logging for the subscription protocols that need monitoring."
      ],
      "summary": "Configure delivery-status logging for the subscription protocols that need monitoring."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_FEEDBACK": [
          "ApplicationFailureFeedbackRoleArn",
          "FirehoseFailureFeedbackRoleArn",
          "HTTPFailureFeedbackRoleArn",
          "LambdaFailureFeedbackRoleArn",
          "SQSFailureFeedbackRoleArn"
        ]
      },
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._attrs": "417fba7a1b13c230ee5f44d6725a4428e173fcc93e4d0effa4e8db8477c87ee5",
        "peaso.checks.claude_aws_b_messaging.sns_feedback": "c2695a212b5815ea6d87d0fdf63bac9def026a1d4190a96ccdfbb7cde03c41b8"
      },
      "source_qualname": "sns_feedback"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SNS topic declares no failure-feedback logging role."
  },
  "aws.cb.sns.policy_no_public_publish": {
    "description_base_sha256": "1d23522c83e18158d33af31b341cc5a5ee94f75a374db43cbabeb7fd0ba05511",
    "description_fields": {
      "description": "Finds unconditioned wildcard-principal Allow statements with explicit sns:Publish actions."
    },
    "remediation_base_sha256": "30988abe1a50c99e638fc377d1b3eda3f03f514c052a8b2578f2bde123573fb0",
    "remediation_fields": {
      "caveats": [
        "This literal action-list profile does not match wildcard action spellings such as sns:*."
      ],
      "steps": [
        "Restrict the affected grant to the principals that need it."
      ],
      "summary": "Restrict the affected grant to the principals that need it."
    },
    "reviewed_binding": {
      "closure": {
        "actions": [
          "sns:publish"
        ]
      },
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._sns_action.<locals>.evaluate": "9375ee774ef78294eb548c3eba4ee998c27ef2b0ab4c525cea68437145ba0126",
        "peaso.checks.claude_aws_b_messaging._topic_policy": "d5f9ae34e6fc62c99ae418ab263c93083539c5ac692052b56d71193e037023c8",
        "peaso.checks.claude_aws_b_messaging._unconditioned_actions": "44e0a7a2e5e8bd74f2e4f1522aa2286d7f979f023a035e2d1a7d3376c78fb69f"
      },
      "source_qualname": "_sns_action.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SNS topic policy declares an unconditioned public sns:Publish grant."
  },
  "aws.cb.sns.policy_no_public_subscribe": {
    "description_base_sha256": "2a4e2a47dc9d374b74a8117a2ca1361d943364a8abda34be1dbc342bf5930dcf",
    "description_fields": {
      "description": "Finds unconditioned wildcard-principal Allow statements with explicit sns:Subscribe or sns:Receive actions."
    },
    "remediation_base_sha256": "16d4551c26a368f7b41a8f94082ddcc34087edbbe35c9e5f25e065905aec52b3",
    "remediation_fields": {
      "caveats": [
        "This literal action-list profile does not match wildcard action spellings such as sns:*."
      ],
      "steps": [
        "Restrict the affected grant to the principals that need it."
      ],
      "summary": "Restrict the affected grant to the principals that need it."
    },
    "reviewed_binding": {
      "closure": {
        "actions": [
          "sns:subscribe",
          "sns:receive"
        ]
      },
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging._sns_action.<locals>.evaluate": "9375ee774ef78294eb548c3eba4ee998c27ef2b0ab4c525cea68437145ba0126",
        "peaso.checks.claude_aws_b_messaging._topic_policy": "d5f9ae34e6fc62c99ae418ab263c93083539c5ac692052b56d71193e037023c8",
        "peaso.checks.claude_aws_b_messaging._unconditioned_actions": "44e0a7a2e5e8bd74f2e4f1522aa2286d7f979f023a035e2d1a7d3376c78fb69f"
      },
      "source_qualname": "_sns_action.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SNS topic policy declares an unconditioned public sns:Subscribe or sns:Receive grant."
  },
  "aws.cb.sns.policy_no_unrestricted_wildcard": {
    "description_base_sha256": "ebb023ab2383c4c3158d679ef0f53e464e74ffb5381368ca56dac151b4db6554",
    "description_fields": {
      "description": "Examines SNS topic policy wildcard-principal Allow statements using supported account, organization and source conditions."
    },
    "remediation_base_sha256": "a24685eb30673176a097151813c18530acaaa927ddf40c327d00ad2f1477aeb6",
    "remediation_fields": {
      "caveats": [
        "This policy model does not compute effective access across explicit denies or external policies."
      ],
      "steps": [
        "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
      ],
      "summary": "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131",
        "peaso.checks.claude_aws_b_messaging._topic_policy": "d5f9ae34e6fc62c99ae418ab263c93083539c5ac692052b56d71193e037023c8",
        "peaso.checks.claude_aws_b_messaging.sns_public_c": "06b8b1e1a6b8cc20502823db93f2344301b58b486b43b9d962ae75b080aee800"
      },
      "source_qualname": "sns_public_c"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SNS topic policy matches this source\u2019s public-grant criteria."
  },
  "aws.cb.sns.policy_prohibit_public_access_perimeter": {
    "description_base_sha256": "ef881fc7c63517e705160eb041ad9cb2ef84d5236412797950c1ef33deffb68f",
    "description_fields": {
      "description": "Examines SNS topic policy wildcard-principal Allow statements using supported account, organization and source conditions."
    },
    "remediation_base_sha256": "07955dffd3cfc2e1ce4bf757da1a5d098ba2a8ac70bb0635ae53de52b9b11f4b",
    "remediation_fields": {
      "caveats": [
        "This policy model does not compute effective access across explicit denies or external policies."
      ],
      "steps": [
        "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
      ],
      "summary": "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131",
        "peaso.checks.claude_aws_b_messaging._topic_policy": "d5f9ae34e6fc62c99ae418ab263c93083539c5ac692052b56d71193e037023c8",
        "peaso.checks.claude_aws_b_messaging.sns_public_x": "e2fc306ca53499aa30549d02baeb1c5f5f7b25764bb3567b2be0e4858f5ba192"
      },
      "source_qualname": "sns_public_x"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SNS topic policy matches this source\u2019s public-grant criteria."
  },
  "aws.cb.sns.subscription_not_http": {
    "description_base_sha256": "43ef566ba73e20617b8c0135557de2e28b35663ffcfddf313b1b8d2869fdb7a2",
    "description_fields": {
      "description": "Checks confirmed SNS subscriptions for the plain HTTP protocol."
    },
    "remediation_base_sha256": "42ca3b5b2c1a3fccc63dabf0ee63016e42e41b42710c5c2c4d8b0ec8e6ece7e6",
    "remediation_fields": {
      "caveats": [
        "Pending-confirmation subscriptions are outside scope; no endpoint connection is tested."
      ],
      "steps": [
        "Use HTTPS for subscriptions carrying data that needs transport protection."
      ],
      "summary": "Use HTTPS for subscriptions carrying data that needs transport protection."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sns_subscription",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging.sns_http": "185753252b84870ed69a9de3e3b9f5959f548d8774fddf92ede8ffa300601920"
      },
      "source_qualname": "sns_http"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The confirmed SNS subscription uses plain HTTP."
  },
  "aws.cb.sns.topic_not_publicly_accessible_prowler": {
    "description_base_sha256": "55339433ca07251504d5bcb87609a85fe431e8d2ae4a379f6d22d3c4b1919c17",
    "description_fields": {
      "description": "Examines SNS topic policy wildcard-principal Allow statements using the source\u2019s account, organization, source and endpoint conditions."
    },
    "remediation_base_sha256": "30da82ee0359a91d17da20bc3b2a741bfab7baccfd25e146ce293f7ef9078d8c",
    "remediation_fields": {
      "caveats": [
        "This policy model does not compute effective access across explicit denies or external policies."
      ],
      "steps": [
        "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
      ],
      "summary": "Restrict unnecessary wildcard grants to intended principals and appropriate conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.account": "e81980f4cab1bc0e206f42709aa2bc53c5ac0c54268c8cc9c11f58853bbc7bb0",
        "peaso.checks.claude_aws_b_messaging._topic_policy": "d5f9ae34e6fc62c99ae418ab263c93083539c5ac692052b56d71193e037023c8",
        "peaso.checks.claude_aws_b_messaging.prowler_sns_public": "e3282ceba8103fe9472c40bf8793f2eb7e4f581c1030a0367acc6b890bf36177",
        "peaso.checks.claude_aws_b_messaging.sns_public_p": "b5782e789f736d4ca24d99937c83a7ef8e9d9f4c109df57563d5a8190be6792a"
      },
      "source_qualname": "sns_public_p"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SNS topic policy matches this source\u2019s public-grant criteria."
  },
  "aws.cb.sqs.cmk_encryption": {
    "description_base_sha256": "18d3905e5fc11c5ff350aee6d024770b65e6835a77009db3d36738eb5bbda909",
    "description_fields": {
      "description": "Checks that KmsMasterKeyId is nonempty and is not alias/aws/sqs."
    },
    "remediation_base_sha256": "fd8941fe3f12d4cf927b5c1cf6d621e5806761b47654d6096a89fae235284542",
    "remediation_fields": {
      "caveats": [
        "SQS-managed encryption can still protect messages; this literal alias check does not verify key ownership."
      ],
      "steps": [
        "Select a customer-managed key if this encryption profile is required."
      ],
      "summary": "Select a customer-managed key if this encryption profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sqs_queue",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.sqs_cmk": "600abb3697abbe7c057a68f67736076c269721c4279d2889237f8eefec46fdc7"
      },
      "source_qualname": "sqs_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The queue lacks a KMS key reference accepted by this customer-key profile."
  },
  "aws.cb.sqs.dead_letter_queue": {
    "description_base_sha256": "d231481ec3edff6a020ec33118f5236d6782b5595aba13e46526dc7b43072b36",
    "description_fields": {
      "description": "Checks that SQS queue attributes include a nonempty RedrivePolicy."
    },
    "remediation_base_sha256": "8b5b9c91dd85662ef75fda6917391ad92394a421883fe13de7f09765fdf4ea5d",
    "remediation_fields": {
      "caveats": [
        "Policy presence does not validate the target, message retries or recovery workflow."
      ],
      "steps": [
        "Configure a dead-letter queue if failed-message recovery is required."
      ],
      "summary": "Configure a dead-letter queue if failed-message recovery is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sqs_queue",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.sqs_dlq": "21bc6a0e8d4ba5ef3bade780dff4bfb7c4743e345fe40f9b6bd20c4cab1ac09a"
      },
      "source_qualname": "sqs_dlq"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The SQS queue has no nonempty redrive policy."
  },
  "aws.cb.sqs.policy_no_wildcard_allow": {
    "description_base_sha256": "7fe4b4b649199b82f47c157232b9b40b0a4732fa79bb61187f2f5e390022bb8a",
    "description_fields": {
      "description": "Finds any wildcard-principal Allow in the SQS policy, without interpreting conditions."
    },
    "remediation_base_sha256": "250a7565343bc816ed7f6b191dafef16d31762cdac7985faeb39d34f02dfda64",
    "remediation_fields": {
      "caveats": [
        "A tightly conditioned wildcard grant also fails this literal profile; effective access is not calculated."
      ],
      "steps": [
        "Review wildcard grants and restrict only those that exceed intended access."
      ],
      "summary": "Review wildcard grants and restrict only those that exceed intended access."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sqs_queue",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.wildcard_allow_statements": "8a5586bb9a835246ae37b3fe8f2d2afd149fa3013f765c7829df23433f5f49da",
        "peaso.checks.claude_aws_b_messaging._queue_policy": "59e9f4bbfc82f038bb3c97d19c4e8a0d65e684c0e893b22e62f48de6edf44665",
        "peaso.checks.claude_aws_b_messaging.sqs_public_c": "480f5a3f0cdeb1bb459647d65143054482301568c006b6f02f6d63414f9e3c0a"
      },
      "source_qualname": "sqs_public_c"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SQS policy declares a wildcard-principal Allow statement."
  },
  "aws.cb.sqs.policy_prohibit_public_access_perimeter": {
    "description_base_sha256": "d1abc2455b5b876bd37bd2d1dcd6297e0e5fe32ebb65f324d166371b3aa78378",
    "description_fields": {
      "description": "Checks SQS policy wildcard grants using the perimeter condition model."
    },
    "remediation_base_sha256": "3f1214e40ba264a2f9c1ce409933863568cac889124675c3d9f27a6d9ceeb9bd",
    "remediation_fields": {
      "caveats": [
        "Policy-model results are not live access tests and do not resolve every external control."
      ],
      "steps": [
        "Restrict unnecessary public grants to intended principals or scoped conditions."
      ],
      "summary": "Restrict unnecessary public grants to intended principals or scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sqs_queue",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131",
        "peaso.checks.claude_aws_b_messaging._queue_policy": "59e9f4bbfc82f038bb3c97d19c4e8a0d65e684c0e893b22e62f48de6edf44665",
        "peaso.checks.claude_aws_b_messaging.sqs_public_x": "c6a4076afc6d4b3fee779806c6cbf5789b1cac1fb549bbcd860573247c324753"
      },
      "source_qualname": "sqs_public_x"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SQS queue policy matches this source\u2019s public-grant criteria."
  },
  "aws.cb.sqs.queue_not_public_prowler": {
    "description_base_sha256": "60dd7f8cef840131cc7d7e0fc949625eff2093b90f9ddc1b21cbcac5f1947455",
    "description_fields": {
      "description": "Checks SQS policy wildcard grants using the account-aware Prowler condition model."
    },
    "remediation_base_sha256": "078b3a51e3450ebc2a515e1aee1bb1fb9d9197af865f661ff629f4162bae524d",
    "remediation_fields": {
      "caveats": [
        "Policy-model results are not live access tests and do not resolve every external control."
      ],
      "steps": [
        "Restrict unnecessary public grants to intended principals or scoped conditions."
      ],
      "summary": "Restrict unnecessary public grants to intended principals or scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sqs_queue",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.account": "e81980f4cab1bc0e206f42709aa2bc53c5ac0c54268c8cc9c11f58853bbc7bb0",
        "peaso.checks.claude_aws_b_messaging._queue_policy": "59e9f4bbfc82f038bb3c97d19c4e8a0d65e684c0e893b22e62f48de6edf44665",
        "peaso.checks.claude_aws_b_messaging.prowler_sqs_public": "5cb75c315065c7027ba0b76f37b595c4c2bbe9553344b032fe38e9931c16ef51",
        "peaso.checks.claude_aws_b_messaging.sqs_public_p": "d471bf16bd3e16c52eb0fab5f32698895b71f8450851ff5488fe77cfe51136dd"
      },
      "source_qualname": "sqs_public_p"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The SQS queue policy matches this source\u2019s public-grant criteria."
  },
  "aws.cb.stepfunctions.cmk_encryption": {
    "description_base_sha256": "6560f9388c998446c0ee9c087aea64f7b164689a4383d13552ef91982e8cf52b",
    "description_fields": {
      "description": "Checks that Step Functions encryption type is CUSTOMER_MANAGED_KMS_KEY."
    },
    "remediation_base_sha256": "6c49d619bce89829ad73801ac68ee51389f9d4a23b32b196b80188e7fed9abb5",
    "remediation_fields": {
      "caveats": [
        "AWS-owned encryption still encrypts data; the type does not prove customer-key usability."
      ],
      "steps": [
        "Configure a customer-managed key if that key-control profile is required."
      ],
      "summary": "Configure a customer-managed key if that key-control profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sfn_state_machine",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.sfn_cmk": "794aa750d4203bca98257eeed162a98cee71487549adbdc26d678e5ad3afd743"
      },
      "source_qualname": "sfn_cmk"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The state machine does not declare customer-managed KMS encryption."
  },
  "aws.cb.stepfunctions.logging_enabled": {
    "description_base_sha256": "0ac589cd9467f20053bcdb48317b23c71ebb11da30700a951a964d1e6152326c",
    "description_fields": {
      "description": "Checks that Step Functions logging configuration is nonempty and its level is not OFF."
    },
    "remediation_base_sha256": "a9686269aab7db98ae656444f41bb4c46e5190e6cbf7c0dd97dfbe541568b0d6",
    "remediation_fields": {
      "caveats": [
        "The predicate does not validate destination delivery or every possible level value."
      ],
      "steps": [
        "Configure a suitable logging level and destination if execution logs are required."
      ],
      "summary": "Configure a suitable logging level and destination if execution logs are required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "sfn_state_machine",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.sfn_logging_p": "9d0ddc744008d8af318b77ba0efb50b8b63c158a0d233c92710688f70d3582f1"
      },
      "source_qualname": "sfn_logging_p"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The state machine has no logging configuration or declares level OFF."
  },
  "aws.cb.storagegateway.fileshare_kms": {
    "description_base_sha256": "00f374348d3cf265dafedd73253bb6c1988822d0238bbccf8d8f445ffe244104",
    "description_fields": {
      "description": "Reads the Storage Gateway file-share KMSEncrypted flag."
    },
    "remediation_base_sha256": "af57368d75a8010d5a0d7b6b835810af3c6dfc451a6e7430ee9399ad4dbbcb0a",
    "remediation_fields": {
      "caveats": [
        "The flag does not verify key usability or encrypt every external dependency."
      ],
      "steps": [
        "Enable suitable file-share KMS encryption if required."
      ],
      "summary": "Enable suitable file-share KMS encryption if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "storagegateway_file_share",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.sgw_kms": "7fd25ebaf12e0f3ccfecd43504ceca572f152a949f96c5766a06b612996f8833"
      },
      "source_qualname": "sgw_kms"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Storage Gateway file share has KMS encryption disabled."
  },
  "aws.cb.storagegateway.gateway_not_on_ec2": {
    "description_base_sha256": "531bad47843cf4fd3a2180e9de7cae383f72f0ddd16a3f3a0d6c1fda78e9575c",
    "description_fields": {
      "description": "Checks whether the Storage Gateway HostEnvironment equals EC2."
    },
    "remediation_base_sha256": "3aea86300c8c630647c420ab18bff3a0029f3df918aedc4501246f478ab781bb",
    "remediation_fields": {
      "caveats": [
        "EC2 hosting can be legitimate and does not alone prove a single point of failure."
      ],
      "steps": [
        "Review gateway availability and recovery needs; change hosting only if the deployment profile requires it."
      ],
      "summary": "Review gateway availability and recovery needs; change hosting only if the deployment profile requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "storagegateway_gateway",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage.sgw_env": "73707a6bde0d7c1b4357e5293d568ae29eb9e9a581d1b3bd22ed4b7b29b66730"
      },
      "source_qualname": "sgw_env"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Storage Gateway is hosted on EC2 under this placement-preference profile."
  },
  "aws.cb.transfer.connector_logging_role": {
    "description_base_sha256": "84a73b2cd2924639c9b1dd6a01cc2f7f008402b2c101e6e7a8d8fff160adc35f",
    "description_fields": {
      "description": "Checks that the Transfer Family connector declares a nonempty LoggingRole."
    },
    "remediation_base_sha256": "33bf93c99b813b7c9105e79897ebab22e3e14b6a61065dba0532ddfc33503d11",
    "remediation_fields": {
      "caveats": [
        "A role reference does not prove its permissions or successful log delivery."
      ],
      "steps": [
        "Assign a suitable logging role if connector activity must be recorded."
      ],
      "summary": "Assign a suitable logging role if connector activity must be recorded."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "transfer_connector",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.tr_conn": "99306cfdd569e3bdff43e4de19f9333e1849674260accf7bfc9f48448b1bff17"
      },
      "source_qualname": "tr_conn"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Transfer Family connector declares no logging role."
  },
  "aws.cb.transfer.fips_security_policy": {
    "description_base_sha256": "913888ed8ca7261ab7a6715382dcfcd770e0e99a1641e5bc4a3d1b9d1f2a5fc7",
    "description_fields": {
      "description": "Checks whether the Transfer Family security-policy name contains a dash-separated FIPS token."
    },
    "remediation_base_sha256": "2c2fa8e1c343916848f2504707d96d57a47a649bc0978acda2bbf15fc3b09722",
    "remediation_fields": {
      "caveats": [
        "The name test does not establish actual cryptographic operation or general security of non-FIPS policies."
      ],
      "steps": [
        "Select a supported FIPS policy if your required cryptographic profile needs it."
      ],
      "summary": "Select a supported FIPS policy if your required cryptographic profile needs it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "transfer_server",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_messaging.tr_fips": "ff29046294eda8e69d53282c2d5e92197c6dded0a7c033528aebb5104281d94f"
      },
      "source_qualname": "tr_fips"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Transfer Family policy name does not contain the FIPS profile token."
  },
  "aws.cb.transfer.no_ftp_protocol": {
    "description_base_sha256": "bc45783d757b60f9ffe84beae0eabded773e801e2f914fb09da9cdd460692622",
    "description_fields": {
      "description": "Checks whether the Transfer Family server protocol list contains FTP."
    },
    "remediation_base_sha256": "e4202d3c316d7c403c970d8767f1b539d0d9f938c7fe1c296b6a22311d0658b6",
    "remediation_fields": {
      "caveats": [
        "Protocol configuration is not a live traffic or endpoint test."
      ],
      "steps": [
        "Use SFTP or FTPS instead of FTP where transport protection is required."
      ],
      "summary": "Use SFTP or FTPS instead of FTP where transport protection is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "transfer_server",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2",
        "peaso.checks.claude_aws_b_messaging.tr_ftp": "ec35ab6093580bb11c2f94196a910f1203a90eddcc516bc71a23f0898859e37d"
      },
      "source_qualname": "tr_ftp"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Transfer Family server enables plain FTP."
  },
  "aws.cb.transfer.pqc_ssh_kex_policy": {
    "description_base_sha256": "ea196940cafd2bbcba8c9aad534f8a1a9df6f17ccf6d5476fe403fcda9464794",
    "description_fields": {
      "description": "Compares the Transfer Family security-policy name with this source\u2019s post-quantum SSH policy allowlist."
    },
    "remediation_base_sha256": "bfa4c56b1c5fe1b80b421294efc3bcb2bfc001bf214455204a553d6d3ef3667f",
    "remediation_fields": {
      "caveats": [
        "A policy outside this optional allowlist is not automatically weak conventional SSH."
      ],
      "steps": [
        "Use a supported post-quantum SSH policy if required and compatible with clients."
      ],
      "summary": "Use a supported post-quantum SSH policy if required and compatible with clients."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "PQC": [
          "TransferSecurityPolicy-2025-03",
          "TransferSecurityPolicy-FIPS-2025-03",
          "TransferSecurityPolicy-AS2Restricted-2025-07"
        ]
      },
      "kind": "transfer_server",
      "module": "peaso.checks.claude_aws_b_messaging",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_messaging.tr_pqc": "1c4c4a4b3042602e64a22f0c1bb7a0f2e070b9660a88f865b6a38d703243f742"
      },
      "source_qualname": "tr_pqc"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Transfer Family server does not use a policy in the pinned post-quantum allowlist."
  },
  "aws.cb.workspaces.private_subnet_with_nat_vpc": {
    "description_base_sha256": "a04d5841a4df8d423496c37db644fdae9960028d27848d4cb987393cb1e3e83f",
    "description_fields": {
      "description": "Joins subnet route tables and requires a private WorkSpace subnet, two private subnets, one public subnet and a NAT route."
    },
    "remediation_base_sha256": "fd609f36bb400600009e5526d830ec1e5924b7347c13800d809b35fe223dcb23",
    "remediation_fields": {
      "caveats": [
        "NAT is outbound connectivity, not public ingress; alternative private egress designs can fail this literal topology profile."
      ],
      "steps": [
        "Use the private-subnet and egress design appropriate for this WorkSpace deployment."
      ],
      "summary": "Use the private-subnet and egress design appropriate for this WorkSpace deployment."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "workspaces_workspace",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.igw_default_route": "0d25eaf73ae990c938c5b946f62f6107375c90733534d4e338a24a6dbf70ba7b",
        "peaso.checks.claude_aws_b_common.subnet_route_table": "fa4570658bebade423d8d15981fe4f7f57b8b71d86428f28a0cf54a92c603696",
        "peaso.checks.claude_aws_b_common.subnet_vpc": "a5fa15042a17539391314fc461c2a7bb3d33871a258dab604daf4d1997d254e4",
        "peaso.checks.claude_aws_b_storage.ws_vpc": "b73fe8029286054299c9141670e313cbb79817ae249e7d6c0c584244749a78d5"
      },
      "source_qualname": "ws_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The WorkSpace VPC does not meet the pinned private-subnet and NAT topology."
  },
  "aws.cb.workspaces.root_and_user_volume_encryption": {
    "description_base_sha256": "786abf920230e516b9a08b5e2603f8db4ee7b2a45376dd0058860e5b66d4af0e",
    "description_fields": {
      "description": "Checks the WorkSpace encryption flags for its root and user volumes."
    },
    "remediation_base_sha256": "c729040b7b96803f4a517fe00008ce5bd4eee0ff8cc2f070b6afa2d53c59bd83",
    "remediation_fields": {
      "caveats": [
        "Existing encryption changes can require replacement; the flags do not inspect volume contents."
      ],
      "steps": [
        "Plan an encrypted WorkSpace migration for the affected root and user volumes, preserving required user data."
      ],
      "summary": "Plan an encrypted WorkSpace migration for the affected root and user volumes, preserving required user data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "workspaces_workspace",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_storage._ws_flags": "a14d5b4240b36c3bd705d35add4186eca0ecf5c0b3c628a8c87bcfca7e93aa31",
        "peaso.checks.claude_aws_b_storage.ws_both": "78e13aa6acadd78a69a3e6e0ae3c0adeaff84a8c23aa18460a2237ee08bef88e"
      },
      "source_qualname": "ws_both"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The WorkSpace does not declare encryption enabled for its root and user volumes."
  },
  "aws.cb.workspaces.root_volume_encryption": {
    "description_base_sha256": "bc0d692a1ba7293e7fafd29e8839c0c1c860713eba8ef8b639294a107730ff67",
    "description_fields": {
      "description": "Checks the WorkSpace encryption flags for its root volume."
    },
    "remediation_base_sha256": "9c4f2b9e27911246c37154b9ac993594c38eb6a40b03e33e3aceb45f7cc236e0",
    "remediation_fields": {
      "caveats": [
        "Existing encryption changes can require replacement; the flags do not inspect volume contents."
      ],
      "steps": [
        "Plan an encrypted WorkSpace migration for the affected root volume, preserving required user data."
      ],
      "summary": "Plan an encrypted WorkSpace migration for the affected root volume, preserving required user data."
    },
    "reviewed_binding": {
      "closure": {
        "field": "RootVolumeEncryptionEnabled"
      },
      "constants": {},
      "kind": "workspaces_workspace",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage._ws_one.<locals>.evaluate": "475b75e756d2e2da0e7d5fb6de329426efb944a2f2111ae937fa7635b5edb17a"
      },
      "source_qualname": "_ws_one.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The WorkSpace does not declare encryption enabled for its root volume."
  },
  "aws.cb.workspaces.user_volume_encryption": {
    "description_base_sha256": "9c866fd48945b1ccfc1a6e471d4b4bb17773ed5370c66d182f02fe1bc4bf9520",
    "description_fields": {
      "description": "Checks the WorkSpace encryption flags for its user volume."
    },
    "remediation_base_sha256": "f5903390f4a42f4cb89ba78cbbea7fddc9bd7c304afd7d50d56cc46fb3781ac6",
    "remediation_fields": {
      "caveats": [
        "Existing encryption changes can require replacement; the flags do not inspect volume contents."
      ],
      "steps": [
        "Plan an encrypted WorkSpace migration for the affected user volume, preserving required user data."
      ],
      "summary": "Plan an encrypted WorkSpace migration for the affected user volume, preserving required user data."
    },
    "reviewed_binding": {
      "closure": {
        "field": "UserVolumeEncryptionEnabled"
      },
      "constants": {},
      "kind": "workspaces_workspace",
      "module": "peaso.checks.claude_aws_b_storage",
      "predicate_sources": {
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2",
        "peaso.checks.claude_aws_b_storage._ws_one.<locals>.evaluate": "475b75e756d2e2da0e7d5fb6de329426efb944a2f2111ae937fa7635b5edb17a"
      },
      "source_qualname": "_ws_one.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The WorkSpace does not declare encryption enabled for its user volume."
  },
  "aws.claude2_a.cloudtrail.account_has_logging_trail": {
    "description_base_sha256": "eed3957b21f4bd4899f2fd8fcd6b0c55dd0f89454dd5bd1645f8b110772f9d6e",
    "description_fields": {
      "description": "Checks complete account trail inventory for any home-copy trail with IsLogging=true."
    },
    "remediation_base_sha256": "f89f2881ed4b2a42eb95caa73b5794abc34e0abd9a9614771d6fecc49c2251d4",
    "remediation_fields": {
      "caveats": [
        "One active trail does not establish complete event selectors, regions or delivery."
      ],
      "steps": [
        "Enable suitable CloudTrail logging if this account lacks an active trail."
      ],
      "summary": "Enable suitable CloudTrail logging if this account lacks an active trail."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "aws_account",
      "module": "peaso.checks.claude2_aws_a_cloudtrail",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_cloudtrail._account_trails": "8e629f4b8000f35ca0a58af150a395a69c027c8ebc6e08b4ad2291a78c6553c0",
        "peaso.checks.claude2_aws_a_cloudtrail.account_logging": "922fcd6e68483fff35104cd09e1b6004e6e9e0962aea88098e93ecc0bc664b8c"
      },
      "source_qualname": "account_logging"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The account has no home-copy CloudTrail trail reporting logging enabled."
  },
  "aws.claude2_a.cloudtrail.region_has_logging_trail": {
    "description_base_sha256": "e45eb94efabe60fe9547f54ddf7a5696c607d21be219ae068b54f23e62778449",
    "description_fields": {
      "description": "Checks regional trail inventory for an active home-region or multi-region trail."
    },
    "remediation_base_sha256": "4cb8893a22c86dd14bfd4f6c85aaf1cbf354f29fa0726663c107033cf98d6ef4",
    "remediation_fields": {
      "caveats": [
        "An active trail witness does not establish complete event selectors or delivery."
      ],
      "steps": [
        "Enable a suitable trail that covers this region if regional auditing is required."
      ],
      "summary": "Enable a suitable trail that covers this region if regional auditing is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudtrail",
      "module": "peaso.checks.claude2_aws_a_cloudtrail",
      "predicate_sources": {
        "peaso.checks.aws_a_facts.scope_subject": "2760f605db629c9bdb82c40fc799b58b0900ca08fdd6f2c56af9b6a803667a6c",
        "peaso.checks.claude2_aws_a_cloudtrail.region_logging": "8ac8f493a3634c947bfd6f306766ad1f744885c4a96fd408263e0ebb889ecc4e"
      },
      "source_qualname": "region_logging"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The region has no applicable CloudTrail trail reporting logging enabled."
  },
  "aws.claude2_a.cloudtrail.trail_bucket_mfa_delete": {
    "description_base_sha256": "aa9d9d23ab56d9e24fe96e0286a3fddfd4a8ac7e711152c8143aea6b97ef5c8d",
    "description_fields": {
      "description": "Joins a home-region trail to its owned S3 bucket and checks MFADelete=Enabled."
    },
    "remediation_base_sha256": "0512927b554df1db1834dc77ef1e4ca105e7c88aca1af8def3ed91d400c73c22",
    "remediation_fields": {
      "caveats": [
        "External buckets require review; MFA Delete is separate from Object Lock and does not prove log integrity."
      ],
      "steps": [
        "Consider MFA Delete where compatible with the audit bucket\u2019s retention and administration model."
      ],
      "summary": "Consider MFA Delete where compatible with the audit bucket\u2019s retention and administration model."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "cloudtrail",
      "module": "peaso.checks.claude2_aws_a_cloudtrail",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_cloudtrail.trail_bucket_mfa": "e410f32f003c5967aba96d8dfe23a731b0521ee1530dfe692dd91c722f34d77f",
        "peaso.checks.claude2_aws_a_common.collected": "13b4eb43022270d18ebc69ebd5187e1de0a849887ac8a41ea9646a3109e99071",
        "peaso.checks.claude2_aws_a_common.home_copy": "14b270c82b62fe04a67b6aaa60f8dd3721e298ea95c4d74a6dd5f7d9eba1b895",
        "peaso.checks.claude2_aws_a_common.not_home": "5f8d5c4c5176ad54a10be6daad6e3d4dd592d88a64875cc57f48914974d468d2",
        "peaso.checks.claude2_aws_a_common.trail_bucket": "2278ebf0c2b451154d125bca413ffa6b30e6aea5a762ca2fea03a640e7096544"
      },
      "source_qualname": "trail_bucket_mfa"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CloudTrail bucket does not declare MFA Delete enabled."
  },
  "aws.claude2_a.config.aggregation_authorization_trusted": {
    "description_base_sha256": "116be96862c745d428843c8c17830c6b7d871662bd0fe80cbaf9d0819da7d758",
    "description_fields": {
      "description": "Passes same-account Config aggregation authorizations and sends external account authorizations for trust review."
    },
    "remediation_base_sha256": "0f9ddea8e93fed15b9001009cc7eb5d0cca59a582219736091d29a4982fd52cf",
    "remediation_fields": {
      "caveats": [
        "No native approved-account universe exists here; external authorizations are MANUAL, not automatically unsafe."
      ],
      "steps": [
        "Confirm whether the external aggregation authorization is intended; remove it only if unnecessary."
      ],
      "summary": "Confirm whether the external aggregation authorization is intended; remove it only if unnecessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "config_aggregate_authorization",
      "module": "peaso.checks.claude2_aws_a_misc",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_common.scope_account": "0a26ccfdc37e0b185387b161251fe7c6a1eb99f98306504311271c657c3f9bc2",
        "peaso.checks.claude2_aws_a_misc.aggregation_authorization": "abd7a8edb2bb144cab71585e01cefcd31142b2369763064246d6ece793ec8e97"
      },
      "source_qualname": "aggregation_authorization"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Config aggregation authorization requires an external-account trust decision."
  },
  "aws.claude2_a.config.org_aggregator_all_regions_with_delegated_admin": {
    "description_base_sha256": "7d5886b95db61fa906dc1dc88acf7157cc49f579273b39369164f194c96c4dd8",
    "description_fields": {
      "description": "Checks organization aggregation, AllAwsRegions=true and at least one Config delegated-administrator record."
    },
    "remediation_base_sha256": "410c26edfd2709e9a26b3d7a214e6195e325ba5753baca46f236e02a950f0dff",
    "remediation_fields": {
      "caveats": [
        "The witness is not joined to the aggregator owner and does not prove complete configuration delivery."
      ],
      "steps": [
        "Configure the organization-wide aggregation scope and delegated administration required by this deployment profile."
      ],
      "summary": "Configure the organization-wide aggregation scope and delegated administration required by this deployment profile."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "config_aggregator",
      "module": "peaso.checks.claude2_aws_a_misc",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_misc.org_aggregator": "011ef0dac58b26754e7d0c3aa89308a8e49c0299ad8302835741df128a2ab4c5",
        "peaso.checks.claude_aws_b_common.absent_or": "18a1ea26df9fd6f98eb4d2d757fbd4d87529242f5550b8cd8811aea1c634cca2"
      },
      "source_qualname": "org_aggregator"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The aggregator lacks an organization-wide or delegated-administrator setting required by this profile."
  },
  "aws.claude2_a.dlm.snapshot_sharing_trusted_accounts": {
    "description_base_sha256": "e04555853be62605007a4e339825342a7469e00377ab94de39b638c948907453",
    "description_fields": {
      "description": "Reviews external target accounts in the first share rule of the first four enabled EBS snapshot-management schedules."
    },
    "remediation_base_sha256": "9fb642f4604f4badaa929b9f83d7d81fafd5a5ba1a257ecdc867a9e2d9c80e1e",
    "remediation_fields": {
      "caveats": [
        "The source requires an owner trust decision and does not inspect later schedules or all share rules."
      ],
      "steps": [
        "Confirm the intended external snapshot recipients; remove unnecessary shares."
      ],
      "summary": "Confirm the intended external snapshot recipients; remove unnecessary shares."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "dlm_policy",
      "module": "peaso.checks.claude2_aws_a_misc",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_common.detail": "24ef79499457c6519547eeb2b5dff453ac3347e57347cde5b7f4ac8e54452ab4",
        "peaso.checks.claude2_aws_a_common.scope_account": "0a26ccfdc37e0b185387b161251fe7c6a1eb99f98306504311271c657c3f9bc2",
        "peaso.checks.claude2_aws_a_misc.dlm_sharing": "6a68d8a099fd66681f10741eb9e95a5499967f1dca58a894f29ede901f5e063a",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      },
      "source_qualname": "dlm_sharing"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The lifecycle policy requires an external snapshot-recipient trust decision."
  },
  "aws.claude2_a.logs.log_group_not_public_via_resource_policy": {
    "description_base_sha256": "e5c2f2f3569d821c8ecd83406b5638b41ab2726c613fefd95eae820611a934e4",
    "description_fields": {
      "description": "Joins log-group ARNs to resource policies judged public and containing that ARN or Resource:*."
    },
    "remediation_base_sha256": "e58d2bf49d1fd09cd4b52bd2bfe02a2a9d439563ff94e43dddf53447efd6a445",
    "remediation_fields": {
      "caveats": [
        "The source joins ARN substrings after a document-level public test, so a match does not prove the same statement grants access."
      ],
      "steps": [
        "Review matching resource-policy statements and narrow unnecessary grants."
      ],
      "summary": "Review matching resource-policy statements and narrow unnecessary grants."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "log_group",
      "module": "peaso.checks.claude2_aws_a_misc",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_common.scope_account": "0a26ccfdc37e0b185387b161251fe7c6a1eb99f98306504311271c657c3f9bc2",
        "peaso.checks.claude2_aws_a_misc.log_group_public": "18f4750ad64f2bfec4c2903cbc9e03a5613c66cfdc65c32b6d7502e4bea89b11",
        "peaso.checks.claude_aws_b_common.is_policy_public": "80a33609944bd0a1df87c7b89bdc31093d82fc9a5544183e6926e7f4ef38032f",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_common.strings": "14c4269098c145ff223dcc31ee6a7df80e81230a33a0c0efa5893c2b77e2ade2"
      },
      "source_qualname": "log_group_public"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A modeled-public resource policy references this log group or all resources."
  },
  "aws.claude2_a.logs.resource_policy_not_public": {
    "description_base_sha256": "651290d5d543ba35419ea210ed5d88048996ba08dd6176829c7a1864312ddba9",
    "description_fields": {
      "description": "Checks the CloudWatch Logs resource policy for wildcard grants without recognized restricting conditions."
    },
    "remediation_base_sha256": "7b785b3ff445a5fee084482f3e0ef47d4cb3efcbfe6a4d2cd4b932f2b66dc658",
    "remediation_fields": {
      "caveats": [
        "This policy model does not calculate every effective permission or test log access."
      ],
      "steps": [
        "Restrict unnecessary policy grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary policy grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "log_resource_policy",
      "module": "peaso.checks.claude2_aws_a_misc",
      "predicate_sources": {
        "peaso.checks.claude2_aws_a_misc.log_policy_public": "5274ff7c740949b96c7f10a77d357691ed2d74aa7804fb129d5975e01153d1a1",
        "peaso.checks.claude_aws_b_common.policy_document": "66644913c85538bcae6068f3403b52bc1e153cd29e05373531224ce905ac4e13",
        "peaso.checks.claude_aws_b_common.turbot_public_statements": "3ad714a1cfcbee99d10c048590f75d6a253fbf4aee4efd7b6d00f2983b379131"
      },
      "source_qualname": "log_policy_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The CloudWatch Logs resource policy matches the public-grant model."
  },
  "aws.claude_a.ec2.client_vpn_connection_logging": {
    "description_base_sha256": "ad83805d1ad76f9dad28e4b60c772518b8ebd3e50ebacf52ee1d699792fac39c",
    "description_fields": {
      "description": "Reads the Client VPN endpoint connection-logging flag."
    },
    "remediation_base_sha256": "b04523b3f76fb1ca070e99ad4a54999420a8d57964e8c470090304b138309806",
    "remediation_fields": {
      "caveats": [
        "The flag does not prove log delivery or retention."
      ],
      "steps": [
        "Enable connection logging where VPN activity needs auditing."
      ],
      "summary": "Enable connection logging where VPN activity needs auditing."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ec2_client_vpn_endpoint",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_ec2.client_vpn_logging": "ca298e0354aeb13cec004c25832884d26c42d01ca6b12a082d8f24c36bdd136f"
      },
      "source_qualname": "client_vpn_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Client VPN endpoint disables connection logging."
  },
  "aws.claude_a.ec2.eip_associated": {
    "description_base_sha256": "7b1d8901a8a2f29430bb72f8474730ab90511814552404e4ba0bbc26adb9cbb6",
    "description_fields": {
      "description": "Checks whether an allocated Elastic IP declares an association identifier."
    },
    "remediation_base_sha256": "b1ebaf9abfb0bc199b9aab50547da6d02d4c9fffc424df2e61d9365a6338a3e5",
    "remediation_fields": {
      "caveats": [
        "An unassociated address can be intentionally reserved; this is an inventory and cost check."
      ],
      "steps": [
        "Associate the address if needed or release it after checking dependencies."
      ],
      "summary": "Associate the address if needed or release it after checking dependencies."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ec2_eip",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_common.absent_or": "1f9bd01a08d00fa2fb23bfa8abd02a367bce9086494082231c0671ef471cf5f6",
        "peaso.checks.claude_aws_a_ec2.eip_associated": "522ac86dc5e999ceb5ba0df0b5fa3a736996ab42760667d416459e5c5ab09d81"
      },
      "source_qualname": "eip_associated"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Elastic IP has no association identifier."
  },
  "aws.claude_a.ec2.eni_in_use": {
    "description_base_sha256": "693cf45a3cbd56cf3cf51f0a5eceac642a6918aff99de0ca6544eb2fbe18a7ef",
    "description_fields": {
      "description": "Finds network interfaces whose status is available and which have no attached instance identifier."
    },
    "remediation_base_sha256": "9d15cd147f3b367562e48a24d79009f1d1a2acb7b7f50b35dbb53aeb8be9fc3c",
    "remediation_fields": {
      "caveats": [
        "An available interface can be intentionally reserved or managed by a service."
      ],
      "steps": [
        "Remove the unattached interface only after confirming it is unused."
      ],
      "summary": "Remove the unattached interface only after confirming it is unused."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "network_interface",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_common.absent_or": "1f9bd01a08d00fa2fb23bfa8abd02a367bce9086494082231c0671ef471cf5f6",
        "peaso.checks.claude_aws_a_ec2.eni_unused": "be14f73b179d0081314cacddc02d9a886426ccb7fe10cefdcbdce7c60f774773"
      },
      "source_qualname": "eni_unused"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The network interface is available and has no attached instance."
  },
  "aws.claude_a.ec2.eni_no_public_ip": {
    "description_base_sha256": "9b5fe68c8e03b2dc86a0ce64a1c050584a61d797857f31373eedcfeee86c2d62",
    "description_fields": {
      "description": "Checks whether the network interface declares an associated public IPv4 address."
    },
    "remediation_base_sha256": "7528b598585421ca0a2f1fa66f3f077943f74a192924fe8b44368839cc1bd070",
    "remediation_fields": {
      "caveats": [
        "A public address does not prove a reachable listener or permissive network rules."
      ],
      "steps": [
        "Remove the public association if this interface does not need public connectivity."
      ],
      "summary": "Remove the public association if this interface does not need public connectivity."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "network_interface",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_common.absent_or": "1f9bd01a08d00fa2fb23bfa8abd02a367bce9086494082231c0671ef471cf5f6",
        "peaso.checks.claude_aws_a_ec2.eni_public": "5e4a10c1d221f7ad133b8b918b33a1c5f99fd002b96e22eadee33a448db87993"
      },
      "source_qualname": "eni_public"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The network interface declares a public IPv4 association."
  },
  "aws.claude_a.ec2.eni_source_dest_check": {
    "description_base_sha256": "c89c7d6dd8fd6edb71138de8454e4f6d31038b511015f06b5c3afeee29b42300",
    "description_fields": {
      "description": "Checks SourceDestCheck on the source\u2019s applicable network-interface types."
    },
    "remediation_base_sha256": "0be63d8a87283e39af964eb70e1417bf8416834712f6de732d39c8de945b2882",
    "remediation_fields": {
      "caveats": [
        "Disabling this check can be required for legitimate traffic forwarding."
      ],
      "steps": [
        "Enable source/destination checking unless the interface serves a router, NAT or forwarding appliance."
      ],
      "summary": "Enable source/destination checking unless the interface serves a router, NAT or forwarding appliance."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_SDC_TYPES": [
          "aws_codestar_connections_managed",
          "branch",
          "efa",
          "interface",
          "lambda",
          "quicksight"
        ]
      },
      "kind": "network_interface",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_ec2.eni_sdc": "67d423695b7560f2c5a3faeb524a1d19a6803b169923e1f945af451e737b7e61"
      },
      "source_qualname": "eni_sdc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Source/destination checking is disabled on this applicable network interface."
  },
  "aws.claude_a.ec2.spot_fleet_ebs_encrypted": {
    "description_base_sha256": "7c07899c2b3986e8cd6995dc900a1485ed0c641dc275b028982b611c75a286ff",
    "description_fields": {
      "description": "Checks that every EBS mapping in Spot Fleet launch specifications explicitly sets Encrypted=true."
    },
    "remediation_base_sha256": "11fc5a2e1b9bbaa5846b25d62f05c8612a87e910c699aca3c3872935a5de0d10",
    "remediation_fields": {
      "caveats": [
        "Launch-template fleets are outside scope; account defaults and existing volume encryption are not inferred."
      ],
      "steps": [
        "Enable EBS encryption in the affected launch specifications before replacing instances."
      ],
      "summary": "Enable EBS encryption in the affected launch specifications before replacing instances."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ec2_spot_fleet_request",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_ec2.spot_fleet_encrypted": "dd9f1aa1a566e7e706465221840538c11c01c459969a200bcff5ecc805c9492c"
      },
      "source_qualname": "spot_fleet_encrypted"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Spot Fleet EBS launch mapping does not explicitly enable encryption."
  },
  "aws.claude_a.ec2.tgw_no_auto_accept_shared_attachments": {
    "description_base_sha256": "f9c51ff7831c83e9c4d10bc76c2ce08727335b40d52b41890aeabf8a8472c675",
    "description_fields": {
      "description": "Reads whether the transit gateway automatically accepts shared attachments."
    },
    "remediation_base_sha256": "faa807e05f40a2e46810c7503090f0150778f00a3ff18ab56435dec863b77a6a",
    "remediation_fields": {
      "caveats": [
        "Automatic acceptance does not itself prove an untrusted attachment exists."
      ],
      "steps": [
        "Disable automatic acceptance when cross-account attachments should require review."
      ],
      "summary": "Disable automatic acceptance when cross-account attachments should require review."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "transit_gateway",
      "module": "peaso.checks.claude_aws_a_ec2",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_ec2.tgw_auto_accept": "6ec181c8926c1732163b3e317f01da8815ad1696730a56d996e81ace601baf3e"
      },
      "source_qualname": "tgw_auto_accept"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The transit gateway automatically accepts shared attachments."
  },
  "aws.claude_a.s3.account_public_access_block_all": {
    "description_base_sha256": "49abc9171217f7ec35185f7434bb31ce88785e31c14917bf5c2992245491ff3b",
    "description_fields": {
      "description": "Checks all four account-level S3 Block Public Access flags."
    },
    "remediation_base_sha256": "4bd1f687b742f4d10eb3baf3dac97f82235911c255d599aaf242a643403783a1",
    "remediation_fields": {
      "caveats": [
        "Missing guardrails do not prove any bucket is public."
      ],
      "steps": [
        "Enable all four flags if account-wide public access is unnecessary; check intentional public workloads first."
      ],
      "summary": "Enable all four flags if account-wide public access is unnecessary; check intentional public workloads first."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BLOCKS": [
          "BlockPublicAcls",
          "IgnorePublicAcls",
          "BlockPublicPolicy",
          "RestrictPublicBuckets"
        ]
      },
      "kind": "s3_account_public_access_block",
      "module": "peaso.checks.claude_aws_a_s3",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_s3.account_all": "39e551177010f6eef1df4b5b654a279cf8987407e8cbb3c3036f2c862b217175",
        "peaso.checks.claude_aws_a_s3.account_blocks": "8614ed71c348946e631aa2924ab6cc95ee7e6a431eb2baaec4e49180de9dbbba"
      },
      "source_qualname": "account_all"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "At least one account-level S3 Block Public Access flag is disabled."
  },
  "aws.claude_a.s3.directory_bucket_lifecycle": {
    "description_base_sha256": "99240b176fa48d79956c138dd1b48adc6ac3ba4b2208c4d7979306ce52b86d60",
    "description_fields": {
      "description": "Checks whether the directory bucket has any lifecycle configuration."
    },
    "remediation_base_sha256": "281df36c491e2ac8b9809acde564d0066339a616675efecb7e4257f5e9b981b2",
    "remediation_fields": {
      "caveats": [
        "Configuration presence does not validate rule coverage or prove cleanup occurred."
      ],
      "steps": [
        "Add lifecycle rules if object cleanup is needed; preserve required data retention."
      ],
      "summary": "Add lifecycle rules if object cleanup is needed; preserve required data retention."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "_S3_DETAIL_PAYLOAD_KEYS": {
          "Encryption": [
            "ServerSideEncryptionConfiguration"
          ],
          "Lifecycle": [
            "Rules"
          ],
          "ObjectLock": [
            "ObjectLockConfiguration"
          ],
          "OwnershipControls": [
            "OwnershipControls"
          ],
          "Policy": [
            "Policy"
          ],
          "PolicyStatus": [
            "PolicyStatus"
          ],
          "PublicAccessBlock": [
            "PublicAccessBlockConfiguration"
          ],
          "Replication": [
            "ReplicationConfiguration"
          ],
          "Tags": [
            "TagSet"
          ],
          "Website": [
            "IndexDocument",
            "ErrorDocument",
            "RedirectAllRequestsTo",
            "RoutingRules"
          ]
        }
      },
      "kind": "s3_directory_bucket",
      "module": "peaso.checks.claude_aws_a_s3",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_s3.directory_lifecycle": "8dc31a38aaa14cf2656333ea0e3ffe92206aac3692e5664f9502f08de6f5f498",
        "peaso.checks.claude_aws_a_s3.section": "3ff06aae1e62f578522904c1387d95e18c5809a19b429bfa83e8e6721f842951"
      },
      "source_qualname": "directory_lifecycle"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The S3 directory bucket has no lifecycle configuration."
  },
  "aws.claude_a.s3.multi_region_access_point_public_access_block": {
    "description_base_sha256": "4d9309e1cc0414e93f8e085a9457dcb07c6a3e6585005acf9dd3bc3f38611105",
    "description_fields": {
      "description": "Checks all four public-access-block flags on the S3 Multi-Region Access Point."
    },
    "remediation_base_sha256": "a2199a951b0182e2f11ce0b860c312fcda0cea18c7712086109b8ba4f056ecf8",
    "remediation_fields": {
      "caveats": [
        "A disabled guardrail is not proof of a public data path."
      ],
      "steps": [
        "Use an access point with all required public-access-block settings; preserve intended access during replacement."
      ],
      "summary": "Use an access point with all required public-access-block settings; preserve intended access during replacement."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BLOCKS": [
          "BlockPublicAcls",
          "IgnorePublicAcls",
          "BlockPublicPolicy",
          "RestrictPublicBuckets"
        ]
      },
      "kind": "s3_multi_region_access_point",
      "module": "peaso.checks.claude_aws_a_s3",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_s3._all_access_point_flags": "8cc7f6b30df6435672a09386b9f5bb393b8cc4a2e4c0a79fcb2511ebda2fa8b8",
        "peaso.checks.claude_aws_a_s3.mrap": "e2ead0d0c603eca6f47f990d07f9bfef7facd880984f969680c4105d05c5886e"
      },
      "source_qualname": "mrap"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Multi-Region Access Point has a disabled public-access-block flag."
  },
  "aws.claude_a.s3.prowler_account_ignore_restrict": {
    "description_base_sha256": "dabf29eff05a1309c89e98f0d980a4e41003b463357c47cd605ec07a9986d2f1",
    "description_fields": {
      "description": "Checks account-level IgnorePublicAcls and RestrictPublicBuckets when the account has buckets."
    },
    "remediation_base_sha256": "c2321dad270da5eb68817b96f55b0b7a8b8668b319e06f71d9d81f82f8f5aa89",
    "remediation_fields": {
      "caveats": [
        "The two flags do not establish effective access for every bucket."
      ],
      "steps": [
        "Enable these public-access guardrails where public buckets and ACLs are unnecessary."
      ],
      "summary": "Enable these public-access guardrails where public buckets and ACLs are unnecessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "BLOCKS": [
          "BlockPublicAcls",
          "IgnorePublicAcls",
          "BlockPublicPolicy",
          "RestrictPublicBuckets"
        ]
      },
      "kind": "s3_account_public_access_block",
      "module": "peaso.checks.claude_aws_a_s3",
      "predicate_sources": {
        "peaso.checks.claude_aws_a_common.items": "449c5d049df799e2a26ce590535ed288f924e7de25800c9afd073942183956c0",
        "peaso.checks.claude_aws_a_s3.account_blocks": "8614ed71c348946e631aa2924ab6cc95ee7e6a431eb2baaec4e49180de9dbbba",
        "peaso.checks.claude_aws_a_s3.prowler_account": "b81c0d772ed5554d3dc46d83bc28cb61306a5f883db0c8ded53dc5cc81356763"
      },
      "source_qualname": "prowler_account"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The account has buckets and lacks an IgnorePublicAcls or RestrictPublicBuckets guardrail."
  },
  "aws.cloudtrail.kms_encryption": {
    "description_base_sha256": "d8563f2167eefa3bd3e9ba7f3bd718035e7589d0665a7627ad3608f653b0f905",
    "description_fields": {
      "description": "Checks that the CloudTrail trail declares a nonempty KMS key identifier."
    },
    "remediation_base_sha256": "1b118fa56ac1a0e94ce11e29fb4032271aeb06fc967e969be472e045f13f1c8f",
    "remediation_fields": {
      "caveats": [
        "A key reference does not prove key usability or that service-managed encryption is absent."
      ],
      "steps": [
        "Select a suitable KMS key if customer-managed log encryption is required."
      ],
      "summary": "Select a suitable KMS key if customer-managed log encryption is required."
    },
    "reviewed_binding": {
      "closure": {
        "path": "KmsKeyId"
      },
      "constants": {},
      "kind": "cloudtrail",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.nonempty.<locals>.evaluate": "90a36866245362615a3c31c3dad2a5155028f7288d27fdbd978fc41d6a8f1fce"
      },
      "source_qualname": "nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The CloudTrail trail declares no KMS key identifier."
  },
  "aws.config.service_linked_role": {
    "description_base_sha256": "ee9eae52985f989e4d22761028e795641fb5040395a644be4da73b458e640d54",
    "description_fields": {
      "description": "Checks that a recording AWS Config recorder uses its account\u2019s exact Config service-linked role ARN."
    },
    "remediation_base_sha256": "36946f33c58ea50376fb263cbcc74a2ca9e1281fb9ba8d5b5447d277ddb06bd8",
    "remediation_fields": {
      "caveats": [
        "A custom role may be legitimate; this comparison does not assess its permissions."
      ],
      "steps": [
        "Use the Config service-linked role if this deployment profile is required."
      ],
      "summary": "Use the Config service-linked role if this deployment profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "config_recorder",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.config_role": "001cbdddb3c2c4ba675dfa8bd9d32f484c367c39c9d88469b1fb82cb01ffe57f"
      },
      "source_qualname": "config_role"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The recording Config recorder uses a different role from its account\u2019s service-linked role."
  },
  "aws.ec2.restrict_internet_ingress": {
    "description_base_sha256": "a6b106c580e6c4afb9a2fd83d0570d8cd6f89056e6c27959273427f82e506c6c",
    "description_fields": {
      "description": "Finds security-group ingress CIDRs covering all IPv4 or IPv6 addresses."
    },
    "remediation_base_sha256": "a9be14f228be1819da797c9fe85b967ab3e26eac04530e2b8040161e05368269",
    "remediation_fields": {
      "caveats": [
        "Security-group declarations do not prove a reachable listener or network path."
      ],
      "steps": [
        "Restrict unnecessary ingress sources and ports to the clients that need them."
      ],
      "summary": "Restrict unnecessary ingress sources and ports to the clients that need them."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "security_group",
      "module": "peaso.checks",
      "predicate_sources": {
        "peaso.checks.aws_ingress": "6e8c6ef6a2d62aedb96fba4d9335ffd53d9f8c9333ae9ca8ec53dffd5e36881e"
      },
      "source_qualname": "aws_ingress"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The security group allows ingress from every IPv4 or IPv6 address."
  },
  "aws.ecr.lifecycle_policy": {
    "description_base_sha256": "377c47bfe28c29c7c6fad9266ff5953837db4ce9cfc9a75904795595baafb66b",
    "description_fields": {
      "description": "Checks that an ECR repository has a nonempty lifecycle-policy document."
    },
    "remediation_base_sha256": "48297a71fd93184d4e405e7a84d875c49301c8e414dfd4885d0cc5c808877a2a",
    "remediation_fields": {
      "caveats": [
        "Policy presence does not validate its rules or prove image deletion has occurred."
      ],
      "steps": [
        "Add a lifecycle policy if stale image cleanup is needed; retain images required for rollback."
      ],
      "summary": "Add a lifecycle policy if stale image cleanup is needed; retain images required for rollback."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "ecr_repository",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.ecr_lifecycle": "6b4b7fd78a75bff9d25828b8ec927e45d2b9e98779958b6a16ebfcecf6689b5a"
      },
      "source_qualname": "ecr_lifecycle"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The ECR repository has no nonempty lifecycle-policy document."
  },
  "aws.elbv2.deletion_protection": {
    "description_base_sha256": "df27522db918c9c4ef8e8dc58af46cb820e108009983b7649d529b3365fa693f",
    "description_fields": {
      "description": "Reads the ELBv2 deletion_protection.enabled attribute."
    },
    "remediation_base_sha256": "d554977bbd278df210057bef5727627ccfb592440e0e3ea69301a9ff1cc22f7a",
    "remediation_fields": {
      "caveats": [
        "Deletion protection does not replace recovery planning or change controls."
      ],
      "steps": [
        "Enable deletion protection where accidental load-balancer deletion would disrupt service."
      ],
      "summary": "Enable deletion protection where accidental load-balancer deletion would disrupt service."
    },
    "reviewed_binding": {
      "closure": {
        "application_only": false,
        "key": "deletion_protection.enabled"
      },
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.lb_attribute": "2a0725b6ca6931c0be3c44840d8c4d1435d7aa9b6764d3aba19c41a35ba1bf9a",
        "peaso.checks.aws_extended.lb_boolean.<locals>.evaluate": "a879fff4501c84fb2ecc2f8f1a7f22678d4ef8237454c754d5a407d179052fc7"
      },
      "source_qualname": "lb_boolean.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Load-balancer deletion protection is disabled."
  },
  "aws.elbv2.multiple_availability_zones": {
    "description_base_sha256": "de563bfaad7990c4e7866c836fe33e6534a9c09bd59f2711c45b35ab002e1cb6",
    "description_fields": {
      "description": "Counts distinct availability-zone names declared by the load balancer; requires at least two."
    },
    "remediation_base_sha256": "7ec541b043aef7e265162eb1cb2af6776164f720f18059c32d6ec117bf80bba1",
    "remediation_fields": {
      "caveats": [
        "Declared zones do not prove healthy backends or successful failover."
      ],
      "steps": [
        "Use suitable subnets in at least two availability zones if redundancy is required."
      ],
      "summary": "Use suitable subnets in at least two availability zones if redundancy is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "load_balancer",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.lb_zones": "b16cca7cbc0bd7f88ea5bcf910c33d2a4441566483e8f67e095b1139de8100ac"
      },
      "source_qualname": "lb_zones"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The load balancer declares fewer than two distinct availability zones."
  },
  "aws.guardduty.eks_audit_logs": {
    "description_base_sha256": "a18f53a01601fbbad4a686deee4839818659b2ce93e62d6e4249c30812e50096",
    "description_fields": {
      "description": "Checks that the existing GuardDuty detector and its EKS audit-log protection feature are both enabled."
    },
    "remediation_base_sha256": "64cff6c1aa6b3267a0947a12916c74047df178ec0c78652129ca273af57bb0f1",
    "remediation_fields": {
      "caveats": [
        "Feature settings do not prove event coverage or successful threat detection."
      ],
      "steps": [
        "Enable EKS audit-log protection and its GuardDuty detector where required."
      ],
      "summary": "Enable EKS audit-log protection and its GuardDuty detector where required."
    },
    "reviewed_binding": {
      "closure": {
        "feature": "EKS_AUDIT_LOGS"
      },
      "constants": {},
      "kind": "guardduty_detector",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.feature_check.<locals>.evaluate": "23e7043986c1b4993f6b55f72ceebeb1d6565cdd70bfebeeca2ac64f36649c2b"
      },
      "source_qualname": "feature_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GuardDuty detector or its EKS audit-log protection feature is disabled or absent."
  },
  "aws.guardduty.lambda_network_logs": {
    "description_base_sha256": "d6ffa4d1fbd451a71e81cd7e3298ae445c401e2b4d2247ef0451ecb766106893",
    "description_fields": {
      "description": "Checks that the existing GuardDuty detector and its Lambda network protection feature are both enabled."
    },
    "remediation_base_sha256": "d0225ea2a96941e77c3060ec363676b3e75c8b40656fda6822cd0512a53cc303",
    "remediation_fields": {
      "caveats": [
        "Feature settings do not prove event coverage or successful threat detection."
      ],
      "steps": [
        "Enable Lambda network protection and its GuardDuty detector where required."
      ],
      "summary": "Enable Lambda network protection and its GuardDuty detector where required."
    },
    "reviewed_binding": {
      "closure": {
        "feature": "LAMBDA_NETWORK_LOGS"
      },
      "constants": {},
      "kind": "guardduty_detector",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.feature_check.<locals>.evaluate": "23e7043986c1b4993f6b55f72ceebeb1d6565cdd70bfebeeca2ac64f36649c2b"
      },
      "source_qualname": "feature_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GuardDuty detector or its Lambda network protection feature is disabled or absent."
  },
  "aws.guardduty.rds_login_events": {
    "description_base_sha256": "26ce2233b0391cab5069307267182bfe83650ceffcb2b1e56cc11f97da5f173f",
    "description_fields": {
      "description": "Checks that the existing GuardDuty detector and its RDS login-event protection feature are both enabled."
    },
    "remediation_base_sha256": "88cb4764a3d16ea56f9a976be9429ccdb5378400436ea610282e5d88c76b93c6",
    "remediation_fields": {
      "caveats": [
        "Feature settings do not prove event coverage or successful threat detection."
      ],
      "steps": [
        "Enable RDS login-event protection and its GuardDuty detector where required."
      ],
      "summary": "Enable RDS login-event protection and its GuardDuty detector where required."
    },
    "reviewed_binding": {
      "closure": {
        "feature": "RDS_LOGIN_EVENTS"
      },
      "constants": {},
      "kind": "guardduty_detector",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.feature_check.<locals>.evaluate": "23e7043986c1b4993f6b55f72ceebeb1d6565cdd70bfebeeca2ac64f36649c2b"
      },
      "source_qualname": "feature_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GuardDuty detector or its RDS login-event protection feature is disabled or absent."
  },
  "aws.guardduty.runtime_monitoring": {
    "description_base_sha256": "a07b5c84afe2b303f7379903d1947bfd2a7d852c2ca1825b7cf48e6aef0a1e72",
    "description_fields": {
      "description": "Checks that the existing GuardDuty detector and its runtime monitoring feature are both enabled."
    },
    "remediation_base_sha256": "38d20574699aa2960a618e8c949584d0ceebd0fed642c72c96bc3afa5f825212",
    "remediation_fields": {
      "caveats": [
        "Feature settings do not prove event coverage or successful threat detection."
      ],
      "steps": [
        "Enable runtime monitoring and its GuardDuty detector where required."
      ],
      "summary": "Enable runtime monitoring and its GuardDuty detector where required."
    },
    "reviewed_binding": {
      "closure": {
        "feature": "RUNTIME_MONITORING"
      },
      "constants": {},
      "kind": "guardduty_detector",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.feature_check.<locals>.evaluate": "23e7043986c1b4993f6b55f72ceebeb1d6565cdd70bfebeeca2ac64f36649c2b"
      },
      "source_qualname": "feature_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GuardDuty detector or its runtime monitoring feature is disabled or absent."
  },
  "aws.guardduty.s3_data_events": {
    "description_base_sha256": "d8699be2e82d1b454e936266924150d58f1125df6f7d8e23944e850f0e124863",
    "description_fields": {
      "description": "Checks that the existing GuardDuty detector and its S3 data-event protection feature are both enabled."
    },
    "remediation_base_sha256": "3c446ce468c521364f405422fbcd2c64e5f0bae1e7473848982b8c768aad43cf",
    "remediation_fields": {
      "caveats": [
        "Feature settings do not prove event coverage or successful threat detection."
      ],
      "steps": [
        "Enable S3 data-event protection and its GuardDuty detector where required."
      ],
      "summary": "Enable S3 data-event protection and its GuardDuty detector where required."
    },
    "reviewed_binding": {
      "closure": {
        "feature": "S3_DATA_EVENTS"
      },
      "constants": {},
      "kind": "guardduty_detector",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.feature_check.<locals>.evaluate": "23e7043986c1b4993f6b55f72ceebeb1d6565cdd70bfebeeca2ac64f36649c2b"
      },
      "source_qualname": "feature_check.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GuardDuty detector or its S3 data-event protection feature is disabled or absent."
  },
  "aws.htbp.cognito.identity_pool_classic_flow_disabled": {
    "description_base_sha256": "3c295e298d3a5ddae1cfa9fd87b257eee3f3de9c4523aea5a4a6e028661e02f7",
    "description_fields": {
      "description": "Reads the identity pool AllowClassicFlow flag, using the service\u2019s false omission default."
    },
    "remediation_base_sha256": "dd1a10e625e28cd1e7794956a1250b97c0a0886c0d7b11bb6fd0af60893dd88f",
    "remediation_fields": {
      "caveats": [
        "Classic-flow enablement alone does not establish excessive role permissions or an exploitable path."
      ],
      "steps": [
        "Disable classic flow unless required; use the enhanced authentication flow where appropriate."
      ],
      "summary": "Disable classic flow unless required; use the enhanced authentication flow where appropriate."
    },
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "classic_flow"
        }
      },
      "constants": {},
      "kind": "cognito_identity_pool",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_sources": {
        "peaso.checks.hacktricks_bp_aws.classic_flow": "b0ae6f0e53da9d968c022d010bc8a47db4b00fa3c3e51619fc92dc2d46de3996",
        "peaso.checks.hacktricks_bp_common.ht_register.<locals>.apply.<locals>.evaluate": "66de431b10d4f724f8ff7391116df58fc088fc66226ca0c7ee5cf4a3ba44fad5",
        "peaso.checks.hacktricks_bp_common.native": "ae306cc4db16319694007c41ee7e2049e503bda32ccade629b0f300607f8a546"
      },
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cognito identity pool enables classic authentication flow."
  },
  "aws.iam.no_full_admin": {
    "description_base_sha256": "a3b680b23b657acff9670532f961539cc78d555ab78ca1afb933ef8e997ecd78",
    "description_fields": {
      "description": "Finds unconditional Allow statements granting Action:* on Resource:* in collected policy documents."
    },
    "remediation_base_sha256": "d2020735939a591cfca179c0f88a6cd8f8b58bf4bb81ed66cb1f76cc2333f49e",
    "remediation_fields": {
      "caveats": [
        "Declared grants are not effective access; conditioned administrator statements require review."
      ],
      "steps": [
        "Replace unnecessary full-administrator statements with the actions and resources this workload needs."
      ],
      "summary": "Replace unnecessary full-administrator statements with the actions and resources this workload needs."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "iam_policy",
      "module": "peaso.checks",
      "predicate_sources": {
        "peaso.checks.array": "deef94b9a8f4ff3e52550f342b85148a65c21822a3b7fd20d2a0db160f05e7fc",
        "peaso.checks.aws_admin": "c91daeb64e94c43a881b53606ec04ac366332a4eb99ef08a2983a73d5eba9861",
        "peaso.checks.aws_documents": "253971a39622d6c2736eab50ac3cbb327a91403bcb9bf091d17ae60501d1841b",
        "peaso.checks.statements": "42d39abb720b190099ce19056ec8fc99e3955ef527647377d5ed2cf552e4b711"
      },
      "source_qualname": "aws_admin"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The policy declares an unconditional full-administrator grant."
  },
  "aws.iam.password_minimum_length": {
    "description_base_sha256": "0f4fc5a5e0fb5f859d62faaa4f01794a75541919b56fdb711680e8e4098f6474",
    "description_fields": {
      "description": "Checks that the account password policy requires at least 14 characters."
    },
    "remediation_base_sha256": "40a031451e36ef2271824cf01838a765787c3f94319527959e0a3718aea4fd0f",
    "remediation_fields": {
      "caveats": [
        "This account policy does not establish federated or application password controls."
      ],
      "steps": [
        "Require at least 14 characters in the IAM account password policy."
      ],
      "summary": "Require at least 14 characters in the IAM account password policy."
    },
    "reviewed_binding": {
      "closure": {
        "maximum": null,
        "minimum": 14,
        "path": "PasswordPolicy.MinimumPasswordLength"
      },
      "constants": {},
      "kind": "iam_password_policy",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.numeric.<locals>.evaluate": "d9d55717e580184cdcf1d50479966864953a8cefdf519c7002f7183722065987"
      },
      "source_qualname": "numeric.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The account password policy permits passwords shorter than 14 characters."
  },
  "aws.iam.password_reuse_prevention": {
    "description_base_sha256": "dcb4366f682895bd93351666efc24548130251df74c923ead2946d116b09218e",
    "description_fields": {
      "description": "Checks that the account password policy prevents reuse of exactly 24 prior passwords."
    },
    "remediation_base_sha256": "7e15a81a27093591edf2eeb7680b6e6fc762616c07b6083f99ccacf3e1e401b4",
    "remediation_fields": {
      "caveats": [
        "This account policy does not establish federated or application password controls."
      ],
      "steps": [
        "Set IAM password reuse prevention to 24 prior passwords if this profile is adopted."
      ],
      "summary": "Set IAM password reuse prevention to 24 prior passwords if this profile is adopted."
    },
    "reviewed_binding": {
      "closure": {
        "maximum": 24,
        "minimum": 24,
        "path": "PasswordPolicy.PasswordReusePrevention"
      },
      "constants": {},
      "kind": "iam_password_policy",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.numeric.<locals>.evaluate": "d9d55717e580184cdcf1d50479966864953a8cefdf519c7002f7183722065987"
      },
      "source_qualname": "numeric.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The account password policy does not prevent reuse of 24 prior passwords."
  },
  "aws.kms.no_pending_key_deletion": {
    "description_base_sha256": "ccc31450387cd3ac8f5b472cda1b15d77f7eed2d22478efa001a9ae1b7860c3c",
    "description_fields": {
      "description": "Finds customer-managed KMS keys in PendingDeletion, excluding disabled keys under this profile."
    },
    "remediation_base_sha256": "c512e12df20a4129cc04aee641454e77add7dc616e20c6e5aab656081653ee3a",
    "remediation_fields": {
      "caveats": [
        "Key state does not identify every dependent ciphertext or validate recovery."
      ],
      "steps": [
        "Cancel deletion if the key still protects needed data; otherwise verify the deletion is intentional."
      ],
      "summary": "Cancel deletion if the key still protects needed data; otherwise verify the deletion is intentional."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kms_key",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.kms_deletion": "b3fea3a13a49e55e580388c1a9f198c8d29232482d77458b1644838eb7134d1a"
      },
      "source_qualname": "kms_deletion"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The customer-managed KMS key is scheduled for deletion."
  },
  "aws.kms.rotation": {
    "description_base_sha256": "e6a8f26a25ee490808754466a4a3f01864b45f50be330acd705326c332419e5b",
    "description_fields": {
      "description": "Checks automatic rotation on customer-managed AWS_KMS symmetric keys."
    },
    "remediation_base_sha256": "ae52a61f4a499923d15efd6f3bb87dfb47e116db0f0fde6667295a66a48c01b4",
    "remediation_fields": {
      "caveats": [
        "Rotation configuration does not prove past rotations or re-encryption of existing data."
      ],
      "steps": [
        "Enable automatic rotation on this eligible customer-managed key."
      ],
      "summary": "Enable automatic rotation on this eligible customer-managed key."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "kms_key",
      "module": "peaso.checks.aws",
      "predicate_sources": {
        "peaso.checks.aws.rotation": "5fea9732300bf24833e14ca89bce230a9c8282ba40215324f20b67403d245ddb"
      },
      "source_qualname": "rotation"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Automatic rotation is disabled for this eligible symmetric customer-managed key."
  },
  "aws.logs.retention": {
    "description_base_sha256": "3b859ca686140e43dfd700a0d1755c5ed50d9dfeea62e6c0f54a2354de896b2b",
    "description_fields": {
      "description": "Checks whether a CloudWatch log group has an explicit positive retention period."
    },
    "remediation_base_sha256": "80d62754e117969fd351a454232088c4dbf2658c019bb809fb7fe24b384f5c67",
    "remediation_fields": {
      "caveats": [
        "Omitted retention means logs never expire, not that logs are missing."
      ],
      "steps": [
        "Choose explicit retention if unlimited storage is unnecessary; preserve required audit history."
      ],
      "summary": "Choose explicit retention if unlimited storage is unnecessary; preserve required audit history."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "log_group",
      "module": "peaso.checks.aws",
      "predicate_sources": {
        "peaso.checks.aws._native_optional": "34c9fe317180f8a906be7051729f7623015f23eca52af5dabafdb5f03012542d",
        "peaso.checks.aws.retention": "7e1d0157fe1ba6cf456acd548dc59d29b32a71618b6c739595c9230f27351189"
      },
      "source_qualname": "retention"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The log group retains logs indefinitely without an explicit expiry period."
  },
  "aws.rds.backups": {
    "description_base_sha256": "64308675ef2c672a0cf4ff652fe0b35bf99e7e1c887c6252ad92eec4b76f80fe",
    "description_fields": {
      "description": "Checks that a non-read-replica RDS instance retains automated backups for at least one day."
    },
    "remediation_base_sha256": "19285a9372aa4a4dacd9fd767d9c500e39dd49701caba7fdf933a893d65c36c1",
    "remediation_fields": {
      "caveats": [
        "Retention configuration does not prove a successful backup or restore."
      ],
      "steps": [
        "Enable automated backup retention suitable for this database\u2019s recovery needs."
      ],
      "summary": "Enable automated backup retention suitable for this database\u2019s recovery needs."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws",
      "predicate_sources": {
        "peaso.checks.aws.backups": "e0c388679460d59d1ed166bffbd7c2eca6a8243fa5692b0838f11a1a51782233",
        "peaso.checks.facts.guard": "5356efd8b28edcb109fe40dad0ebe28b435bc89b9fff9015d08ae94806e6a6cd"
      },
      "source_qualname": "backups"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Automated backup retention is zero days."
  },
  "aws.rds.cloudwatch_log_exports": {
    "description_base_sha256": "c86bb48441e0dc9aad46866015f1414305300c3d0b5b9fb2b151c03b429a95bc",
    "description_fields": {
      "description": "Checks that the RDS instance declares at least one CloudWatch log export type."
    },
    "remediation_base_sha256": "ffc4592224b5bae0052f637b096a0b079c787bdb26c345289d34b9419d4c708d",
    "remediation_fields": {
      "caveats": [
        "One declared export does not prove all relevant logs are delivered."
      ],
      "steps": [
        "Enable the engine log exports needed for monitoring and investigation."
      ],
      "summary": "Enable the engine log exports needed for monitoring and investigation."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.rds_logs": "f58831d22ab25bb871fd907606e49cc87b601e4e937a9e7274a3a0d6dfda0ec8"
      },
      "source_qualname": "rds_logs"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The RDS instance declares no CloudWatch log exports."
  },
  "aws.rds.copy_snapshot_tags": {
    "description_base_sha256": "3901a7af170473faaa7c6afc4ea576c62e84f2e588623c9034ca9432dda94182",
    "description_fields": {
      "description": "Checks CopyTagsToSnapshot on RDS instances other than Aurora."
    },
    "remediation_base_sha256": "9294614591ff9c50bfdd0ddfdc96d78091b92936326d2d1508492f921caf92c2",
    "remediation_fields": {
      "caveats": [
        "Copying tags does not create backups or establish recoverability."
      ],
      "steps": [
        "Enable snapshot tag copying if these tags are required for ownership or backup management."
      ],
      "summary": "Enable snapshot tag copying if these tags are required for ownership or backup management."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.rds_copy_tags": "25146cc055e289a079a8e0ba90d7f7683f91bf06b84cb043267daab8f05b3829"
      },
      "source_qualname": "rds_copy_tags"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The non-Aurora RDS instance does not copy tags to snapshots."
  },
  "aws.rds.enhanced_monitoring": {
    "description_base_sha256": "0f7daea5c42869863efa44b16a44d9bad876be960e167b4103a1b77bb1bca89d",
    "description_fields": {
      "description": "Checks that the RDS instance declares an enhanced-monitoring resource ARN."
    },
    "remediation_base_sha256": "e934560dcebaee343a6860fddb2cbd032d7be779435f5836b72a149ae55c7054",
    "remediation_fields": {
      "caveats": [
        "An ARN does not prove metrics are delivered."
      ],
      "steps": [
        "Configure enhanced monitoring if operating-system metrics are needed."
      ],
      "summary": "Configure enhanced monitoring if operating-system metrics are needed."
    },
    "reviewed_binding": {
      "closure": {
        "path": "EnhancedMonitoringResourceArn"
      },
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.nonempty.<locals>.evaluate": "90a36866245362615a3c31c3dad2a5155028f7288d27fdbd978fc41d6a8f1fce"
      },
      "source_qualname": "nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The RDS instance declares no enhanced-monitoring resource ARN."
  },
  "aws.rds.no_public_endpoint": {
    "description_base_sha256": "d2a2c5c27daef86b439d58ffd1c7b42ed67aa29f75c17cd321b89808e710d4be",
    "description_fields": {
      "description": "Reads the RDS instance public-accessibility setting."
    },
    "remediation_base_sha256": "5e60141cf793e5c1ecd01158e8a67bf349777bd7eb1c727fa6896082235a54bb",
    "remediation_fields": {
      "caveats": [
        "Public accessibility does not prove a reachable database listener."
      ],
      "steps": [
        "Disable public accessibility if Internet connectivity is unnecessary; preserve required client connectivity."
      ],
      "summary": "Disable public accessibility if Internet connectivity is unnecessary; preserve required client connectivity."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws",
      "predicate_sources": {
        "peaso.checks.aws.rds_public": "ea6ad3532fce77b6c0d8b86955244ef39842fdede04bf700b33164a3c27188a1"
      },
      "source_qualname": "rds_public"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The RDS instance declares a publicly accessible endpoint."
  },
  "aws.rds.vpc_configuration": {
    "description_base_sha256": "8872292b3cd0e039f0eecbd881020c26adb65b28dadd79af686171aa97266716",
    "description_fields": {
      "description": "Checks that the RDS subnet group declares a nonempty VPC identifier."
    },
    "remediation_base_sha256": "229c0486c1e6e61032ceec824988d679fd35a47daea81f1f8c81d5980ee51681",
    "remediation_fields": {
      "caveats": [
        "A VPC identifier does not establish private reachability."
      ],
      "steps": [
        "Place the instance in an appropriate VPC subnet group if required."
      ],
      "summary": "Place the instance in an appropriate VPC subnet group if required."
    },
    "reviewed_binding": {
      "closure": {
        "path": "DBSubnetGroup.VpcId"
      },
      "constants": {},
      "kind": "rds_instance",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.nonempty.<locals>.evaluate": "90a36866245362615a3c31c3dad2a5155028f7288d27fdbd978fc41d6a8f1fce"
      },
      "source_qualname": "nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The RDS subnet group declares no VPC identifier."
  },
  "aws.sns.kms_encryption": {
    "description_base_sha256": "55f3369f545548d347bd490c0147f66cfbdf797bef8b563ea8814a16a6cbf127",
    "description_fields": {
      "description": "Checks that the SNS topic declares a nonempty KMS key identifier."
    },
    "remediation_base_sha256": "9f1a2a986c663c03752513f94e8c71132240f98352b3555761004e20d9bd8094",
    "remediation_fields": {
      "caveats": [
        "A key reference does not prove key usability or that service-managed encryption is absent."
      ],
      "steps": [
        "Configure KMS encryption on the topic if required for its message data."
      ],
      "summary": "Configure KMS encryption on the topic if required for its message data."
    },
    "reviewed_binding": {
      "closure": {
        "path": "Attributes.Attributes.KmsMasterKeyId"
      },
      "constants": {},
      "kind": "sns_topic",
      "module": "peaso.checks.aws_extended",
      "predicate_sources": {
        "peaso.checks.aws_extended.nonempty.<locals>.evaluate": "90a36866245362615a3c31c3dad2a5155028f7288d27fdbd978fc41d6a8f1fce"
      },
      "source_qualname": "nonempty.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SNS topic declares no KMS key identifier."
  }
}
''')

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def _apply(check_id,original,kind):
    row=ROWS.get(check_id)
    if row is None:return deepcopy(original)
    if _digest(original)!=row[kind+"_base_sha256"] or (not isinstance(original,dict) and not (kind=="remediation" and original is None)):
        raise ValueError("Reviewed AWS remaining clarity base changed: "+check_id+" ("+kind+")")
    result=deepcopy(original) if original is not None else {}
    result.update(deepcopy(row[kind+"_fields"]))
    return result

def description(check_id,original):return _apply(check_id,original,"description")
def remediation(check_id,original):return _apply(check_id,original,"remediation")
REVIEWED_RISKS={cid:(row["reviewed_source_severity"],row["reviewed_severity"]) for cid,row in ROWS.items()}
def severity_review(check_id,source_severity):
    review=REVIEWED_RISKS.get(check_id)
    if review is None:return None
    if review[0]!=source_severity:raise ValueError("Reviewed AWS remaining source severity changed: "+check_id)
    return review[1]

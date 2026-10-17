# AWS collection diagnostics and route-search completeness

A denied EC2 read retains the fixed `UnauthorizedOperation` error identifier in collection coverage. Provider messages and arbitrary error strings remain omitted from that coverage field. This adds a diagnostic; it does not change DENIED/UNKNOWN into PASS or grant permissions.

`SearchTransitGatewayRoutes` can report `AdditionalRoutesAvailable=true`. A response with that marker and no usable continuation cannot prove complete or empty route inventory. The collector retains observed routes, marks the read incomplete and keeps the enclosing `RouteInventory` partial. A malformed marker also cannot establish completeness. When the SDK exposes a paginator and a usable `NextToken`, the existing bounded pagination continues to the last page. No new operation or configuration write is introduced.

The [EC2 API contract](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SearchTransitGatewayRoutes.html) describes the availability flag and continuation token. Directed tests cover older models without pagination, newer models with pagination, empty and nonempty truncated results, malformed markers, and a complete multipage result. Inert SDK tests verify the enclosing native collection path. These tests do not establish completeness of an existing customer scan or supply missing permissions.

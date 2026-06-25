Entra "Test Connection" performs `GET /Users?filter=externalId eq "<random-guid>"`.
The service MUST answer 200 with an empty ListResponse (totalResults:0), never 404.
This is asserted in conformance.rs::entra_test_connection_returns_empty_list_not_404.

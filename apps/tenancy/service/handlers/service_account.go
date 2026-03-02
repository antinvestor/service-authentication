package handlers

// Service Account Handlers
//
// These ConnectRPC handler methods will be implemented once the proto types
// (ServiceAccountObject, CreateServiceAccountRequest, etc.) are generated
// and published to BSR. The proto definitions have been added to
// apis/proto/partition/partition/v1/partition.proto.
//
// Planned RPCs (gated by CanAccessManage):
//   - CreateServiceAccount: creates service account + child partition + Keto tuples
//   - GetServiceAccount: returns service account by ID, or by client_id+profile_id
//   - ListServiceAccount: lists service accounts for a partition (streamed)
//   - RemoveServiceAccount: deregisters and cleans up
//
// The business logic is fully implemented in business/service_account.go
// and can be called directly for internal use.

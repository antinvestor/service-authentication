# antinvestor_ui_tenancy

Embeddable tenancy management UI for Antinvestor applications. Provides screens and widgets for managing tenants, partitions, roles, access control, service accounts, and permissions in a multi-tenant environment.

## Installation

```yaml
dependencies:
  antinvestor_ui_tenancy: ^0.1.0
```

## Features

- **Tenant Management**: List, create, and view tenant details
- **Partition Management**: Hierarchical partition tree with analytics
- **Role Management**: Partition-scoped roles and access role configuration
- **Access Control**: Access page with role assignment and permission grants
- **Service Accounts**: Manage service accounts and API clients
- **Permission Management**: View and assign permissions across partitions
- **Embeddable Widgets**: `PartitionTree`, `CreatePartitionWizard`, `AsyncEntityList`, `StateBadge`
- **Routing**: `TenancyRouteModule` with GoRouter integration

## Usage

```dart
import 'package:antinvestor_ui_tenancy/antinvestor_ui_tenancy.dart';

// Partition tree selector
PartitionTree(
  onSelected: (partition) => print(partition.id),
)

// Guided partition creation
CreatePartitionWizard(tenantId: 'tenant-123')

// Register routes in your host app
final module = TenancyRouteModule();
ShellRoute(
  routes: [...ownRoutes, ...module.buildRoutes()],
);
```

## Routes

| Path | Screen |
|------|--------|
| `/services/tenancy` | Partition analytics dashboard |
| `/services/tenancy/tenants` | Tenant list |
| `/services/tenancy/tenants/:tenantId` | Tenant detail |
| `/services/tenancy/partitions` | Partition list |
| `/services/tenancy/partitions/:partitionId` | Partition detail |

## Embedding Widgets

```dart
// Hierarchical partition tree
PartitionTree(rootPartitionId: 'root')

// State indicator badge
StateBadge(state: entityState)

// Async paginated entity list
AsyncEntityList<Tenant>(
  provider: tenantListProvider,
  itemBuilder: (tenant) => ListTile(title: Text(tenant.name)),
)
```

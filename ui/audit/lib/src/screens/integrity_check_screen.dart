import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/widgets/page_header.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/audit_providers.dart';

/// Screen for verifying the hash chain integrity of audit entries
/// over a user-selected date range.
class IntegrityCheckScreen extends ConsumerStatefulWidget {
  const IntegrityCheckScreen({super.key});

  @override
  ConsumerState<IntegrityCheckScreen> createState() =>
      _IntegrityCheckScreenState();
}

class _IntegrityCheckScreenState extends ConsumerState<IntegrityCheckScreen> {
  DateTimeRange? _dateRange;
  bool _hasRun = false;

  Future<void> _pickDateRange(BuildContext context) async {
    final now = DateTime.now();
    final picked = await showDateRangePicker(
      context: context,
      firstDate: now.subtract(const Duration(days: 365)),
      lastDate: now,
      initialDateRange: _dateRange ??
          DateTimeRange(
            start: now.subtract(const Duration(days: 7)),
            end: now,
          ),
    );
    if (picked != null) {
      setState(() {
        _dateRange = picked;
        _hasRun = false;
      });
    }
  }

  void _runVerification() {
    if (_dateRange == null) return;
    setState(() => _hasRun = true);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final dateFormat = DateFormat('MMMM d, yyyy');

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PageHeader(
            title: 'Integrity Verification',
            breadcrumbs: const ['Services', 'Audit', 'Integrity'],
            actions: [
              OutlinedButton.icon(
                onPressed: () => context.go('/services/audit'),
                icon: const Icon(Icons.arrow_back, size: 18),
                label: const Text('Back to Log'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          // Controls card
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: surfaceColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Hash Chain Verification',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                Text(
                  'Verify the integrity of audit entries by checking the hash chain '
                  'over a selected date range. Each entry references the hash of the '
                  'previous entry, forming a tamper-proof chain.',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                ),
                const SizedBox(height: 20),
                Row(
                  children: [
                    OutlinedButton.icon(
                      onPressed: () => _pickDateRange(context),
                      icon: const Icon(Icons.date_range, size: 18),
                      label: Text(
                        _dateRange != null
                            ? '${dateFormat.format(_dateRange!.start)} - ${dateFormat.format(_dateRange!.end)}'
                            : 'Select Date Range',
                      ),
                    ),
                    const SizedBox(width: 16),
                    ElevatedButton.icon(
                      onPressed: _dateRange != null ? _runVerification : null,
                      icon: const Icon(Icons.play_arrow, size: 18),
                      label: const Text('Run Verification'),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          // Results
          if (_hasRun && _dateRange != null)
            _VerificationResults(
              dateRange: DateRange(
                start: _dateRange!.start,
                end: _dateRange!.end,
              ),
            ),
        ],
      ),
    );
  }
}

class _VerificationResults extends ConsumerWidget {
  const _VerificationResults({required this.dateRange});
  final DateRange dateRange;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final asyncResult = ref.watch(verifyIntegrityProvider(dateRange));

    return asyncResult.when(
      loading: () => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(40),
        decoration: BoxDecoration(
          color: surfaceColor,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: borderColor),
        ),
        child: const Column(
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('Verifying hash chain integrity...'),
          ],
        ),
      ),
      error: (error, _) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: surfaceColor,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: theme.colorScheme.error),
        ),
        child: Column(
          children: [
            Icon(Icons.error_outline,
                size: 48, color: theme.colorScheme.error),
            const SizedBox(height: 12),
            Text('Verification failed: $error'),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: () =>
                  ref.invalidate(verifyIntegrityProvider(dateRange)),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
      data: (result) => _buildResultCard(context, result),
    );
  }

  Widget _buildResultCard(
      BuildContext context, VerifyIntegrityResponse result) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final isValid = result.valid;
    final statusColor = isValid ? Colors.green.shade600 : theme.colorScheme.error;
    final statusIcon = isValid ? Icons.check_circle : Icons.cancel;
    final statusLabel = isValid ? 'Chain Verified' : 'Integrity Issue Detected';

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: surfaceColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(statusIcon, size: 32, color: statusColor),
              const SizedBox(width: 12),
              Text(
                statusLabel,
                style: theme.textTheme.titleLarge?.copyWith(
                  color: statusColor,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          _ResultRow(
            icon: Icons.numbers,
            label: 'Entries Verified',
            value: '${result.entriesVerified}',
          ),
          const SizedBox(height: 8),
          _ResultRow(
            icon: isValid ? Icons.check : Icons.close,
            label: 'Status',
            value: isValid ? 'All hashes valid' : 'Chain broken',
            color: statusColor,
          ),
          if (result.message.isNotEmpty) ...[
            const SizedBox(height: 8),
            _ResultRow(
              icon: Icons.info_outline,
              label: 'Message',
              value: result.message,
            ),
          ],
          if (result.firstInvalidEntryId.isNotEmpty) ...[
            const SizedBox(height: 16),
            OutlinedButton.icon(
              onPressed: () => context
                  .go('/services/audit/${result.firstInvalidEntryId}'),
              icon:
                  Icon(Icons.arrow_forward, size: 18, color: statusColor),
              label: Text(
                'View Invalid Entry: ${result.firstInvalidEntryId}',
                style: TextStyle(color: statusColor),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _ResultRow extends StatelessWidget {
  const _ResultRow({
    required this.icon,
    required this.label,
    required this.value,
    this.color,
  });
  final IconData icon;
  final String label;
  final String value;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        Icon(icon, size: 18, color: color ?? theme.colorScheme.primary),
        const SizedBox(width: 8),
        SizedBox(
          width: 140,
          child: Text(
            label,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: theme.textTheme.bodyMedium
                ?.copyWith(fontWeight: FontWeight.w500, color: color),
          ),
        ),
      ],
    );
  }
}

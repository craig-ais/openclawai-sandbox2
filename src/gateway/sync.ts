import type { Sandbox } from '@cloudflare/sandbox';
import type { MoltbotEnv } from '../types';
import { R2_MOUNT_PATH } from '../config';
import { mountR2Storage } from './r2';
import { waitForProcess } from './utils';

export interface SyncResult {
  success: boolean;
  lastSync?: string;
  error?: string;
  details?: string;
}

export interface CleanupResult {
  success: boolean;
  deletedCount: number;
  error?: string;
  details?: string;
}

export interface PurgeResult {
  success: boolean;
  error?: string;
  details?: string;
}

/**
 * Sync moltbot config from container to R2 for persistence.
 * 
 * This function:
 * 1. Mounts R2 if not already mounted
 * 2. Verifies source has critical files (prevents overwriting good backup with empty data)
 * 3. Runs rsync to copy config to R2
 * 4. Writes a timestamp file for tracking
 * 
 * @param sandbox - The sandbox instance
 * @param env - Worker environment bindings
 * @returns SyncResult with success status and optional error details
 */
export async function syncToR2(sandbox: Sandbox, env: MoltbotEnv): Promise<SyncResult> {
  // Check if R2 is configured
  if (!env.R2_ACCESS_KEY_ID || !env.R2_SECRET_ACCESS_KEY || !env.CF_ACCOUNT_ID) {
    return { success: false, error: 'R2 storage is not configured' };
  }

  // Mount R2 if not already mounted
  const mounted = await mountR2Storage(sandbox, env);
  if (!mounted) {
    return { success: false, error: 'Failed to mount R2 storage' };
  }

  // Sanity check: verify source has critical files before syncing
  // This prevents accidentally overwriting a good backup with empty/corrupted data
  try {
    const checkProc = await sandbox.startProcess('test -f /root/.clawdbot/clawdbot.json && echo "ok"');
    await waitForProcess(checkProc, 5000);
    const checkLogs = await checkProc.getLogs();
    if (!checkLogs.stdout?.includes('ok')) {
      return { 
        success: false, 
        error: 'Sync aborted: source missing clawdbot.json',
        details: 'The local config directory is missing critical files. This could indicate corruption or an incomplete setup.',
      };
    }
  } catch (err) {
    return { 
      success: false, 
      error: 'Failed to verify source files',
      details: err instanceof Error ? err.message : 'Unknown error',
    };
  }

  // Run rsync to backup config to R2
  // Note: Use --no-times because s3fs doesn't support setting timestamps
  // SECURITY: Exclude clawdbot.json from backup - it contains embedded API keys
  // and secrets injected by start-moltbot.sh. The config is regenerated from
  // environment variables on every container start, so it doesn't need persistence.
  const syncCmd = `rsync -r --no-times --delete --exclude='*.lock' --exclude='*.log' --exclude='*.tmp' --exclude='clawdbot.json' /root/.clawdbot/ ${R2_MOUNT_PATH}/clawdbot/ && rsync -r --no-times --delete /root/clawd/skills/ ${R2_MOUNT_PATH}/skills/ && date -Iseconds > ${R2_MOUNT_PATH}/.last-sync`;
  
  try {
    const proc = await sandbox.startProcess(syncCmd);
    await waitForProcess(proc, 30000); // 30 second timeout for sync

    // Check for success by reading the timestamp file
    // (process status may not update reliably in sandbox API)
    // Note: backup structure is ${R2_MOUNT_PATH}/clawdbot/ and ${R2_MOUNT_PATH}/skills/
    const timestampProc = await sandbox.startProcess(`cat ${R2_MOUNT_PATH}/.last-sync`);
    await waitForProcess(timestampProc, 5000);
    const timestampLogs = await timestampProc.getLogs();
    const lastSync = timestampLogs.stdout?.trim();
    
    if (lastSync && lastSync.match(/^\d{4}-\d{2}-\d{2}/)) {
      return { success: true, lastSync };
    } else {
      const logs = await proc.getLogs();
      return {
        success: false,
        error: 'Sync failed',
        details: logs.stderr || logs.stdout || 'No timestamp file created',
      };
    }
  } catch (err) {
    return {
      success: false,
      error: 'Sync error',
      details: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}

/**
 * Delete session files older than the specified retention period.
 *
 * Targets JSONL and markdown files in session directories
 * (both container and R2 backup), including per-agent sessions.
 * Preserves memory files, skills, config, and credentials.
 *
 * @param sandbox - The sandbox instance
 * @param env - Worker environment bindings
 * @returns CleanupResult with count of deleted files
 */
export async function cleanupOldSessions(sandbox: Sandbox, env: MoltbotEnv): Promise<CleanupResult> {
  const retentionDays = parseInt(env.DATA_RETENTION_DAYS || '90', 10);

  // Retention disabled
  if (retentionDays <= 0) {
    return { success: true, deletedCount: 0, details: 'Retention cleanup disabled (DATA_RETENTION_DAYS=0)' };
  }

  try {
    // Find and delete old session files in the container
    // Uses -mtime (modification time) to identify stale sessions
    // Only targets *.jsonl and *.md files in sessions/ directories
    const cleanupCmd = [
      // Container session directories
      `find /root/.clawdbot/sessions/ -name '*.jsonl' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find /root/.clawdbot/sessions/ -name '*.md' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find /root/.clawdbot/agents/*/sessions/ -name '*.jsonl' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find /root/.clawdbot/agents/*/sessions/ -name '*.md' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      // R2 backup session directories (if mounted)
      `find ${R2_MOUNT_PATH}/clawdbot/sessions/ -name '*.jsonl' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find ${R2_MOUNT_PATH}/clawdbot/sessions/ -name '*.md' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find ${R2_MOUNT_PATH}/clawdbot/agents/*/sessions/ -name '*.jsonl' -mtime +${retentionDays} -delete -print 2>/dev/null`,
      `find ${R2_MOUNT_PATH}/clawdbot/agents/*/sessions/ -name '*.md' -mtime +${retentionDays} -delete -print 2>/dev/null`,
    ].join('; ');

    const proc = await sandbox.startProcess(cleanupCmd);
    await waitForProcess(proc, 30000);

    const logs = await proc.getLogs();
    const stdout = logs.stdout?.trim() || '';
    // Count deleted files (each -print outputs one line per deleted file)
    const deletedCount = stdout ? stdout.split('\n').filter(line => line.length > 0).length : 0;

    return {
      success: true,
      deletedCount,
      details: deletedCount > 0
        ? `Deleted ${deletedCount} session file(s) older than ${retentionDays} days`
        : `No session files older than ${retentionDays} days found`,
    };
  } catch (err) {
    return {
      success: false,
      deletedCount: 0,
      error: 'Cleanup error',
      details: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}

/**
 * Purge all session data from the container and R2 backup.
 *
 * Deletes all session files but preserves:
 * - Memory files (MEMORY.md, daily logs)
 * - Skills
 * - Configuration
 * - Credentials
 *
 * @param sandbox - The sandbox instance
 * @param env - Worker environment bindings
 * @returns PurgeResult
 */
export async function purgeSessions(sandbox: Sandbox, env: MoltbotEnv): Promise<PurgeResult> {
  try {
    // Mount R2 if configured (so we can purge the backup too)
    if (env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY && env.CF_ACCOUNT_ID) {
      await mountR2Storage(sandbox, env);
    }

    const purgeCmd = [
      // Container session directories
      `rm -rf /root/.clawdbot/sessions/* 2>/dev/null`,
      `find /root/.clawdbot/agents/*/sessions/ -type f -delete 2>/dev/null`,
      // R2 backup session directories
      `rm -rf ${R2_MOUNT_PATH}/clawdbot/sessions/* 2>/dev/null`,
      `find ${R2_MOUNT_PATH}/clawdbot/agents/*/sessions/ -type f -delete 2>/dev/null`,
    ].join('; ');

    const proc = await sandbox.startProcess(purgeCmd);
    await waitForProcess(proc, 30000);

    return { success: true, details: 'All session data purged from container and R2 backup' };
  } catch (err) {
    return {
      success: false,
      error: 'Purge error',
      details: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}

/**
 * Source-map resolution.
 *
 * Minified bundles are where most real handlers live, and their positions are
 * meaningless without the map. When a script ships a sourceMappingURL, resolve
 * the registration site back to the original file/line so the report points at
 * something a developer can open.
 */
import { SourceMapConsumer } from 'source-map';
import type { FetchedScript } from '../browser/page-model.js';

export interface ResolvedPosition {
  url: string;
  line: number;
  column: number;
  name?: string;
}

interface MapEntry {
  consumer: any;
  sourceRoot: string;
}

export class SourceMapRegistry {
  private maps = new Map<string, MapEntry>();
  private ready = false;

  async load(scripts: FetchedScript[]): Promise<void> {
    for (const s of scripts) {
      if (!s.mapJson || !s.mapUrl) continue;
      try {
        const consumer = await new SourceMapConsumer(s.mapJson);
        this.maps.set(s.url, { consumer, sourceRoot: s.mapJson.sourceRoot || '' });
        // The page may reference the script by a URL variant; index by path too.
        try {
          const u = new URL(s.url);
          this.maps.set(u.origin + u.pathname, { consumer, sourceRoot: s.mapJson.sourceRoot || '' });
        } catch {
          /* relative urls */
        }
      } catch {
        /* malformed map: skip */
      }
    }
    this.ready = true;
  }

  get size(): number {
    return this.maps.size;
  }

  /**
   * Resolve a script position. `column`-less callers get line-only resolution
   * by scanning the start and end of the line.
   */
  resolve(scriptUrl: string, line: number | null, column: number | null): ResolvedPosition | null {
    if (!this.ready || line == null) return null;
    const entry = this.maps.get(scriptUrl) || this.lookupByPath(scriptUrl);
    if (!entry) return null;
    try {
      const col = column ?? 0;
      const pos = entry.consumer.originalPositionFor({ line, column: col });
      if (!pos || !pos.source) return null;
      return {
        url: joinSourceRoot(entry.sourceRoot, pos.source),
        line: pos.line ?? 0,
        column: pos.column ?? 0,
        name: pos.name || undefined,
      };
    } catch {
      return null;
    }
  }

  private lookupByPath(scriptUrl: string): MapEntry | null {
    try {
      const u = new URL(scriptUrl);
      return this.maps.get(u.origin + u.pathname) || null;
    } catch {
      return null;
    }
  }

  destroy(): void {
    for (const { consumer } of this.maps.values()) {
      try {
        consumer.destroy?.();
      } catch {
        /* ignore */
      }
    }
    this.maps.clear();
  }
}

function joinSourceRoot(root: string, source: string): string {
  if (!root) return normalizeSource(source);
  if (/^[a-z]+:\/\//i.test(source)) return normalizeSource(source);
  if (/^webpack:\/\//.test(source)) return source;
  return normalizeSource(root.replace(/\/$/, '') + '/' + source);
}

/** Strip bundler-internal prefixes so the path is meaningful to a human. */
function normalizeSource(source: string): string {
  return source
    .replace(/^webpack:\/\/[^/]*\//, '')
    .replace(/^\.\//, '')
    .replace(/^~/, '');
}

// Types for build_info.js, which //:build_info generates at build time.

/** Which source the site was built from. */
export const BUILD: {
  repo: string;
  /** The commit, or null for a development build. */
  commit: string | null;
  /** Whether the tree had uncommitted changes when built. */
  dirty: boolean;
};

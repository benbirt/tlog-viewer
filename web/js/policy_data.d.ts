// Types for policy_data.js, which //:policy_data generates from the
// google-tlog-witness policy at build time.

/** The tlog-policy the viewer trusts. */
export const POLICY_TEXT: string;

/** Where POLICY_TEXT came from. */
export const POLICY_SOURCE: {
  repo: string;
  commit: string;
  target: string;
};

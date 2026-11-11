// Where each log's tiles are served. The tlog-policy identifies logs by
// origin and key only, so the URL is a convention: PAIC logs are published on
// gstatic under their origin.
export const logBaseUrl = (origin: string): string => `https://www.gstatic.com/${origin}/`;

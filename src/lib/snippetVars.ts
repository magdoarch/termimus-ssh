/**
 * Snippet variables: `{{name}}` or `{{name:default}}`, asked for when the
 * snippet runs. Names start with a letter or `_`, so Go templates such as
 * docker's `{{.Names}}` or `{{json .}}` are left alone.
 */
const VARIABLE = /\{\{([A-Za-z_][A-Za-z0-9_-]*)(?::([^{}\n]*))?\}\}/g;

export interface SnippetVariable {
  name: string;
  defaultValue: string;
}

/** The variables in `command`, in order of first use (the first default wins). */
export function snippetVariables(command: string): SnippetVariable[] {
  const found = new Map<string, string>();
  for (const match of command.matchAll(VARIABLE)) {
    if (!found.has(match[1])) found.set(match[1], match[2] ?? "");
  }
  return [...found].map(([name, defaultValue]) => ({ name, defaultValue }));
}

export function fillSnippet(command: string, values: Record<string, string>): string {
  return command.replace(VARIABLE, (_match, name: string) => values[name] ?? "");
}

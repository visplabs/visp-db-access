type NavigatorWithHints = Navigator & {
  userAgentData?: { platform?: string };
};
/** True on macOS and iOS, where the Command key is the shortcut modifier. */
export function isApplePlatform(
  nav: NavigatorWithHints | undefined = typeof navigator === 'undefined'
    ? undefined
    : navigator,
): boolean {
  if (!nav) return false;
  const platform = nav.userAgentData?.platform || nav.platform || '';
  return /mac|iphone|ipad|ipod/i.test(platform);
}
/** Short visible label for the shortcut modifier on this host. */
export function modifierLabel(apple = isApplePlatform()): string {
  return apple ? '⌘' : 'Ctrl';
}
/** Visible label for a shortcut, such as "⌘ K" on macOS or "Ctrl K" elsewhere. */
export function shortcutLabel(key: string, apple = isApplePlatform()): string {
  return `${modifierLabel(apple)} ${key}`;
}
